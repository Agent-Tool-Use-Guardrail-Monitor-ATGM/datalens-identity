"""Publish confirmed RabbitMQ messages from the identity PostgreSQL outbox."""

import logging
import os
import signal
import ssl
import time
from threading import Event
from urllib.parse import urlsplit
from uuid import uuid4

import pika
import psycopg
from identity_events import EventContractError, decode_event

EXCHANGE = "identity.events.v1"
LOG = logging.getLogger("identity-publisher")
AMQP_ERRORS = (pika.exceptions.AMQPError, OSError)


def broker_parameters(url):
    target = urlsplit(url)
    local_hosts = {"127.0.0.1", "::1", "localhost", "rabbitmq"}
    if target.scheme not in {"amqp", "amqps"} or not target.hostname:
        raise ValueError("A valid RabbitMQ endpoint is required")
    if target.scheme == "amqp" and target.hostname not in local_hosts:
        raise ValueError("Remote RabbitMQ endpoints require AMQPS")
    if target.query or target.fragment or not target.username or not target.password:
        raise ValueError("RabbitMQ URL requires credentials and no query or fragment")
    parameters = pika.URLParameters(url)
    if parameters.virtual_host != "identity":
        raise ValueError("RabbitMQ virtual host must be identity")
    if target.scheme == "amqps":
        parameters.ssl_options = pika.SSLOptions(ssl.create_default_context(), target.hostname)
    parameters.connection_attempts = 1
    parameters.socket_timeout = 5
    parameters.stack_timeout = 10
    parameters.blocked_connection_timeout = 10
    parameters.heartbeat = 15
    return parameters


class RabbitPublisher:
    def __init__(self, parameters):
        self.parameters = parameters
        self.connection = None
        self.channel = None

    def send(self, event, body):
        if self.channel is None:
            self.connection = pika.BlockingConnection(self.parameters)
            channel = self.connection.channel()
            channel.exchange_declare(EXCHANGE, passive=True)
            channel.confirm_delivery()
            self.channel = channel
        self.channel.basic_publish(
            EXCHANGE,
            event["event_type"],
            body,
            pika.BasicProperties(
                delivery_mode=2, message_id=event["event_id"], content_type="application/json"
            ),
            mandatory=True,
        )

    def poll(self):
        if self.connection is not None:
            self.connection.process_data_events(time_limit=0)

    def close(self):
        connection, self.connection = self.connection, None
        self.channel = None
        if connection is not None and connection.is_open:
            try:
                connection.close()
            except AMQP_ERRORS:
                pass


def publish_one(connection, broker, issuer):
    # Autocommit releases the claim statement's locks before any broker I/O.
    if not connection.autocommit:
        raise ValueError("The publisher requires an autocommit connection")
    token = uuid4()
    row = connection.execute(
        """
        WITH candidate AS (
            SELECT event_id FROM public.dl_identity_outbox
            WHERE published_at IS NULL AND (claim_until IS NULL OR claim_until <= now())
            ORDER BY created_at_ms, event_id LIMIT 1 FOR UPDATE SKIP LOCKED
        )
        UPDATE public.dl_identity_outbox AS outbox
        SET claim_token = %s, claim_until = now() + interval '2 minutes'
        FROM candidate WHERE outbox.event_id = candidate.event_id
        RETURNING outbox.event_id, outbox.payload
        """,
        (token,),
    ).fetchone()
    if row is None:
        return False
    event_id, payload = row
    try:
        body = payload.encode("utf-8")
        event = decode_event(body, expected_issuer=issuer)
        if event["event_id"] != event_id:
            raise EventContractError("Outbox event ID mismatch")
    except (EventContractError, UnicodeError):
        LOG.error("Stored event violates identity contract; retained for inspection")
        defer(connection, event_id, token, 300)
        return True
    try:
        broker.send(event, body)
    except AMQP_ERRORS as error:
        defer(connection, event_id, token, 5)
        LOG.warning("RabbitMQ publish unconfirmed (%s); retained for retry", type(error).__name__)
        raise
    result = connection.execute(
        """
        UPDATE public.dl_identity_outbox
        SET published_at = now(), claim_token = NULL, claim_until = NULL
        WHERE event_id = %s AND claim_token = %s AND published_at IS NULL
        """,
        (event_id, token),
    )
    if result.rowcount != 1:
        LOG.warning("Publish confirmed after claim was replaced; duplicate delivery possible")
    return True


def defer(connection, event_id, token, seconds):
    connection.execute(
        """
        UPDATE public.dl_identity_outbox
        SET claim_token = NULL, claim_until = now() + make_interval(secs => %s)
        WHERE event_id = %s AND claim_token = %s AND published_at IS NULL
        """,
        (seconds, event_id, token),
    )


def maintain(connection):
    connection.execute("SELECT public.dl_identity_purge_published()")
    pending, oldest = connection.execute(
        """
        SELECT count(*), min(created_at_ms)
        FROM (
            SELECT created_at_ms FROM public.dl_identity_outbox
            WHERE published_at IS NULL ORDER BY created_at_ms, event_id LIMIT 1000
        ) AS pending
        """
    ).fetchone()
    if pending == 1000 or (oldest is not None and time.time() - oldest / 1000 >= 300):
        LOG.warning("Identity outbox backlog exceeds threshold (count capped at 1000): %s", pending)


def run(dsn, broker, issuer, stop):
    maintenance_at = 0
    while not stop.is_set():
        try:
            with psycopg.connect(
                dsn,
                autocommit=True,
                connect_timeout=5,
                options="-c statement_timeout=5000 -c lock_timeout=2000",
            ) as connection:
                while not stop.is_set():
                    if time.monotonic() >= maintenance_at:
                        maintain(connection)
                        maintenance_at = time.monotonic() + 30
                    broker.poll()
                    if not publish_one(connection, broker, issuer):
                        stop.wait(1)
        except (psycopg.Error, *AMQP_ERRORS) as error:
            LOG.warning("Identity publisher will retry (%s)", type(error).__name__)
            broker.close()
            stop.wait(5)
    broker.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("pika").setLevel(logging.CRITICAL)
    try:
        dsn = os.environ["IDENTITY_PUBLISHER_DB_DSN"]
        issuer = os.environ["IDENTITY_PUBLISHER_ISSUER"]
        broker = RabbitPublisher(broker_parameters(os.environ["IDENTITY_PUBLISHER_AMQP_URL"]))
        issuer_url = urlsplit(issuer)
        if issuer_url.scheme not in {"http", "https"} or not issuer_url.hostname or not dsn:
            raise ValueError("Invalid identity publisher configuration")
    except (KeyError, ValueError, OSError, pika.exceptions.AMQPError):
        LOG.error("Invalid or missing identity publisher configuration")
        return 2
    stop = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    run(dsn, broker, issuer, stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Publisher settings and delivery against disposable PostgreSQL and RabbitMQ."""

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

import pika
import psycopg
import pytest
from identity_publisher import RabbitPublisher, broker_parameters, maintain, publish_one
from psycopg.pq import TransactionStatus
from test_runtime import runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "http://localhost:18081/realms/publisher-fixture"
QUEUE = "agent.identity.v1"
AMQP_ERRORS = (pika.exceptions.AMQPError, OSError)


def test_remote_broker_requires_verified_tls():
    with pytest.raises(ValueError, match="require AMQPS"):
        broker_parameters("amqp://user:secret@broker.example/identity")
    parameters = broker_parameters("amqps://user:secret@broker.example/identity")
    assert parameters.ssl_options.server_hostname == "broker.example"
    assert parameters.ssl_options.context.check_hostname
    with pytest.raises(ValueError, match="virtual host"):
        broker_parameters("amqp://user:secret@localhost/other")


@pytest.fixture
def broker_project(tmp_path):
    messaging = Path(os.getenv("IDENTITY_MESSAGING_ROOT", ROOT.parent / "datalens-messaging"))
    messaging = messaging.resolve()
    secrets = tmp_path / "broker"
    subprocess.run(
        [sys.executable, str(messaging / "prepare.py"), "--secrets-dir", str(secrets)],
        cwd=messaging,
        check=True,
    )
    project = "identity-publisher-test-" + uuid4().hex[:10]
    env = os.environ | {
        "RABBITMQ_PORT": "0",
        "RABBITMQ_DEFINITIONS_FILE": str(secrets / "definitions.json"),
    }

    def compose(*args):
        return subprocess.run(
            ["docker", "compose", "-p", project, *args],
            cwd=messaging,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=200,
        ).stdout.strip()

    try:
        compose("up", "-d", "--wait", "--wait-timeout", "180")
        yield compose, secrets
    finally:
        compose("down", "--volumes")


@pytest.mark.runtime
def test_confirm_retry_fencing_and_retention(runtime, broker_project):
    compose, secrets = broker_project
    target = runtime.command("port", "identity-postgres", "5432")
    assert target.returncode == 0
    host, port = target.stdout.strip().rsplit(":", 1)
    assert host == "127.0.0.1"
    database = f"host={host} port={port} dbname=identity_test_db connect_timeout=5"
    bootstrap = runtime.command(
        "exec",
        "-T",
        "identity-postgres",
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "identity_bootstrap",
        "-d",
        "identity_test_db",
        sql="CREATE ROLE identity_publisher LOGIN PASSWORD 'publisher-test-only-password';",
    )
    assert bootstrap.returncode == 0, bootstrap.stderr
    assert runtime.sql((ROOT / "tools/grant_publisher.sql").read_text()).returncode == 0

    def amqp_url(username):
        address = compose("port", "rabbitmq", "5672")
        password = quote((secrets / f"{username}.password").read_text().strip(), safe="")
        return f"amqp://{username}:{password}@{address}/identity"

    def row_state(connection, event_id):
        return connection.execute(
            "SELECT published_at IS NOT NULL, claim_until IS NOT NULL "
            "FROM dl_identity_outbox WHERE event_id = %s",
            (event_id,),
        ).fetchone()

    event = {
        "schema_version": 1,
        "event_id": str(uuid4()),
        "event_type": "user.created",
        "issuer": ISSUER,
        "subject": "fixture-subject",
        "occurred_at": "2026-11-11T12:00:00Z",
        "data": {
            "profile_revision": 1,
            "display_name": None,
            "username": None,
            "email": None,
        },
    }
    event_id = event["event_id"]
    body = json.dumps(event)

    def seed(connection, row_id):
        connection.execute(
            "INSERT INTO dl_identity_outbox (event_id, realm_id, subject, payload, created_at_ms) "
            "VALUES (%s, 'publisher-fixture', 'fixture-subject', %s, 0)",
            (row_id, body),
        )

    with (
        psycopg.connect(
            database,
            user="identity_test",
            password="identity-test-app-only-password",
            autocommit=True,
        ) as owner,
        psycopg.connect(
            database,
            user="identity_publisher",
            password="publisher-test-only-password",
            autocommit=True,
        ) as connection,
    ):
        seed(owner, event_id)
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT count(*) FROM realm")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "DELETE FROM dl_identity_outbox WHERE event_id = %s", (event_id,)
                )

            broker = RabbitPublisher(broker_parameters(amqp_url("identity-publisher")))
            compose("stop", "rabbitmq")
            with pytest.raises(AMQP_ERRORS):
                publish_one(connection, broker, ISSUER)
            broker.close()
            assert row_state(owner, event_id) == (False, True)
            owner.execute(
                "UPDATE dl_identity_outbox SET claim_until = now() WHERE event_id = %s", (event_id,)
            )
            compose("up", "-d", "--wait", "--wait-timeout", "180")
            broker = RabbitPublisher(broker_parameters(amqp_url("identity-publisher")))

            class LostClaim:
                def send(self, event, payload):
                    assert connection.info.transaction_status == TransactionStatus.IDLE
                    broker.send(event, payload)
                    owner.execute(
                        "UPDATE dl_identity_outbox SET claim_token = NULL, claim_until = now() "
                        "WHERE event_id = %s",
                        (event_id,),
                    )

            try:
                assert publish_one(connection, LostClaim(), ISSUER)
                assert row_state(owner, event_id) == (False, True)
                assert publish_one(connection, broker, ISSUER)
                assert row_state(owner, event_id) == (True, False)
            finally:
                broker.close()

            with pika.BlockingConnection(
                broker_parameters(amqp_url("agent-identity-consumer"))
            ) as consumer:
                channel = consumer.channel()
                for _ in range(2):
                    delivery, properties, payload = channel.basic_get(QUEUE, auto_ack=False)
                    assert delivery is not None and payload == body.encode()
                    assert properties.message_id == event_id and properties.delivery_mode == 2
                    channel.basic_ack(delivery.delivery_tag)
                assert channel.basic_get(QUEUE)[0] is None

            owner.execute(
                "UPDATE dl_identity_outbox SET published_at = now() - interval '8 days' "
                "WHERE event_id = %s",
                (event_id,),
            )
            pending_id = str(uuid4())
            seed(owner, pending_id)
            maintain(connection)
            assert row_state(owner, event_id) is None
            assert row_state(owner, pending_id) == (False, False)
            assert publish_one(connection, None, ISSUER)
            assert row_state(owner, pending_id) == (False, True)
        finally:
            owner.execute("DELETE FROM dl_identity_outbox WHERE realm_id = 'publisher-fixture'")

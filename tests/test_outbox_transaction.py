"""Real Keycloak/JPA commit, rollback and concurrent revision proof."""

import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import UUID, uuid4

import httpx
import pika
import pytest
from bootstrap_identity import Admin, create_realm
from identity_events import EventContractError, decode_event
from identity_publisher import RabbitPublisher, broker_parameters, publish_one
from test_publisher import AMQP_ERRORS, QUEUE, amqp_url
from test_publisher import broker_project as broker_project
from test_publisher import publisher_database as publisher_database
from test_runtime import runtime as runtime


@pytest.mark.runtime
def test_account_and_outbox_share_commit_rollback_and_revision_lock(
    runtime, monkeypatch, publisher_database, broker_project
):
    admin_name = "outbox-test-" + secrets.token_hex(4)
    password = "Outbox-Test!29" + secrets.token_urlsafe(24)
    monkeypatch.setenv("KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD", password)
    assert runtime.command("stop", "identity-keycloak").returncode == 0
    try:
        assert (
            runtime.command(
                "run",
                "--rm",
                "--no-deps",
                "-e",
                "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD",
                "identity-keycloak",
                "bootstrap-admin",
                "user",
                "--optimized",
                "--username",
                admin_name,
                "--password:env",
                "KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD",
                "--no-prompt",
                timeout=180,
            ).returncode
            == 0
        )
    finally:
        assert runtime.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
    origin = "http://localhost:18081"
    realm = "outbox-test-" + secrets.token_hex(4)
    issuer = origin + "/realms/" + realm
    admin = Admin(origin, admin_name, password)
    admin.client.timeout = httpx.Timeout(60)
    try:
        # Exercise real provider renewal after authentication rejects the access token.
        admin.client.headers["Authorization"] = "Bearer invalid-test-access-token"
        assert admin.request("GET", "master").status_code == 200
        assert admin.client.headers["Authorization"] != "Bearer invalid-test-access-token"
        create_realm(admin, realm)
        realm_id = str(UUID(admin.request("GET", realm).json()["id"]))
        admin.request(
            "POST",
            realm + "/users",
            {"username": "existing-user", "firstName": "Existing", "enabled": False},
        )
        existing = admin.request("GET", realm + "/users?username=existing-user&exact=true").json()[
            0
        ]
        existing_path = f"{realm}/users/{existing['id']}"
        existing = admin.request("GET", existing_path).json()
        snapshot_path = f"{realm}/identity-backfill/users/{existing['id']}"
        admin.request("POST", snapshot_path, expected=(404,))
        admin.request("PUT", realm, {"eventsListeners": ["identity-outbox-proof"]})
        admin.request("POST", f"{realm}/identity-backfill/users/{uuid4()}", expected=(404,))

        def events():
            rows = runtime.value(
                f"SELECT payload FROM dl_identity_outbox WHERE realm_id = '{realm_id}';"
            )
            return [decode_event(row.encode(), expected_issuer=issuer) for row in rows.splitlines()]

        admin.request("POST", realm + "/users", {"username": "proof-user", "enabled": True})
        user = admin.request("GET", realm + "/users?username=proof-user&exact=true").json()[0]
        subject = str(UUID(user["id"]))
        first = events()
        assert len(first) == 1 and first[0]["event_type"] == "user.created"
        assert first[0]["subject"] == subject
        assert first[0]["data"] == {
            "profile_revision": 1,
            "display_name": None,
            "username": "proof-user",
            "email": None,
        }

        def update(index):
            return admin.request(
                "PUT",
                f"{realm}/users/{subject}",
                {"firstName": f"Name-{index}"},
                expected=(204,),
            ).status_code

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(update, range(4))) == [204] * 4
        snapshots = events()
        assert sorted(e["data"]["profile_revision"] for e in snapshots) == [1, 2, 3, 4, 5]
        assert len({e["event_id"] for e in snapshots}) == 5
        assert (
            runtime.value(
                f"SELECT profile_revision, security_revision FROM dl_identity_revision "
                f"WHERE realm_id = '{realm_id}' AND subject = '{subject}';"
            )
            == "5|0"
        )
        before = admin.request("GET", f"{realm}/users/{subject}").json()["firstName"]

        # Valid individual name lengths can still exceed the combined display contract.
        assert admin.request(
            "PUT",
            f"{realm}/users/{subject}",
            {"firstName": "a" * 200, "lastName": "b" * 200},
            expected=(400, 500),
        ).status_code in (400, 500)
        assert admin.request("GET", f"{realm}/users/{subject}").json()["firstName"] == before
        assert len(events()) == 5

        # Immediate storage failure must not be swallowed into an account-only commit.
        assert (
            runtime.sql(
                "ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_proof_reject "
                "CHECK(false) NOT VALID;"
            ).returncode
            == 0
        )
        try:
            failed = admin.request(
                "PUT",
                f"{realm}/users/{subject}",
                {"firstName": "must-rollback"},
                expected=(400, 500),
            )
            assert failed.status_code in (400, 500)
        finally:
            assert (
                runtime.sql(
                    "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_proof_reject;"
                ).returncode
                == 0
            )
        assert admin.request("GET", f"{realm}/users/{subject}").json()["firstName"] == before
        assert len(events()) == 5

        # This trigger fails only at commit, after listener persist/flush succeeded.
        assert (
            runtime.sql("""
            CREATE FUNCTION dl_identity_proof_fail() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Disposable commit failure'; END $$;
            CREATE CONSTRAINT TRIGGER dl_identity_proof_fail AFTER INSERT ON dl_identity_outbox
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION dl_identity_proof_fail();
        """).returncode
            == 0
        )
        try:
            assert (
                admin.request(
                    "POST",
                    realm + "/users",
                    {"username": "must-not-exist", "enabled": True},
                    expected=(500,),
                ).status_code
                == 500
            )
            admin.request("POST", snapshot_path, expected=(500,))
        finally:
            assert (
                runtime.sql("""
                DROP TRIGGER dl_identity_proof_fail ON dl_identity_outbox;
                DROP FUNCTION dl_identity_proof_fail();
            """).returncode
                == 0
            )
        assert (
            admin.request("GET", realm + "/users?username=must-not-exist&exact=true").json() == []
        )
        assert len(events()) == 5
        assert (
            runtime.value(
                f"SELECT count(*) FROM dl_identity_revision WHERE realm_id = '{realm_id}';"
            )
            == "1"
        )

        update(5)
        assert sorted(e["data"]["profile_revision"] for e in events()) == [1, 2, 3, 4, 5, 6]
        user_path = f"{realm}/users/{subject}"
        before_security = events()
        # Let the profile insert succeed, then reject the security event in the same transaction.
        assert (
            runtime.sql("""
            ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_security_reject
            CHECK ((payload::jsonb ->> 'event_type') <> 'user.disabled') NOT VALID;
            """).returncode
            == 0
        )
        try:
            admin.request("PUT", user_path, {"enabled": False}, expected=(400, 500))
            assert admin.request("GET", user_path).json()["enabled"] is True
            assert {e["event_id"] for e in events()} == {e["event_id"] for e in before_security}
        finally:
            assert (
                runtime.sql(
                    "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_security_reject;"
                ).returncode
                == 0
            )

        admin.request("PUT", user_path, {"enabled": False})
        admin.request("PUT", user_path, {"enabled": False})
        admin.request("PUT", user_path, {"enabled": True})
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(admin.request, "POST", user_path + "/logout") for _ in range(2)]
            assert [result.result().status_code for result in results] == [204, 204]
        admin.request("DELETE", user_path)
        admin.request("DELETE", user_path, expected=(404,))
        all_events = events()
        assert sorted(
            e["data"]["profile_revision"] for e in all_events if "profile_revision" in e["data"]
        ) == list(range(1, 10))
        security = sorted(
            (e for e in all_events if "security_revision" in e["data"]),
            key=lambda e: e["data"]["security_revision"],
        )
        assert [e["event_type"] for e in security] == [
            "user.disabled",
            "user.enabled",
            "user.sessions.revoked",
            "user.sessions.revoked",
            "user.deleted",
        ]
        assert [e["data"]["security_revision"] for e in security] == list(range(1, 6))
        for event in security:
            assert event["subject"] == subject
            cutoff = event["data"].get("tokens_issued_at_or_before")
            if event["event_type"] == "user.enabled":
                assert cutoff is None
            else:
                assert cutoff == int(datetime.fromisoformat(event["occurred_at"]).timestamp())
            if event["event_type"] == "user.sessions.revoked":
                assert event["data"]["reason"] == "logout_all"

        admin.request("POST", f"{realm}/identity-backfill/users/{subject}", expected=(404,))
        with httpx.Client(base_url=origin, timeout=10) as unauthenticated:
            assert unauthenticated.post("/admin/realms/" + snapshot_path).status_code == 401
            client_secret = secrets.token_urlsafe(32)
            admin.request(
                "POST",
                f"{realm}/clients",
                {
                    "clientId": "backfill-denied",
                    "secret": client_secret,
                    "serviceAccountsEnabled": True,
                },
            )
            token = unauthenticated.post(
                f"/realms/{realm}/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "backfill-denied",
                    "client_secret": client_secret,
                },
            )
            assert token.status_code == 200
            forbidden = unauthenticated.post(
                "/admin/realms/" + snapshot_path,
                headers={"Authorization": "Bearer " + token.json()["access_token"]},
            )
            assert forbidden.status_code == 403
        assert all(e["subject"] != existing["id"] for e in events())
        admin.request("POST", snapshot_path, expected=(204,))
        assert admin.request("GET", existing_path).json() == existing
        first_snapshot = [e for e in events() if e["subject"] == existing["id"]]
        by_type = {e["event_type"]: e["data"] for e in first_snapshot}
        assert len(first_snapshot) == 2
        assert by_type["user.profile.updated"] == {
            "profile_revision": 1,
            "display_name": "Existing",
            "username": "existing-user",
            "email": None,
        }
        assert by_type["user.disabled"]["security_revision"] == 1
        assert by_type["user.disabled"]["tokens_issued_at_or_before"] > 0

        assert (
            runtime.sql("""
            ALTER TABLE dl_identity_outbox ADD CONSTRAINT dl_snapshot_reject
            CHECK ((payload::jsonb ->> 'event_type') <> 'user.disabled') NOT VALID;
            """).returncode
            == 0
        )
        try:
            admin.request("POST", snapshot_path, expected=(500,))
            assert {e["event_id"] for e in events()} == {
                e["event_id"] for e in [*all_events, *first_snapshot]
            }
        finally:
            assert (
                runtime.sql(
                    "ALTER TABLE dl_identity_outbox DROP CONSTRAINT dl_snapshot_reject;"
                ).returncode
                == 0
            )

        with ThreadPoolExecutor(max_workers=3) as pool:
            requests = [
                pool.submit(admin.request, "POST", snapshot_path, expected=(204,)),
                pool.submit(admin.request, "POST", snapshot_path, expected=(204,)),
                pool.submit(
                    admin.request, "PUT", existing_path, {"firstName": "Current", "enabled": True}
                ),
            ]
            assert [request.result().status_code for request in requests] == [204] * 3

        saved = {e["event_id"]: e for e in events()}
        existing_events = [e for e in saved.values() if e["subject"] == existing["id"]]
        profiles = sorted(
            (e["data"] for e in existing_events if e["event_type"] == "user.profile.updated"),
            key=lambda data: data["profile_revision"],
        )
        assert [data["profile_revision"] for data in profiles] == [1, 2, 3, 4]
        assert profiles[-1]["display_name"] == "Current"
        statuses = sorted(
            (e for e in existing_events if "security_revision" in e["data"]),
            key=lambda event: event["data"]["security_revision"],
        )
        assert [e["data"]["security_revision"] for e in statuses] == [1, 2, 3, 4]
        assert statuses[-1]["event_type"] == "user.enabled"
        assert {e["event_id"]: e for e in events()} == saved
        assert runtime.command("restart", "--no-deps", "identity-keycloak").returncode == 0
        assert runtime.command("up", "-d", "--wait", "--wait-timeout", "180").returncode == 0
        assert {e["event_id"]: e for e in events()} == saved
        assert all(len(json.dumps(e).encode()) <= 16384 for e in saved.values())
        replay_id = next(
            e["event_id"] for e in first_snapshot if e["event_type"] == "user.disabled"
        )
        verify_transport(publisher_database[0], broker_project, issuer, realm_id, saved, replay_id)
    finally:
        admin.close()
        cleanup = Admin(origin, admin_name, password)
        try:
            cleanup.request("DELETE", realm, expected=(204, 404))
        finally:
            cleanup.close()


def verify_transport(connection, broker_project, issuer, realm_id, expected, replay_id):
    compose, _ = broker_project
    broker = RabbitPublisher(broker_parameters(amqp_url(broker_project, "identity-publisher")))
    compose("stop", "rabbitmq")
    try:
        with pytest.raises(AMQP_ERRORS):
            while publish_one(connection, broker, issuer):
                pass
    finally:
        broker.close()

    def confirmed():
        return connection.execute(
            "SELECT count(*) FROM dl_identity_outbox WHERE published_at IS NOT NULL "
            "AND event_id = ANY(%s)",
            (list(expected),),
        ).fetchone()[0]

    assert confirmed() == 0
    compose("up", "-d", "--force-recreate", "--wait", "--wait-timeout", "180")
    broker = RabbitPublisher(broker_parameters(amqp_url(broker_project, "identity-publisher")))
    poison_id = str(uuid4())
    try:
        deadline = time.monotonic() + 20
        while confirmed() < len(expected):
            assert time.monotonic() < deadline, f"Transport stalled for test realm {realm_id}"
            if not publish_one(connection, broker, issuer):
                time.sleep(0.2)
        broker.send({"event_id": poison_id, "event_type": "user.created"}, b"{")
    finally:
        broker.close()

    compose("up", "-d", "--force-recreate", "--wait", "--wait-timeout", "180")

    def receive(channel, deadline):
        while time.monotonic() < deadline:
            delivery, properties, body = channel.basic_get(QUEUE, auto_ack=False)
            if delivery is not None:
                return delivery, properties, body
            time.sleep(0.2)
        pytest.fail("Expected durable messages did not arrive")

    with pika.BlockingConnection(
        broker_parameters(amqp_url(broker_project, "agent-identity-consumer"))
    ) as consumer:
        channel = consumer.channel()
        received = {}
        abandoned = False
        poison_rejected = False
        deadline = time.monotonic() + 15
        while len(received) < len(expected) or not poison_rejected:
            delivery, properties, body = receive(channel, deadline)
            if properties.message_id == poison_id:
                assert not poison_rejected
                with pytest.raises(EventContractError):
                    decode_event(body, expected_issuer=issuer)
                channel.basic_reject(delivery.delivery_tag, requeue=False)
                poison_rejected = True
                continue
            event = decode_event(body, expected_issuer=issuer)
            assert properties.message_id == event["event_id"]
            assert properties.delivery_mode == 2
            assert delivery.routing_key == event["event_type"]
            assert event["event_id"] not in received
            if event["event_id"] == replay_id:
                if not abandoned:
                    abandoned = True
                    channel.close()
                    channel = consumer.channel()
                    continue
                assert delivery.redelivered
            received[event["event_id"]] = event
            channel.basic_ack(delivery.delivery_tag)
        assert received == expected
        assert channel.basic_get(QUEUE)[0] is None
        with pytest.raises(pika.exceptions.ChannelClosedByBroker) as denied:
            channel.basic_get("agent.identity.dead.v1")
        assert denied.value.reply_code == 403

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        queues = json.loads(
            compose(
                "exec",
                "-T",
                "rabbitmq",
                "rabbitmqctl",
                "-q",
                "list_queues",
                "-p",
                "identity",
                "name",
                "messages_ready",
                "--formatter=json",
            )
        )
        if any(q["name"] == "agent.identity.dead.v1" and q["messages_ready"] == 1 for q in queues):
            return
        time.sleep(0.5)
    pytest.fail("Rejected poison message did not reach the restricted dead-letter queue")

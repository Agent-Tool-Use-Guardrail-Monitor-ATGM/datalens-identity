"""Real PostgreSQL ownership/authentication and isolated volume lifecycle checks."""

import json
import os
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest
from check_config import read_config
from init_local_database import DATABASE_SECRET_NAMES

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "datalens-identity-tests"
PERSISTENCE_PROJECT = "datalens-identity-persistence-tests"
SERVICE = "datalens-identity-postgres"


class FixtureDatabase:
    def __init__(self, prefix):
        self.prefix = prefix

    def command(self, *arguments, sql=None, timeout=90):
        environment = dict(os.environ)
        for name in DATABASE_SECRET_NAMES:
            environment.pop(name, None)
        return subprocess.run(
            ["docker", "compose", *self.prefix, *arguments],
            cwd=ROOT,
            env=environment,
            input=sql,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def sql(self, query, *, password=None, database=None):
        # Only fixed synthetic inputs are passed to fixture clients; never host secrets.
        client = 'export PGPASSWORD="$IDENTITY_DB_PASSWORD"; '
        if password is not None:
            assert password == "wrong-test-only-password"
            client = "export PGPASSWORD=wrong-test-only-password; "
        target = '"$POSTGRES_DB"' if database is None else database
        assert database in {None, "postgres", "template1"}
        client += (
            "exec psql -X --no-password -v ON_ERROR_STOP=1 -h 127.0.0.1 "
            f'-U "$IDENTITY_DB_USER" -d {target} -Atq'
        )
        return self.command("exec", "-T", SERVICE, "bash", "-c", client, sql=query)

    def value(self, query):
        result = self.sql(query)
        assert result.returncode == 0, "Disposable identity SQL failed."
        return result.stdout.strip()

    def check_target(self):
        assert (
            self.value("SELECT current_database(), current_user;")
            == "identity_test_db|identity_test"
        )


@pytest.fixture
def database():
    if os.environ.get("IDENTITY_DATABASE_TESTS") != "1":
        if os.environ.get("CI"):
            pytest.fail("CI must enable IDENTITY_DATABASE_TESTS; database tests cannot be skipped.")
        pytest.skip("Start compose.test.yaml and set IDENTITY_DATABASE_TESTS=1.")
    fixture = FixtureDatabase(["-p", PROJECT, "-f", str(ROOT / "compose.test.yaml")])
    fixture.check_target()
    return fixture


@pytest.mark.postgres
def test_rendered_fixture_uses_contract_image_and_no_host_ports_or_persistent_storage(database):
    model_result = database.command("config", "--format", "json")
    assert model_result.returncode == 0
    model = json.loads(model_result.stdout)
    contract = read_config()
    service = model["services"][SERVICE]
    assert model["name"] == contract["profiles"]["test"]["project"]
    assert service["image"] == contract["images"]["postgres"]
    assert not service.get("ports")
    assert not model.get("volumes")
    assert "/var/lib/postgresql/data" in service["tmpfs"]
    assert service["environment"]["POSTGRES_DB"] == "identity_test_db"
    assert not any("AGENT" in key for key in service["environment"])
    assert all(mount["type"] == "bind" and mount["read_only"] for mount in service["volumes"])


@pytest.mark.postgres
def test_application_role_owns_its_database_without_cluster_privileges(database):
    assert (
        database.value(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user;"
        )
        == "f|f|f|f|f"
    )
    assert (
        database.value(
            "SELECT pg_get_userbyid(datdba) = current_user FROM pg_database "
            "WHERE datname = current_database();"
        )
        == "t"
    )
    assert (
        database.value("SELECT count(*) FROM pg_auth_members WHERE member = current_user::regrole;")
        == "0"
    )


@pytest.mark.postgres
def test_application_can_manage_its_schema_and_data(database):
    schema = "identity_probe_" + uuid4().hex
    try:
        assert (
            database.value(
                f"CREATE SCHEMA {schema}; CREATE TABLE {schema}.probe (id int PRIMARY KEY); "
                f"INSERT INTO {schema}.probe VALUES (7); "
                f"ALTER TABLE {schema}.probe ADD COLUMN note text; "
                f"SELECT id FROM {schema}.probe;"
            )
            == "7"
        )
    finally:
        assert database.sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE;").returncode == 0


@pytest.mark.postgres
@pytest.mark.parametrize("target", ["postgres", "template1"])
def test_application_cannot_connect_to_other_databases(database, target):
    assert database.sql("SELECT 1;", database=target).returncode != 0


@pytest.mark.postgres
@pytest.mark.parametrize(
    "query",
    [
        "CREATE ROLE forbidden_identity_role;",
        "CREATE DATABASE forbidden_identity_db;",
        "SET ROLE identity_bootstrap;",
    ],
)
def test_application_cannot_escalate_or_create_cluster_resources(database, query):
    assert database.sql(query).returncode != 0


@pytest.mark.postgres
def test_wrong_password_is_rejected_over_tcp_without_interactive_prompt(database):
    assert database.sql("SELECT 1;", password="wrong-test-only-password").returncode != 0


@pytest.mark.postgres
def test_missing_bootstrap_password_is_rejected_before_any_container_is_created(database, tmp_path):
    environment_file = tmp_path / "blank.env"
    environment_file.write_text("IDENTITY_DB_PASSWORD=test-only-app-password\n", encoding="utf-8")
    missing = FixtureDatabase(
        [
            "-p",
            PERSISTENCE_PROJECT,
            "--env-file",
            str(environment_file),
            "-f",
            str(ROOT / "compose.yaml"),
        ]
    )
    result = missing.command("config", "--format", "json")
    assert result.returncode != 0
    assert "IDENTITY_DB_BOOTSTRAP_PASSWORD" in result.stderr


@pytest.mark.postgres
def test_development_volume_configuration_retains_data_across_restart_without_touching_local_data(
    database, tmp_path
):
    environment_file = tmp_path / "fixture.env"
    environment_file.write_text(
        "IDENTITY_DB_BOOTSTRAP_PASSWORD=identity-test-bootstrap-only-password\n"
        "IDENTITY_DB_PASSWORD=identity-test-app-only-password\n",
        encoding="utf-8",
    )
    override = tmp_path / "fixture.json"
    override.write_text(
        json.dumps(
            {
                "services": {
                    SERVICE: {
                        "environment": {
                            "POSTGRES_DB": "identity_test_db",
                            "IDENTITY_DB_USER": "identity_test",
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    persistent = FixtureDatabase(
        [
            "-p",
            PERSISTENCE_PROJECT,
            "--env-file",
            str(environment_file),
            "-f",
            str(ROOT / "compose.yaml"),
            "-f",
            str(override),
        ]
    )
    rendered = persistent.command("config", "--format", "json")
    assert rendered.returncode == 0
    model = json.loads(rendered.stdout)
    assert model["name"] == PERSISTENCE_PROJECT
    assert set(model["services"]) == {SERVICE}
    assert model["services"][SERVICE]["image"] == read_config()["images"]["postgres"]
    assert not model["services"][SERVICE].get("ports")
    # A cleanup may delete only this explicitly disposable project's named volume.
    assert len(model["volumes"]) == 1
    assert all(
        volume["name"].startswith(PERSISTENCE_PROJECT + "_") and not volume.get("external")
        for volume in model["volumes"].values()
    )
    try:
        assert persistent.command("up", "-d", "--wait", "--wait-timeout", "90").returncode == 0
        persistent.check_target()
        persistent.value(
            "CREATE TABLE persistence_probe (id int); INSERT INTO persistence_probe VALUES (9);"
        )
        assert persistent.command("restart", "--no-deps", SERVICE).returncode == 0
        assert persistent.command("up", "-d", "--wait", "--wait-timeout", "90").returncode == 0
        assert persistent.value("SELECT id FROM persistence_probe;") == "9"
    finally:
        assert persistent.command("down", "--volumes").returncode == 0

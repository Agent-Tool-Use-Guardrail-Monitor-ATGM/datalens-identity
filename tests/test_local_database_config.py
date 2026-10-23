"""Local credential setup must be safe to repeat and independent of services."""

from check_config import check_secrets
from init_local_database import DATABASE_SECRET_NAMES, main


def test_local_secret_creation_is_private_distinct_and_never_overwrites(tmp_path, capsys):
    target = tmp_path / ".env.postgres"
    assert main(["--output", str(target)]) == 0
    before = target.read_bytes()
    values = dict(
        line.split("=", 1)
        for line in before.decode().splitlines()
        if line and not line.startswith("#")
    )
    assert values.keys() == DATABASE_SECRET_NAMES
    check_secrets(values, names=DATABASE_SECRET_NAMES)
    assert main(["--output", str(target)]) == 1
    assert target.read_bytes() == before
    output = capsys.readouterr().out
    assert not any(value in output for value in values.values())
    assert "not overwritten" in output


def test_local_secret_creation_handles_unavailable_parent_safely(tmp_path, capsys):
    assert main(["--output", str(tmp_path / "absent" / ".env.postgres")]) == 1
    assert capsys.readouterr().out.strip() == "Unable to create local database configuration."

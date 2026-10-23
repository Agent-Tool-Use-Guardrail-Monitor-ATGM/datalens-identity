"""Create ignored local PostgreSQL secrets once, without starting services."""

import argparse
import os
import secrets
from pathlib import Path

DATABASE_SECRET_NAMES = frozenset({"IDENTITY_DB_BOOTSTRAP_PASSWORD", "IDENTITY_DB_PASSWORD"})
DEFAULT_PATH = Path(__file__).resolve().parents[1] / ".env.postgres"


def create_secret_file(path: Path) -> None:
    content = "# Generated local database secrets; never commit or print this file.\n"
    content += "".join(
        f"{name}={secrets.token_urlsafe(32)}\n" for name in sorted(DATABASE_SECRET_NAMES)
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_PATH)
    args = parser.parse_args(argv)
    try:
        create_secret_file(args.output)
    except FileExistsError:
        print("Local database configuration already exists; it was not overwritten.")
        return 1
    except OSError:
        print("Unable to create local database configuration.")
        return 1
    print("Local database configuration created; no secrets printed and no services started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

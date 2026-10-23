"""Explicit local capture configuration; real SMTP is configured separately."""

import argparse
import getpass

import httpx
from bootstrap_identity import Admin, SetupError


def configure_capture(admin, realm):
    admin.request(
        "PUT",
        realm,
        {
            "smtpServer": {
                "host": "identity-mailpit",
                "port": "1025",
                "from": "identity@example.invalid",
                "fromDisplayName": "DataLens Identity",
                "auth": "false",
                "ssl": "false",
                "starttls": "false",
            }
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin", required=True)
    args = parser.parse_args()
    admin = Admin("http://localhost:8081", args.admin, getpass.getpass("Administrator password: "))
    try:
        configure_capture(admin, "datalens")
    finally:
        admin.close()
    print("Local email capture configured. Invitations remain administrator-initiated.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, httpx.HTTPError, KeyError, ValueError):
        print("Email setup failed; inspect local configuration securely.")
        raise SystemExit(1) from None

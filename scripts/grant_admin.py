"""Grant provider administration only to an operator-selected stable subject."""
from __future__ import annotations

import argparse
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jstu_passkey.storage import PasskeyStore


def grant(database: Path, subject: str) -> None:
    if not database.is_file():
        raise ValueError("Existing service database required")
    try:
        handle = urlsafe_b64decode(subject + "=" * (-len(subject) % 4))
    except ValueError as error:
        raise ValueError("Invalid subject") from error
    if not handle or urlsafe_b64encode(handle).decode().rstrip("=") != subject:
        raise ValueError("Invalid subject")
    store = PasskeyStore(database)
    user = store.get_user_by_handle(handle)
    if user is None or user.disabled_at is not None:
        raise ValueError("Subject does not identify an enabled provider user")
    current = store.get_permissions(user.id)
    store.set_permissions(user.id, {**current, "admin": True, "login": True})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--subject", required=True)
    args = parser.parse_args()
    try:
        grant(args.database, args.subject)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Provider administration granted to the selected existing subject.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

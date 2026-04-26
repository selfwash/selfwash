"""
Promote a dashboard user: approved + active + superuser (or grant permissions only).

Run against Railway Postgres (or any DB that matches db.py), e.g.:

  set DATABASE_URL=postgresql+psycopg://...
  py scripts/promote_user_to_admin.py --id 1

  py scripts/promote_user_to_admin.py --username nevo@selfwash.co.il

  railway run py scripts/promote_user_to_admin.py --id 1

Requires: same env as the app (DATABASE_URL), python with project deps.
"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import load_dotenv

# Project root: parent of scripts/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

from sqlalchemy import delete, select  # noqa: E402
from db import AppUser, AppUserPermission, SessionLocal, init_db  # noqa: E402
from security import ALL_KNOWN_PERMISSIONS, PERM_ADMIN_USERS, REVIEW_APPROVED  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--id", type=int, help="app_users.id")
    p.add_argument("--username", type=str, help="exact username (e.g. email used as login)")
    p.add_argument(
        "--no-super",
        action="store_true",
        help="do not set is_superuser; instead grant 'permissions' (comma-separated, default admin+nayax+machines)",
    )
    p.add_argument(
        "--permissions",
        type=str,
        default=f"{PERM_ADMIN_USERS},nayax.read,machines.read,machines.write",
        help="used with --no-super",
    )
    a = p.parse_args()
    if a.id is None and not a.username:
        p.error("Provide --id or --username")
    if not os.environ.get("DATABASE_URL", "").strip():
        print("ERROR: DATABASE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    init_db()
    db = SessionLocal()
    try:
        if a.id is not None:
            u = db.get(AppUser, a.id)
        else:
            u = db.scalar(select(AppUser).where(AppUser.username == a.username.strip()))
        if u is None:
            print("User not found.", file=sys.stderr)
            sys.exit(2)
        u.review_status = REVIEW_APPROVED
        u.is_active = True
        if a.no_super:
            u.is_superuser = False
            want = {x.strip() for x in a.permissions.split(",") if x.strip()}
            bad = want - set(ALL_KNOWN_PERMISSIONS)
            if bad:
                print(f"Unknown permissions: {bad}", file=sys.stderr)
                sys.exit(3)
            db.execute(delete(AppUserPermission).where(AppUserPermission.user_id == u.id))
            for perm in want:
                db.add(AppUserPermission(user_id=u.id, permission=perm))
        else:
            u.is_superuser = True
        db.commit()
        print(f"OK: user id={u.id} username={u!r} review=approved is_active={u.is_active} is_superuser={u.is_superuser}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

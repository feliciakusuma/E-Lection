"""
One-time migration tool to move data from the legacy SQLite test.db into Postgres.

Run from the repo root:
    python backend/migrate_sqlite_to_postgres.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

from database import Base, cipher_suite, engine as pg_engine, User
from services.seed import ensure_core_schema

SQLITE_PATH = Path(__file__).resolve().parent.parent / "test.db"
SQLITE_URL = f"sqlite:///{SQLITE_PATH.as_posix()}"


def decrypt_or_none(blob: Any) -> str | None:
    if blob is None:
        return None
    try:
        return cipher_suite.decrypt(blob).decode()
    except Exception:
        return None


def encrypt_token_or_none(token: Any) -> str | None:
    if not token:
        return None
    try:
        return cipher_suite.encrypt(str(token).encode("utf-8")).decode("utf-8")
    except Exception:
        return str(token)


def hash_token_or_none(token: Any) -> str | None:
    if not token:
        return None
    return User._hash_verification_token(str(token))


def migrate_users(sqlite_conn: Connection, pg_conn: Connection) -> None:
    if pg_conn.execute(text("SELECT COUNT(*) FROM users")).scalar() > 0:
        print("users: skipped (destination not empty)")
        return
    rows = sqlite_conn.execute(
        text(
            """
            SELECT id, first_name_encrypted, last_name_encrypted, email_encrypted,
                   student_id_encrypted, password_hash, status, verification_token,
                   is_active, created_at
            FROM users
            """
        )
    )
    payload = []
    for r in rows:
        payload.append(
            {
                "id": r.id,
                "first_name": decrypt_or_none(r.first_name_encrypted),
                "last_name": decrypt_or_none(r.last_name_encrypted),
                "email": decrypt_or_none(r.email_encrypted),
                "student_id": decrypt_or_none(r.student_id_encrypted),
                "password_hash": r.password_hash,
                "status": r.status,
                "verification_token_encrypted": encrypt_token_or_none(r.verification_token),
                "verification_token_hash": hash_token_or_none(r.verification_token),
                "is_active": r.is_active,
                "created_at": r.created_at,
            }
        )
    if payload:
        pg_conn.execute(
            text(
                """
                INSERT INTO users (
                    id, first_name, last_name, email, student_id,
                    password_hash, status, verification_token_encrypted,
                    verification_token_hash, is_active, created_at
                )
                VALUES (
                    :id, :first_name, :last_name, :email, :student_id,
                    :password_hash, :status, :verification_token_encrypted,
                    :verification_token_hash, :is_active, :created_at
                )
                """
            ),
            payload,
        )
    print(f"users: migrated {len(payload)} rows")


def migrate_elections(sqlite_conn: Connection, pg_conn: Connection) -> None:
    if pg_conn.execute(text("SELECT COUNT(*) FROM elections")).scalar() > 0:
        print("elections: skipped (destination not empty)")
        return
    rows = sqlite_conn.execute(text("SELECT * FROM elections"))
    payload = []
    for r in rows:
        results_json = None
        if r.results_encrypted:
            try:
                results_json = cipher_suite.decrypt(r.results_encrypted).decode()
            except Exception:
                results_json = None
        payload.append(
            {
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "start_date": r.start_date,
                "end_date": r.end_date,
                "status": r.status,
                "is_active": r.is_active,
                "results_json": results_json,
                "created_at": r.created_at,
            }
        )
    if payload:
        pg_conn.execute(
            text(
                """
                INSERT INTO elections (
                    id, title, description, start_date, end_date,
                    status, is_active, results_json, created_at
                )
                VALUES (
                    :id, :title, :description, :start_date, :end_date,
                    :status, :is_active, :results_json, :created_at
                )
                """
            ),
            payload,
        )
    print(f"elections: migrated {len(payload)} rows")


def migrate_table_copy(sqlite_conn: Connection, pg_conn: Connection, table: str, columns: Iterable[str]) -> None:
    if pg_conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar() > 0:
        print(f"{table}: skipped (destination not empty)")
        return
    rows = sqlite_conn.execute(text(f"SELECT {', '.join(columns)} FROM {table}"))
    payload = [dict(zip(columns, row)) for row in rows]
    if payload:
        placeholders = ", ".join(f":{c}" for c in columns)
        pg_conn.execute(
            text(f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"),
            payload,
        )
    print(f"{table}: migrated {len(payload)} rows")


def migrate_system_config(sqlite_conn: Connection, pg_conn: Connection) -> None:
    if pg_conn.execute(text("SELECT COUNT(*) FROM system_config")).scalar() > 0:
        print("system_config: skipped (destination not empty)")
        return
    rows = sqlite_conn.execute(text("SELECT id, key, value_encrypted, is_readonly, created_at FROM system_config"))
    payload = []
    for r in rows:
        payload.append(
            {
                "id": r.id,
                "key": r.key,
                "value": decrypt_or_none(r.value_encrypted),
                "is_readonly": r.is_readonly,
                "created_at": r.created_at,
            }
        )
    if payload:
        pg_conn.execute(
            text(
                """
                INSERT INTO system_config (id, key, value, is_readonly, created_at)
                VALUES (:id, :key, :value, :is_readonly, :created_at)
                """
            ),
            payload,
        )
    print(f"system_config: migrated {len(payload)} rows")


def main() -> None:
    if not SQLITE_PATH.exists():
        print("SQLite database not found, nothing to migrate.")
        return

    # Ensure Postgres schema is correct before migrating.
    ensure_core_schema()
    Base.metadata.create_all(bind=pg_engine)

    sqlite_engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})

    with sqlite_engine.connect() as sqlite_conn, pg_engine.begin() as pg_conn:
        migrate_users(sqlite_conn, pg_conn)
        migrate_elections(sqlite_conn, pg_conn)
        migrate_table_copy(
            sqlite_conn,
            pg_conn,
            "candidates",
            [
                "candidate_id",
                "full_name",
                "student_id",
                "major",
                "cohort",
                "position",
                "status",
                "is_active",
                "created_at",
            ],
        )
        migrate_table_copy(
            sqlite_conn,
            pg_conn,
            "cohort",
            ["cohort_num"],
        )
        migrate_table_copy(
            sqlite_conn,
            pg_conn,
            "majors",
            ["major_code", "major_name"],
        )
        migrate_table_copy(
            sqlite_conn,
            pg_conn,
            "admins",
            ["id", "email", "password_hash", "is_active", "created_at"],
        )
        migrate_table_copy(
            sqlite_conn,
            pg_conn,
            "audit_logs",
            [
                "id",
                "table_name",
                "record_id",
                "action",
                "old_values",
                "new_values",
                "user_id",
                "ip_address",
                "user_agent",
                "timestamp",
                "is_authorized",
            ],
        )
        migrate_table_copy(
            sqlite_conn,
            pg_conn,
            "candidate_tickets",
            ["id", "election_id", "president_candidate_id", "vice_president_candidate_id", "created_at"],
        )
        migrate_system_config(sqlite_conn, pg_conn)

    print("Migration complete.")


if __name__ == "__main__":
    main()

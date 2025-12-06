"""
Utility script to drop legacy `data_hash` columns from tables.

Supports Postgres and modern SQLite (3.35+ with DROP COLUMN support).

Usage:
  python -m backend.migrations.drop_data_hash_columns
"""
import os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# Prefer DATABASE_URL; fall back to defaults from env
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql+psycopg2://{os.getenv('POSTGRES_USER', 'postgres')}:"
    f"{os.getenv('POSTGRES_PASSWORD', '')}@{os.getenv('POSTGRES_HOST', 'localhost')}:"
    f"{os.getenv('POSTGRES_PORT', '5432')}/{os.getenv('POSTGRES_DB', 'demo')}",
)


def drop_column(engine: Engine, table: str, column: str) -> None:
    dialect = engine.dialect.name
    ddl = f'ALTER TABLE IF EXISTS "{table}" DROP COLUMN IF EXISTS "{column}"'
    if dialect == "sqlite":
        ddl = f'ALTER TABLE "{table}" DROP COLUMN "{column}"'
    with engine.begin() as conn:
        conn.execute(text(ddl))
        print(f"Dropped {column} from {table} (dialect={dialect})")


def main():
    engine = create_engine(DATABASE_URL)
    for table in ("votes", "candidates", "elections"):
        try:
            drop_column(engine, table, "data_hash")
        except Exception as exc:
            print(f"Skipping {table}.data_hash: {exc}")


if __name__ == "__main__":
    main()

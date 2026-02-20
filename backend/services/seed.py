from sqlalchemy import text
import uuid
from .. import config
from ..database import SessionLocal, engine, User, Admin
from .security import get_password_hash
from .audit import security_logger
from ..utils.validation import MAJOR_CODE_MAP, SUPPORTED_COHORTS
from sqlalchemy import text as sql_text

# Fallback support admin to ensure access even if no env defaults provided.
SUPPORT_ADMIN = {
    "email": "felicia.kusuma294@gmail.com",
    "password": "Election.77",
    "full_name": "Felicia Kusuma",
    "student_id": "2023000001",
}


def _resolve_ids_from_student_id(conn, student_id: str | None) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    if not student_id:
        return None, None
    sid = student_id.strip()
    cohort_num = None
    major_code = None
    if sid.isdigit() and len(sid) >= 6:
        cohort_num = int(sid[:4])
        major_code = int(sid[4:6])
    cohort_id = None
    major_id = None
    if cohort_num is not None:
        row = conn.execute(sql_text("SELECT cohort_id FROM cohort WHERE cohort_num = :c"), {"c": cohort_num}).first()
        cohort_id = row[0] if row else None
    if major_code is not None:
        row = conn.execute(sql_text("SELECT major_id FROM majors WHERE major_code = :m"), {"m": major_code}).first()
        major_id = row[0] if row else None
    return cohort_id, major_id


def seed_default_accounts():
    """Ensure default student accounts exist for demo access."""
    db = SessionLocal()
    try:
        created_any = False
        with engine.begin() as conn:
            for account in config.DEFAULT_ACCOUNTS:
                if not User.find_by_email(db, account["email"]):
                    cohort_id, major_id = _resolve_ids_from_student_id(conn, account["student_id"])
                    user = User(
                        first_name=account["first_name"],
                        last_name=account["last_name"],
                        email=account["email"],
                        student_id=account["student_id"],
                        cohort_id=cohort_id,
                        major_id=major_id,
                    )
                    user.status = "verified"
                    user.is_active = True
                    db.add(user)
                    created_any = True
        if created_any:
            db.commit()
            security_logger.info("Default demo accounts seeded.")
    except Exception as exc:
        db.rollback()
        security_logger.error(f"Default account seeding failed: {exc}")
    finally:
        db.close()


def ensure_support_admin():
    """Guarantee a baseline admin account for local access."""
    db = SessionLocal()
    try:
        # Normalize admin PK column name if legacy table exists
        email = SUPPORT_ADMIN["email"]
        admin = db.query(Admin).filter(Admin.email == email).first()
        if not admin:
            with engine.begin() as conn:
                user = User.find_by_email(db, email)
                full_name = getattr(user, "full_name", None) or getattr(user, "first_name", None)
                if not full_name:
                    fname = getattr(user, "first_name", None)
                    lname = getattr(user, "last_name", None)
                    full_name = " ".join(filter(None, [fname, lname])) if fname or lname else SUPPORT_ADMIN["full_name"]
                # Admin table still uses password_hash, but user table no longer stores passwords.
                password_hash = get_password_hash(SUPPORT_ADMIN["password"])
                cohort_id, major_id = _resolve_ids_from_student_id(conn, SUPPORT_ADMIN["student_id"])
                if not user:
                    # create minimal user record for admin identity (non-admin user table, no password)
                    user = User(
                        first_name=full_name,
                        last_name="",
                        email=email,
                        student_id=SUPPORT_ADMIN["student_id"],
                        cohort_id=cohort_id,
                        major_id=major_id,
                        status="verified",
                        is_active=True,
                    )
                    db.add(user)
                    db.flush()
                else:
                    updated_user = False
                    if cohort_id and getattr(user, "cohort_id", None) != cohort_id:
                        user.cohort_id = cohort_id
                        updated_user = True
                    if major_id and getattr(user, "major_id", None) != major_id:
                        user.major_id = major_id
                        updated_user = True
                    if updated_user:
                        db.add(user)
                admin = Admin(
                    full_name=full_name or SUPPORT_ADMIN["full_name"],
                    email=email,
                    password_hash=password_hash,
                    status="active",
                    is_active=True,
                )
                db.add(admin)
                db.commit()
                security_logger.info("Support admin seeded in admins table")
        else:
            updated = False
            if admin.status != "active":
                admin.status = "active"
                updated = True
            if not admin.is_active:
                admin.is_active = True
                updated = True
            if updated:
                db.add(admin)
                db.commit()
    except Exception as exc:
        db.rollback()
        security_logger.warning(f"Support admin ensure failed: {exc}")
    finally:
        db.close()


def seed_cohorts_and_majors():
    """Populate core cohort and major reference data if missing."""
    try:
        with engine.begin() as conn:
            # Recreate lightweight reference tables to guarantee constraints.
            conn.execute(text("DROP TABLE IF EXISTS cohort CASCADE;"))
            conn.execute(text("DROP TABLE IF EXISTS majors CASCADE;"))
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto;"))
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS cohort (
                        cohort_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        cohort_num INTEGER NOT NULL UNIQUE
                    );
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS majors (
                        major_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        major_code INTEGER NOT NULL UNIQUE,
                        major_name VARCHAR(200) NOT NULL
                    );
                    """
                )
            )
            for cohort_year in SUPPORTED_COHORTS:
                conn.execute(
                    text(
                        """
                        INSERT INTO cohort (cohort_num)
                        VALUES (:cohort_num)
                        ON CONFLICT (cohort_num) DO UPDATE SET cohort_num = EXCLUDED.cohort_num
                        """
                    ),
                    {"cohort_num": cohort_year},
                )
            for code, name in MAJOR_CODE_MAP.items():
                conn.execute(
                    text(
                        """
                        INSERT INTO majors (major_code, major_name)
                        VALUES (:major_code, :major_name)
                        ON CONFLICT (major_code) DO UPDATE SET major_name = EXCLUDED.major_name
                        """
                    ),
                    {"major_code": int(code), "major_name": name},
                )
    except Exception as exc:
        security_logger.warning(f"Seeding cohorts/majors skipped/failed: {exc}")


def ensure_admins_table_and_account():
    """Create a simple admins table and seed the requested admin account as fallback."""
    admin_email = config.ADMIN_EMAIL
    admin_password = config.ADMIN_PASSWORD
    admin_full_name = config.ADMIN_FULL_NAME
    if not admin_email or not admin_password:
        # Fall back to the baked-in support admin to keep local bootstrap working without env vars.
        security_logger.info("Admin credentials not provided via env; using support admin fallback")
        admin_email = SUPPORT_ADMIN["email"]
        admin_password = SUPPORT_ADMIN["password"]
        admin_full_name = SUPPORT_ADMIN["full_name"]
    try:
        from sqlalchemy import text as _text

        with engine.begin() as conn:
            conn.execute(
                _text(
                    f"""
                    CREATE TABLE IF NOT EXISTS admins (
                      id SERIAL PRIMARY KEY,
                      full_name VARCHAR(200) NOT NULL,
                      email VARCHAR(255) NOT NULL UNIQUE,
                      password_hash VARCHAR(255) NOT NULL,
                      status VARCHAR(20) DEFAULT 'active',
                      verification_token VARCHAR(100),
                      is_active BOOLEAN NOT NULL DEFAULT TRUE,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
            )
            ph = get_password_hash(admin_password)
        # Upsert admin via ORM (avoids type mismatches)
        db = SessionLocal()
        try:
            email_lc = admin_email.strip().lower()
            admin_row = db.query(Admin).filter(Admin.email == email_lc).first()
            if not admin_row:
                admin_row = Admin(
                    full_name=admin_full_name,
                    email=email_lc,
                    password_hash=ph,
                    status="active",
                    is_active=True,
                )
                db.add(admin_row)
            else:
                admin_row.full_name = admin_full_name
                admin_row.password_hash = ph
                admin_row.status = "active"
                admin_row.is_active = True
            db.commit()
            security_logger.info("Admins table ensured and admin account synced from env configuration")
        finally:
            db.close()
    except Exception as exc:
        security_logger.warning(f"Admins table setup skipped/failed: {exc}")


def reset_user_table():
    """Drop and recreate the users table to match the latest schema."""
    try:
        security_logger.warning("Resetting users table to match current schema")
        User.__table__.drop(engine, checkfirst=True)
        User.__table__.create(engine, checkfirst=True)
    except Exception as exc:
        security_logger.error(f"Failed to reset users table: {exc}")
        raise


def create_default_accounts(db) -> bool:
    created_any = False
    for account in config.DEFAULT_ACCOUNTS:
        if not User.find_by_email(db, account["email"]):
            user = User(
                first_name=account["first_name"],
                last_name=account["last_name"],
                email=account["email"],
                student_id=account["student_id"],
            )
            user.status = "verified"
            user.is_active = True
            db.add(user)
            created_any = True
    return created_any


def ensure_core_schema():
    """
    Ensure critical tables have the expected schema.
    Drops and recreates only if legacy schema is detected (to avoid wiping data).
    """
    try:
        with engine.begin() as conn:
            def drop_if_missing(table: str, required: set[str]):
                reg = conn.execute(text(f"SELECT to_regclass('public.{table}')")).scalar()
                if not reg:
                    return
                cols = conn.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = :t
                        """
                    ),
                    {"t": table},
                ).scalars().all()
                if not required.issubset(set(cols)):
                    conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE;"))

            # Drop users table only if legacy encrypted/audit columns are present (keep data otherwise).
            regclass = conn.execute(text("SELECT to_regclass('public.users')")).scalar()
            if regclass:
                legacy_cols = conn.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = 'users'
                        """
                    )
                ).scalars().all()
                if ("first_name_encrypted" in legacy_cols
                        or "email_encrypted" in legacy_cols
                        or "student_id_encrypted" in legacy_cols
                        or "created_by" in legacy_cols
                        or "is_admin" in legacy_cols):
                    conn.execute(text("DROP TABLE IF EXISTS users CASCADE;"))
                else:
                    if "has_voted" not in legacy_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS has_voted BOOLEAN NOT NULL DEFAULT FALSE;"))
                    # Keep a single plaintext verification token column.
                    if "verification_token_encrypted" in legacy_cols and "verification_token" not in legacy_cols:
                        conn.execute(text("ALTER TABLE users RENAME COLUMN verification_token_encrypted TO verification_token;"))
                        legacy_cols = conn.execute(
                            text(
                                """
                                SELECT column_name
                                FROM information_schema.columns
                                WHERE table_name = 'users'
                                """
                            )
                        ).scalars().all()
                    if "verification_token" in legacy_cols:
                        conn.execute(text("ALTER TABLE users ALTER COLUMN verification_token TYPE TEXT;"))
                    if "verification_token_hash" in legacy_cols:
                        conn.execute(text("DROP INDEX IF EXISTS ix_users_verification_token_hash;"))
                        conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS verification_token_hash;"))

            # Drop elections table if legacy encrypted results column exists.
            election_reg = conn.execute(text("SELECT to_regclass('public.elections')")).scalar()
            if election_reg:
                election_cols = conn.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = 'elections'
                        """
                    )
                ).scalars().all()
                if "results_encrypted" in election_cols:
                    conn.execute(text("DROP TABLE IF EXISTS elections CASCADE;"))

            # Drop legacy tables we no longer use.
            conn.execute(text("DROP TABLE IF EXISTS system_config CASCADE;"))
            conn.execute(text("DROP TABLE IF EXISTS voter_election_status CASCADE;"))
            conn.execute(text("DROP TABLE IF EXISTS election_ticket_tallies CASCADE;"))

            # Only drop data tables if schema is wrong (otherwise keep data).
            drop_if_missing(
                "audit_logs",
                {"id", "table_name", "record_id", "action", "timestamp", "is_authorized", "user_id", "ip_address", "user_agent"},
            )
            drop_if_missing(
                "votes",
                {
                    "id",
                    "election_id",
                    "vote_encrypted",
                    "vote_nonce",
                    "verification_code",
                    "is_counted",
                    "created_at",
                },
            )
            drop_if_missing(
                "candidate_tickets",
                {"id", "election_id", "president_candidate_id", "vice_president_candidate_id", "vote_count", "created_at", "updated_at"},
            )
            drop_if_missing(
                "candidates",
                {
                    "id",
                    "full_name",
                    "student_id",
                    "cohort_id",
                    "major_id",
                    "position",
                    "status",
                    "is_active",
                    "created_at",
                },
            )
            drop_if_missing(
                "elections",
                {
                    "id",
                    "title",
                    "description",
                    "start_date",
                    "end_date",
                    "status",
                    "is_active",
                    "results_json",
                    "created_at",
                },
            )
            drop_if_missing(
                "admins",
                {"id", "full_name", "email", "password_hash", "status", "verification_token", "is_active", "created_at"},
            )
    except Exception as exc:
        security_logger.warning(f"Schema check failed: {exc}")


def backfill_user_verification_tokens():
    """Normalize verification tokens as plain text."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        changed = False
        for u in users:
            token = u.verification_token
            if token:
                u.verification_token = token
                changed = True
        if changed:
            db.commit()
    except Exception as exc:
        db.rollback()
        security_logger.warning(f"Verification token backfill skipped/failed: {exc}")
    finally:
        db.close()

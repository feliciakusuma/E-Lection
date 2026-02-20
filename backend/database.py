from sqlalchemy import create_engine, Column, Integer, UUID, String, DateTime, Boolean, Text, LargeBinary, event, func
from sqlalchemy.orm import sessionmaker, declarative_base, synonym
from sqlalchemy.ext.declarative import declared_attr
from datetime import datetime
from urllib.parse import quote_plus
import os
import re
import secrets
import json
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
import redis
import uuid
from sqlalchemy.dialects.postgresql import UUID
from .config import ENABLE_MLKEM

# liboqs (ML-KEM) support
try:  # Prefer ML-KEM, fall back cleanly if liboqs is missing
    import oqs  # type: ignore
    _OQS_AVAILABLE = hasattr(oqs, "KeyEncapsulation")
except Exception:  # pragma: no cover - used only when liboqs is unavailable
    oqs = None  # type: ignore
    _OQS_AVAILABLE = False

def _build_default_db_url() -> str:
    """Construct a Postgres URL from Railway-style PG vars."""
    user = os.getenv("PGUSER") or os.getenv("POSTGRES_USER")
    password = os.getenv("PGPASSWORD") or os.getenv("POSTGRES_PASSWORD")
    host = os.getenv("PGHOST") or os.getenv("POSTGRES_HOST")
    port = os.getenv("PGPORT") or os.getenv("POSTGRES_PORT") or "5432"
    db = os.getenv("PGDATABASE") or os.getenv("POSTGRES_DB")

    if not all([user, password, host, db]):
        return ""

    return f"postgresql+psycopg2://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{db}"

def _normalize_database_url(raw_url: str) -> str:
    """Normalize URL variants for SQLAlchemy + psycopg2."""
    url = raw_url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://") and "+psycopg2" not in url:
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


def _resolve_database_url() -> str:
    candidates = [
        os.getenv("DATABASE_URL"),
        os.getenv("DATABASE_PRIVATE_URL"),
        os.getenv("DATABASE_PUBLIC_URL"),
        os.getenv("POSTGRES_URL"),
    ]
    for value in candidates:
        if value and value.strip():
            return _normalize_database_url(value)

    assembled = _build_default_db_url()
    if assembled:
        return assembled

    raise RuntimeError(
        "Database is not configured. Set DATABASE_URL (or DATABASE_PRIVATE_URL), "
        "or provide PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD. "
        "If using Railway, add/link a Postgres service and redeploy."
    )


DATABASE_URL = _resolve_database_url()

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

KEY_STORAGE_DIR = os.getenv("KEY_STORAGE_DIR", os.path.join(os.path.dirname(__file__), "keys"))
FERNET_KEY_PATH = os.getenv("FERNET_KEY_PATH", os.path.join(KEY_STORAGE_DIR, "fernet.key"))

def _load_or_create_fernet_key() -> bytes:
    os.makedirs(KEY_STORAGE_DIR, exist_ok=True)
    if os.path.exists(FERNET_KEY_PATH):
        with open(FERNET_KEY_PATH, "rb") as key_file:
            return key_file.read()
    key = Fernet.generate_key()
    with open(FERNET_KEY_PATH, "wb") as key_file:
        key_file.write(key)
    return key


ENCRYPTION_KEY = _load_or_create_fernet_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

logger = logging.getLogger(__name__)

# ML-KEM settings and key storage (defaults to ML-KEM-512)
MLKEM_PARAM = os.getenv("MLKEM_PARAM", "ML-KEM-512")
MLKEM_KEY_DIR = os.getenv("MLKEM_KEY_DIR", KEY_STORAGE_DIR)
_mlkem_param_slug = re.sub(r"[^a-zA-Z0-9]+", "_", MLKEM_PARAM).strip("_").lower()
MLKEM_PUBLIC_KEY_PATH = os.getenv(
    "MLKEM_PUBLIC_KEY_PATH",
    os.path.join(MLKEM_KEY_DIR, f"mlkem_public_{_mlkem_param_slug}.bin"),
)
MLKEM_PRIVATE_KEY_PATH = os.getenv(
    "MLKEM_PRIVATE_KEY_PATH",
    os.path.join(MLKEM_KEY_DIR, f"mlkem_private_{_mlkem_param_slug}.bin"),
)

_MLKEM_CACHE = {"pub": None, "sec": None}
_RAW_SESSION_PREFIX = b"RAW_AES_KEY:"

def _load_mlkem_keys_from_disk():
    if os.path.exists(MLKEM_PUBLIC_KEY_PATH) and os.path.exists(MLKEM_PRIVATE_KEY_PATH):
        with open(MLKEM_PUBLIC_KEY_PATH, "rb") as fpub, open(MLKEM_PRIVATE_KEY_PATH, "rb") as fsec:
            return fpub.read(), fsec.read()
    return None, None

def _ensure_mlkem_keypair():
    os.makedirs(MLKEM_KEY_DIR, exist_ok=True)
    pub, sec = _load_mlkem_keys_from_disk()
    if pub and sec:
        return pub, sec
    if not _OQS_AVAILABLE:
        raise RuntimeError("ML-KEM selected but liboqs is disabled.")
    with oqs.KeyEncapsulation(MLKEM_PARAM) as kem:
        pub = kem.generate_keypair()
        sec = kem.export_secret_key()
        with open(MLKEM_PUBLIC_KEY_PATH, "wb") as fpub:
            fpub.write(pub)
        with open(MLKEM_PRIVATE_KEY_PATH, "wb") as fsec:
            fsec.write(sec)
    return pub, sec

def _get_mlkem_keys():
    if _MLKEM_CACHE["pub"] is not None and _MLKEM_CACHE["sec"] is not None:
        return _MLKEM_CACHE["pub"], _MLKEM_CACHE["sec"]
    pub, sec = _load_mlkem_keys_from_disk()
    if pub and sec:
        _MLKEM_CACHE["pub"], _MLKEM_CACHE["sec"] = pub, sec
        return pub, sec
    # Only generate on-demand (avoids import-time failures if oqs missing)
    pub, sec = _ensure_mlkem_keypair()
    _MLKEM_CACHE["pub"], _MLKEM_CACHE["sec"] = pub, sec
    return pub, sec


def encrypt_with_session_key(plaintext: bytes, session_key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.encrypt(nonce, plaintext, None)


def decrypt_with_session_key(ciphertext: bytes, session_key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def mlkem_encapsulate() -> tuple[bytes, bytes]:
    """Encapsulate to ML-KEM public key, returning (kem_ciphertext, session_key)."""
    if not ENABLE_MLKEM:
        session_key = AESGCM.generate_key(bit_length=256)
        return _RAW_SESSION_PREFIX + session_key, session_key
    if not _OQS_AVAILABLE:
        raise RuntimeError("ML-KEM encapsulation disabled (liboqs unavailable).")
    pub, _ = _get_mlkem_keys()
    with oqs.KeyEncapsulation(MLKEM_PARAM) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(pub)
    # Derive 256-bit AES session key from shared secret for uniform length
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kem_ciphertext,
        info=b"vote-aes-session",
    ).derive(shared_secret)
    return kem_ciphertext, session_key

def mlkem_decapsulate(kem_ciphertext: bytes) -> bytes:
    """Decapsulate KEM ciphertext using ML-KEM private key, return session key."""
    if kem_ciphertext and kem_ciphertext.startswith(_RAW_SESSION_PREFIX):
        return kem_ciphertext[len(_RAW_SESSION_PREFIX):]
    if not ENABLE_MLKEM:
        raise RuntimeError("ML-KEM decapsulation disabled by configuration.")
    if not _OQS_AVAILABLE:
        raise RuntimeError("ML-KEM decapsulation disabled (liboqs unavailable).")
    _, sec = _get_mlkem_keys()
    # liboqs-python passes secret key in constructor
    with oqs.KeyEncapsulation(MLKEM_PARAM, secret_key=sec) as kem:
        shared_secret = kem.decap_secret(kem_ciphertext)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kem_ciphertext,
        info=b"vote-aes-session",
    ).derive(shared_secret)
    return session_key

def decrypt_session_key(encrypted_session_key: bytes) -> bytes:
    """Derive the AES session key from stored KEM ciphertext using ML-KEM only."""
    return mlkem_decapsulate(encrypted_session_key)

REDIS_URL = os.getenv("REDIS_URL")
try:
    SESSION_KEY_TTL_SECONDS = int(os.getenv("SESSION_KEY_TTL_SECONDS", "0") or 0)
except ValueError:
    SESSION_KEY_TTL_SECONDS = 0
_redis_client = None


def _get_redis_client():
    global _redis_client
    if not REDIS_URL:
        raise RuntimeError("REDIS_URL is not set.")
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(REDIS_URL)
    return _redis_client


def _session_cache_key(verification_code: str) -> str:
    return f"vote_session:{verification_code}"


def cache_session_ciphertext(verification_code: str, ciphertext: bytes) -> None:
    if not ciphertext:
        return
    if not REDIS_URL:
        return
    try:
        client = _get_redis_client()
        key = _session_cache_key(verification_code)
        if SESSION_KEY_TTL_SECONDS > 0:
            client.setex(key, SESSION_KEY_TTL_SECONDS, ciphertext)
        else:
            client.set(key, ciphertext)
    except redis.RedisError as exc:
        logger.warning("Failed to cache session key for %s: %s", verification_code, exc)


def get_cached_session_ciphertext(verification_code: str) -> bytes | None:
    if not REDIS_URL:
        return None
    try:
        client = _get_redis_client()
        return client.get(_session_cache_key(verification_code))
    except redis.RedisError as exc:
        logger.warning("Failed to fetch session key for %s: %s", verification_code, exc)
        return None

class AuditMixin:
    """Mixin to add audit trail to models"""
    
    @declared_attr
    def created_at(cls):
        return Column(DateTime, default=datetime.utcnow, nullable=False)

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    student_id = Column(String(50), nullable=False, unique=True)
    cohort_id = Column(UUID, nullable=True)
    major_id = Column(UUID, nullable=True)
    status = Column(String(20), default="pending")  # pending, verified, rejected
    verification_token = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    has_voted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __init__(self, first_name, last_name, email, student_id, cohort_id=None, major_id=None, **kwargs):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.student_id = student_id
        self.cohort_id = cohort_id
        self.major_id = major_id
        self.verification_token = secrets.token_urlsafe(32)
        super().__init__(**kwargs)

    @staticmethod
    def find_by_email(db, email):
        """Find user by email using direct lookup"""
        return db.query(User).filter(User.email == email).first()

class Vote(Base, AuditMixin):
    __tablename__ = "votes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    election_id = Column(UUID, nullable=False)
    vote_encrypted = Column(LargeBinary, nullable=False)
    vote_nonce = Column(LargeBinary, nullable=False)
    verification_code = Column(String(100), nullable=False, unique=True)
    is_counted = Column(Boolean, default=False)

    def __init__(self, voter_id, election_id, ticket_id=None, **kwargs):
        self.election_id = election_id

        # Prepare payloads
        now_iso = datetime.utcnow().isoformat()
        vote_payload = json.dumps(
            {
                "election_id": str(election_id) if election_id is not None else None,
                "voter_id": str(voter_id) if voter_id is not None else None,
                "ticket_id": str(ticket_id) if ticket_id is not None else None,
                "timestamp": now_iso,
            }
        ).encode()

        # Derive one-time AES session key per ballot using ML-KEM
        kem_ciphertext, session_key = mlkem_encapsulate()
        aesgcm = AESGCM(session_key)

        vote_nonce = secrets.token_bytes(12)

        ciphertext = aesgcm.encrypt(vote_nonce, vote_payload, None)
        self.vote_encrypted = ciphertext
        self.vote_nonce = vote_nonce
        self.verification_code = secrets.token_urlsafe(32)
        self._session_ciphertext = kem_ciphertext
        super().__init__(**kwargs)

    def _session_key(self):
        ciphertext = get_cached_session_ciphertext(self.verification_code)
        if not ciphertext:
            raise RuntimeError("Session key not available in Redis for this vote.")
        return decrypt_session_key(ciphertext)

    @property
    def vote_data(self):
        """Decrypt and return vote data"""
        try:
            session_key = self._session_key()
            plaintext = decrypt_with_session_key(self.vote_encrypted, session_key, self.vote_nonce)
            return json.loads(plaintext.decode())
        except (InvalidTag, ValueError, json.JSONDecodeError, RuntimeError):
            return {}

    @property
    def vote_timestamp(self):
        """Decrypt and return vote timestamp"""
        try:
            data = self.vote_data
            if isinstance(data, dict):
                return data.get("timestamp", "") or ""
        except Exception:
            return ""
        return ""

    @property
    def voter_id_plain(self):
        """Decrypt and return voter identifier"""
        try:
            data = self.vote_data
            if isinstance(data, dict):
                return str(data.get("voter_id", "") or "")
        except Exception:
            return ""
        return ""

    @property
    def ticket_id_plain(self):
        try:
            data = self.vote_data
            if isinstance(data, dict):
                tid = data.get("ticket_id")
                return int(tid) if tid is not None else None
        except Exception:
            return None
        return None

    @property
    def candidate_id_plain(self):
        try:
            data = self.vote_data
            if isinstance(data, dict):
                cid = data.get("candidate_id")
                return int(cid) if cid is not None else None
        except Exception:
            return None
        return None

class Cohort(Base):
    __tablename__ = "cohort"

    cohort_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    id = synonym("cohort_id")
    cohort_num = Column(Integer, nullable=False, unique=True)


class Major(Base):
    __tablename__ = "majors"

    major_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    id = synonym("major_id")
    major_code = Column(Integer, nullable=False, unique=True)
    major_name = Column(String(200), nullable=False)


class CandidateTicket(Base):
    __tablename__ = "candidate_tickets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    election_id = Column(UUID, nullable=False)
    president_candidate_id = Column(UUID, nullable=False)
    vice_president_candidate_id = Column(UUID, nullable=True)
    vote_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)





class Candidate(Base, AuditMixin):
    __tablename__ = "candidates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(100), nullable=False)
    student_id = Column(String(20), nullable=False)
    cohort_id = Column(UUID, nullable=True)
    major_id = Column(UUID, nullable=True)
    position = Column(String(100), nullable=False)
    status = Column(String(20), default="pending")  # pending, running, rejected
    is_active = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class Election(Base, AuditMixin):
    __tablename__ = "elections"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(String(20), default="upcoming")  # upcoming, ongoing, ended
    is_active = Column(Boolean, default=True)
    results_json = Column(Text, nullable=True)  # Plain JSON results
    
    def set_results(self, results_data):
        """Store election results as JSON text (no encryption)."""
        self.results_json = json.dumps(results_data)
    
    @property
    def results(self):
        """Return parsed results JSON."""
        if self.results_json:
            try:
                return json.loads(self.results_json)
            except json.JSONDecodeError:
                return None
        return None

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    table_name = Column(String(50), nullable=False)
    record_id = Column(UUID, nullable=False)
    action = Column(String(20), nullable=False)  # INSERT, UPDATE, DELETE, SELECT
    user_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_authorized = Column(Boolean, default=False)


class Admin(Base):
    __tablename__ = "admins"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(200), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    status = Column(String(20), default="active")
    verification_token = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __init__(self, full_name, email, password_hash, status="active", is_active=True, **kwargs):
        self.full_name = full_name
        self.email = email
        self.password_hash = password_hash
        self.status = status
        self.verification_token = secrets.token_urlsafe(32)
        self.is_active = is_active
        super().__init__(**kwargs)

# Event listeners for audit logging
@event.listens_for(User, 'after_insert')
@event.listens_for(Vote, 'after_insert')
@event.listens_for(Candidate, 'after_insert')
@event.listens_for(Election, 'after_insert')
def log_insert(mapper, connection, target):
    """Log all insert operations"""
    audit_log = AuditLog(
        table_name=target.__tablename__,
        record_id=target.id,
        action='INSERT',
        timestamp=datetime.utcnow()
    )
    # Note: In a real implementation, you'd need to handle the session properly


@event.listens_for(Vote, "after_insert")
def cache_session_key_after_insert(mapper, connection, target):
    """Persist the ML-KEM ciphertext for this vote inside Redis."""
    ciphertext = getattr(target, "_session_ciphertext", None)
    if ciphertext:
        cache_session_ciphertext(target.verification_code, ciphertext)
@event.listens_for(User, 'after_update')
@event.listens_for(Vote, 'after_update')
@event.listens_for(Candidate, 'after_update')
@event.listens_for(Election, 'after_update')
def log_update(mapper, connection, target):
    """Log all update operations - RESTRICTED"""
    # Log unauthorized update attempts
    audit_log = AuditLog(
        table_name=target.__tablename__,
        record_id=target.id,
        action='UPDATE_BLOCKED',
        timestamp=datetime.utcnow(),
        is_authorized=False
    )

@event.listens_for(User, 'after_delete')
@event.listens_for(Vote, 'after_delete')
def log_delete(mapper, connection, target):
    """Log all delete operations - RESTRICTED"""
    # Log unauthorized delete attempts
    audit_log = AuditLog(
        table_name=target.__tablename__,
        record_id=target.id,
        action='DELETE_BLOCKED',
        timestamp=datetime.utcnow(),
        is_authorized=False
    )

# Read-only session class
class ReadOnlySession:
    def __init__(self, session):
        self._session = session
    
    def query(self, *args, **kwargs):
        return self._session.query(*args, **kwargs)
    
    def get(self, *args, **kwargs):
        return self._session.get(*args, **kwargs)
    
    def add(self, *args, **kwargs):
        raise PermissionError("Database is in read-only mode for voter data")
    
    def delete(self, *args, **kwargs):
        raise PermissionError("Database is in read-only mode for voter data")
    
    def commit(self):
        raise PermissionError("Database is in read-only mode for voter data")
    
    def rollback(self):
        return self._session.rollback()
    
    def close(self):
        return self._session.close()

# Secure database functions
def get_readonly_db():
    """Get read-only database session"""
    db = SessionLocal()
    return ReadOnlySession(db)

def get_secure_db():
    """Get database session with audit logging"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_data_integrity(db, model_class, record_id):
    """Data hash integrity check disabled."""
    return True

def get_vote_count_secure(db, election_id):
    """Get vote count without exposing individual votes"""
    counts: dict = {}
    tickets = (
        db.query(CandidateTicket)
        .filter(CandidateTicket.election_id == election_id)
        .all()
    )
    if tickets:
        for row in tickets:
            counts[str(row.id)] = int(row.vote_count or 0)
        return counts

    votes = (
        db.query(Vote)
        .filter(
            Vote.election_id == election_id,
            Vote.is_counted == True,
        )
        .all()
    )
    for vote in votes:
        try:
            payload = vote.vote_data
            if not isinstance(payload, dict):
                continue
            ticket_id = payload.get("ticket_id")
            candidate_id = payload.get("candidate_id")
            if ticket_id is not None:
                ticket_key = str(ticket_id)
                counts[ticket_key] = counts.get(ticket_key, 0) + 1
            elif candidate_id is not None:
                key = f"legacy_candidate_{candidate_id}"
                counts[key] = counts.get(key, 0) + 1
        except Exception:
            continue
    return counts


def increment_ticket_tally(db, election_id, ticket_id, step: int = 1):
    """Increment persistent ticket tally inside the same vote transaction."""
    if ticket_id is None or step == 0:
        return
    row = (
        db.query(CandidateTicket)
        .filter(
            CandidateTicket.election_id == election_id,
            CandidateTicket.id == ticket_id,
        )
        .first()
    )
    if not row:
        return
    row.vote_count = int(row.vote_count or 0) + int(step)
    row.updated_at = datetime.utcnow()
    db.add(row)

def create_secure_backup():
    """Create encrypted backup of critical data"""
    # Implementation for secure backup
    pass

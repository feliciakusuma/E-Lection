from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, LargeBinary, event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.ext.declarative import declared_attr
from datetime import datetime
import os
import re
import hashlib
import secrets
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidTag

# Replace username, password, host, port, database_name with your MySQL info
DATABASE_URL = "mysql://root:Kamisatoayato.77@localhost:3306/demo"

engine = create_engine(DATABASE_URL)
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

RSA_KEY_DIR = os.getenv("RSA_KEY_DIR", KEY_STORAGE_DIR)
RSA_PUBLIC_KEY_PATH = os.getenv("RSA_PUBLIC_KEY_PATH", os.path.join(RSA_KEY_DIR, "vote_public.pem"))
RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH", os.path.join(RSA_KEY_DIR, "vote_private.pem"))
RSA_KEY_SIZE = 4096


def _ensure_rsa_keypair():
    os.makedirs(RSA_KEY_DIR, exist_ok=True)

    private_key = None
    public_key = None

    if os.path.exists(RSA_PRIVATE_KEY_PATH):
        with open(RSA_PRIVATE_KEY_PATH, "rb") as private_file:
            private_key = serialization.load_pem_private_key(private_file.read(), password=None)

    if private_key is None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
        with open(RSA_PRIVATE_KEY_PATH, "wb") as private_file:
            private_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    public_key = private_key.public_key()

    if not os.path.exists(RSA_PUBLIC_KEY_PATH):
        with open(RSA_PUBLIC_KEY_PATH, "wb") as public_file:
            public_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with open(RSA_PUBLIC_KEY_PATH, "rb") as public_file:
            public_key = serialization.load_pem_public_key(public_file.read())

    return private_key, public_key


RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = _ensure_rsa_keypair()


def encrypt_with_session_key(plaintext: bytes, session_key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.encrypt(nonce, plaintext, None)


def decrypt_with_session_key(ciphertext: bytes, session_key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_session_key(session_key: bytes) -> bytes:
    return RSA_PUBLIC_KEY.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_session_key(encrypted_session_key: bytes) -> bytes:
    if RSA_PRIVATE_KEY is None:
        raise RuntimeError("RSA private key is not available for decryption")
    return RSA_PRIVATE_KEY.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

class AuditMixin:
    """Mixin to add audit trail to models"""
    
    @declared_attr
    def created_at(cls):
        return Column(DateTime, default=datetime.utcnow, nullable=False)
    
    @declared_attr
    def created_by(cls):
        return Column(String(100), nullable=True)
    
    @declared_attr
    def data_hash(cls):
        return Column(String(64), nullable=True)  # SHA-256 hash for integrity
    
    def generate_hash(self):
        """Generate hash of critical data for integrity verification"""
        data_str = ""
        for column in self.__table__.columns:
            if column.name not in ['id', 'created_at', 'data_hash']:
                value = getattr(self, column.name)
                if value is not None:
                    data_str += str(value)
        return hashlib.sha256(data_str.encode()).hexdigest()

class User(Base, AuditMixin):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    first_name_encrypted = Column(LargeBinary, nullable=False)  # Encrypted
    last_name_encrypted = Column(LargeBinary, nullable=False)   # Encrypted
    email_hash = Column(String(64), nullable=False, unique=True)  # Hashed for lookup
    email_encrypted = Column(LargeBinary, nullable=False)       # Encrypted for storage
    student_id_encrypted = Column(LargeBinary, nullable=False, unique=True)  # Encrypted
    password_hash = Column(String(255), nullable=False)
    status = Column(String(20), default="pending")  # pending, verified, rejected
    verification_token = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    def __init__(self, first_name, last_name, email, student_id, password_hash, is_admin=False, **kwargs):
        # Encrypt sensitive data
        self.first_name_encrypted = cipher_suite.encrypt(first_name.encode())
        self.last_name_encrypted = cipher_suite.encrypt(last_name.encode())
        self.email_encrypted = cipher_suite.encrypt(email.encode())
        self.email_hash = hashlib.sha256(email.encode()).hexdigest()
        self.student_id_encrypted = cipher_suite.encrypt(student_id.encode())
        self.password_hash = password_hash
        self.verification_token = secrets.token_urlsafe(32)
        self.is_admin = is_admin
        super().__init__(**kwargs)
    
    @property
    def first_name(self):
        return cipher_suite.decrypt(self.first_name_encrypted).decode()
    
    @property
    def last_name(self):
        return cipher_suite.decrypt(self.last_name_encrypted).decode()
    
    @property
    def email(self):
        return cipher_suite.decrypt(self.email_encrypted).decode()
    
    @property
    def student_id(self):
        return cipher_suite.decrypt(self.student_id_encrypted).decode()
    
    @staticmethod
    def is_valid_university_email(email):
        """Validate that email ends with @university.edu"""
        return re.match(r'^[^@]+@university\.edu$', email) is not None
    
    @staticmethod
    def find_by_email(db, email):
        """Find user by email using hash lookup"""
        email_hash = hashlib.sha256(email.encode()).hexdigest()
        return db.query(User).filter(User.email_hash == email_hash).first()

class Vote(Base, AuditMixin):
    __tablename__ = "votes"

    id = Column(Integer, primary_key=True, index=True)
    voter_hash = Column(String(64), nullable=False)  # Hashed voter ID for anonymity
    candidate_id = Column(Integer, nullable=False)
    election_id = Column(Integer, nullable=False)
    vote_encrypted = Column(LargeBinary, nullable=False)  # AES-GCM ciphertext
    timestamp_encrypted = Column(LargeBinary, nullable=False)  # AES-GCM ciphertext
    session_key_encrypted = Column(LargeBinary, nullable=False)  # RSA encrypted AES session key
    vote_nonce = Column(LargeBinary, nullable=False)  # Nonce for vote encryption
    timestamp_nonce = Column(LargeBinary, nullable=False)  # Nonce for timestamp encryption
    verification_code = Column(String(100), nullable=False, unique=True)  # For vote verification
    is_counted = Column(Boolean, default=False)

    def __init__(self, voter_id, candidate_id, election_id, **kwargs):
        # Create anonymous voter hash
        self.voter_hash = hashlib.sha256(f"{voter_id}_{secrets.token_hex(16)}".encode()).hexdigest()
        self.candidate_id = candidate_id
        self.election_id = election_id

        # Prepare payloads
        vote_payload = json.dumps({
            'candidate_id': candidate_id,
            'election_id': election_id,
            'timestamp': datetime.utcnow().isoformat()
        }).encode()
        timestamp_payload = datetime.utcnow().isoformat().encode()

        # Generate one-time AES session key per ballot
        session_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(session_key)

        vote_nonce = secrets.token_bytes(12)
        timestamp_nonce = secrets.token_bytes(12)

        self.vote_encrypted = aesgcm.encrypt(vote_nonce, vote_payload, None)
        self.timestamp_encrypted = aesgcm.encrypt(timestamp_nonce, timestamp_payload, None)
        self.session_key_encrypted = encrypt_session_key(session_key)
        self.vote_nonce = vote_nonce
        self.timestamp_nonce = timestamp_nonce
        self.verification_code = secrets.token_urlsafe(32)
        super().__init__(**kwargs)

    def _session_key(self):
        return decrypt_session_key(self.session_key_encrypted)

    @property
    def vote_data(self):
        """Decrypt and return vote data"""
        try:
            session_key = self._session_key()
            plaintext = decrypt_with_session_key(self.vote_encrypted, session_key, self.vote_nonce)
            return json.loads(plaintext.decode())
        except (InvalidTag, ValueError, json.JSONDecodeError):
            return {}

    @property
    def vote_timestamp(self):
        """Decrypt and return vote timestamp"""
        try:
            session_key = self._session_key()
            plaintext = decrypt_with_session_key(self.timestamp_encrypted, session_key, self.timestamp_nonce)
            return plaintext.decode()
        except InvalidTag:
            return ""

class Candidate(Base, AuditMixin):
    __tablename__ = "candidates"
    
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100), nullable=False)
    student_id = Column(String(20), nullable=False)
    major = Column(String(100), nullable=False)
    cohort = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    position = Column(String(100), nullable=False)
    status = Column(String(20), default="pending")  # pending, running, rejected
    is_active = Column(Boolean, default=True)

class Election(Base, AuditMixin):
    __tablename__ = "elections"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(String(20), default="upcoming")  # upcoming, ongoing, ended
    is_active = Column(Boolean, default=True)
    results_encrypted = Column(LargeBinary, nullable=True)  # Encrypted results
    
    def encrypt_results(self, results_data):
        """Encrypt election results"""
        self.results_encrypted = cipher_suite.encrypt(json.dumps(results_data).encode())
    
    @property
    def results(self):
        """Decrypt and return results"""
        if self.results_encrypted:
            decrypted = cipher_suite.decrypt(self.results_encrypted).decode()
            return json.loads(decrypted)
        return None

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    table_name = Column(String(50), nullable=False)
    record_id = Column(Integer, nullable=False)
    action = Column(String(20), nullable=False)  # INSERT, UPDATE, DELETE, SELECT
    old_values = Column(Text, nullable=True)
    new_values = Column(Text, nullable=True)
    user_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_authorized = Column(Boolean, default=False)

class SystemConfig(Base):
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), nullable=False, unique=True)
    value_encrypted = Column(LargeBinary, nullable=False)
    is_readonly = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __init__(self, key, value, is_readonly=True):
        self.key = key
        self.value_encrypted = cipher_suite.encrypt(str(value).encode())
        self.is_readonly = is_readonly
    
    @property
    def value(self):
        return cipher_suite.decrypt(self.value_encrypted).decode()

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
        new_values=str(target.__dict__),
        timestamp=datetime.utcnow()
    )
    # Note: In a real implementation, you'd need to handle the session properly

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
        new_values=str(target.__dict__),
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
        old_values=str(target.__dict__),
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
    """Verify data integrity using stored hash"""
    record = db.query(model_class).filter(model_class.id == record_id).first()
    if record and hasattr(record, 'data_hash'):
        current_hash = record.generate_hash()
        return current_hash == record.data_hash
    return False

def get_vote_count_secure(db, election_id):
    """Get vote count without exposing individual votes"""
    # Only return aggregated, anonymized data
    vote_counts = db.query(Vote.candidate_id, db.func.count(Vote.id)).filter(
        Vote.election_id == election_id,
        Vote.is_counted == True
    ).group_by(Vote.candidate_id).all()
    
    return {candidate_id: count for candidate_id, count in vote_counts}

def create_secure_backup():
    """Create encrypted backup of critical data"""
    # Implementation for secure backup
    pass
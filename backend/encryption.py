import os, ctypes, json, base64, secrets
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# liboqs intentionally disabled to avoid local install issues.
_OQS_AVAILABLE = False
oqs = None  # type: ignore
DLL_DIR = None

# ------------------------------
# Config / Paths / Constants
# ------------------------------
KEY_STORAGE_DIR = os.getenv("KEY_STORAGE_DIR", os.path.join(os.path.dirname(__file__), "keys"))
MLKEM_PK_PATH   = os.path.join(KEY_STORAGE_DIR, "mlkem768_public.key")
MLKEM_SK_PATH   = os.path.join(KEY_STORAGE_DIR, "mlkem768_secret.key")

# Versioning helps with future migrations (e.g., rotating algorithms)
TOKEN_VERSION   = "hyb-v1"
AAD_PASSWORD    = b"password-aesgcm-v1"   # AAD for password ciphertext
AAD_WRAP        = b"mlkem-wrap-aeskey-v1" # AAD for AES-session-key wrapping
NONCE_LEN       = 12                      # 96-bit nonce for AES-GCM

# ------------------------------
# OQS / ML-KEM helpers (compat across versions)
# ------------------------------
def _oqs_list_kems():
    return []


def _pick_mlkem768_name() -> str:
    raise RuntimeError("liboqs is disabled; ML-KEM operations are unavailable")


ALG = "ML-KEM-768"

def mlkem_keygen() -> Tuple[bytes, bytes]:
    raise RuntimeError("liboqs is disabled; ML-KEM operations are unavailable")

def mlkem_encaps(pk: bytes) -> Tuple[bytes, bytes]:
    raise RuntimeError("liboqs is disabled; ML-KEM operations are unavailable")

def mlkem_decaps(ct: bytes, sk: bytes) -> bytes:
    raise RuntimeError("liboqs is disabled; ML-KEM operations are unavailable")

# ------------------------------
# Utilities
# ------------------------------
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)

def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

# ------------------------------
# ML-KEM key management
# ------------------------------
def load_or_create_mlkem_keys() -> Tuple[bytes, bytes]:
    """
    Loads ML-KEM-768 public/secret keys from disk, or creates and persists them.
    Returns: (pk, sk)
    """
    _ensure_dir(KEY_STORAGE_DIR)
    if os.path.exists(MLKEM_PK_PATH) and os.path.exists(MLKEM_SK_PATH):
        with open(MLKEM_PK_PATH, "rb") as f: pk = f.read()
        with open(MLKEM_SK_PATH, "rb") as f: sk = f.read()
        return pk, sk

    pk, sk = mlkem_keygen()
    with open(MLKEM_PK_PATH, "wb") as f: f.write(pk)
    with open(MLKEM_SK_PATH, "wb") as f: f.write(sk)
    return pk, sk

def load_mlkem_public() -> bytes:
    with open(MLKEM_PK_PATH, "rb") as f:
        return f.read()

def load_mlkem_secret() -> bytes:
    with open(MLKEM_SK_PATH, "rb") as f:
        return f.read()

# ------------------------------
# Hybrid encrypt/decrypt
# ------------------------------
def encrypt_password_hybrid(plaintext: str) -> str:
    """
    Hybrid encrypt:
      1) Generate AES session key (32 bytes) and nonce1. Encrypt password with AES-GCM.
      2) ML-KEM encaps with public key -> (kem_ct, shared_secret).
      3) Derive KEK from shared_secret (HKDF-SHA256).
      4) Wrap AES session key with AES-GCM using KEK (nonce2).
      5) Return JSON token (base64 fields).

    Returns: JSON string (token)
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")

    # Ensure ML-KEM keys exist
    pk, _ = load_or_create_mlkem_keys()

    # 1) AES session key + encrypt password
    aes_sess_key = AESGCM.generate_key(bit_length=256)  # 32 bytes
    gcm1 = AESGCM(aes_sess_key)
    nonce1 = secrets.token_bytes(NONCE_LEN)
    ct1 = gcm1.encrypt(nonce1, plaintext.encode("utf-8"), AAD_PASSWORD)

    # 2) KEM encapsulation -> kem_ct (public), shared_secret (32 bytes typically)
    kem_ct, shared_secret = mlkem_encaps(pk)

    # 3) Derive KEK from shared_secret (salt = kem_ct for binding; info = context)
    kek = _hkdf_sha256(
        ikm=shared_secret,
        salt=kem_ct,                 # binds KEK to this encapsulation
        info=b"KEK:MLKEM768-AESGCM", # context label
        length=32
    )

    # 4) Wrap AES session key with KEK (AES-GCM)
    gcm2 = AESGCM(kek)
    nonce2 = secrets.token_bytes(NONCE_LEN)
    wrapped_key = gcm2.encrypt(nonce2, aes_sess_key, AAD_WRAP)

    # 5) Assemble versioned token
    token: Dict[str, Any] = {
        "v": TOKEN_VERSION,
        "alg": {"kem": "ML-KEM-768", "sym": "AES-256-GCM"},
        "kem_ct": _b64e(kem_ct),
        "nonce1": _b64e(nonce1),
        "ct1": _b64e(ct1),            # AES-GCM(password)
        "nonce2": _b64e(nonce2),
        "wrapped_key": _b64e(wrapped_key),
        "aad1": _b64e(AAD_PASSWORD),
        "aad2": _b64e(AAD_WRAP),
    }
    return json.dumps(token, separators=(",", ":"))

def decrypt_password_hybrid(token_json: str) -> str:
    """
    Reverse of encrypt_password_hybrid:
      - Parse token; decapsulate with secret key.
      - HKDF derive KEK; unwrap AES session key; decrypt password.
    """
    obj = json.loads(token_json)
    if obj.get("v") != TOKEN_VERSION:
        raise ValueError(f"Unsupported token version: {obj.get('v')}")

    kem_ct  = _b64d(obj["kem_ct"])
    nonce1  = _b64d(obj["nonce1"])
    ct1     = _b64d(obj["ct1"])
    nonce2  = _b64d(obj["nonce2"])
    wrapped = _b64d(obj["wrapped_key"])

    aad1 = _b64d(obj["aad1"])
    aad2 = _b64d(obj["aad2"])

    # Load ML-KEM secret key and decapsulate
    sk = load_mlkem_secret()
    shared_secret = mlkem_decaps(kem_ct, sk)

    # Derive KEK identically
    kek = _hkdf_sha256(
        ikm=shared_secret,
        salt=kem_ct,
        info=b"KEK:MLKEM768-AESGCM",
        length=32
    )

    # Unwrap AES session key
    gcm2 = AESGCM(kek)
    aes_sess_key = gcm2.decrypt(nonce2, wrapped, aad2)

    # Decrypt password
    gcm1 = AESGCM(aes_sess_key)
    plaintext = gcm1.decrypt(nonce1, ct1, aad1)
    return plaintext.decode("utf-8")

# ------------------------------
# Demo
# ------------------------------
if __name__ == "__main__":
    _ = load_or_create_mlkem_keys()  # ensure keys exist

    sample = "AdminPass123!"
    token = encrypt_password_hybrid(sample)
    recovered = decrypt_password_hybrid(token)
    assert recovered == sample, "Hybrid round-trip failed"
    print("Hybrid ML-KEM + AES-GCM OK ✅")

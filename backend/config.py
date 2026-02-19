import os
from pathlib import Path

# Application-level configuration and environment-backed defaults.

DEV_OPEN_ADMIN = os.getenv("DEV_OPEN_ADMIN", "false").lower() == "true"

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_FIRST_NAME = os.getenv("ADMIN_FIRST_NAME", "Admin")
ADMIN_LAST_NAME = os.getenv("ADMIN_LAST_NAME", "User")
ADMIN_STUDENT_ID = os.getenv("ADMIN_STUDENT_ID", "2023000000")
ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME") or f"{ADMIN_FIRST_NAME} {ADMIN_LAST_NAME}".strip()

DEFAULT_ACCOUNTS = []
if ADMIN_EMAIL and ADMIN_PASSWORD:
    DEFAULT_ACCOUNTS.append(
        {
            "first_name": ADMIN_FIRST_NAME,
            "last_name": ADMIN_LAST_NAME,
            "email": ADMIN_EMAIL,
            "student_id": ADMIN_STUDENT_ID,
        }
    )

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "security.log"

# Session + cookie security settings
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "SUPER_SECRET_KEY")
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "session")
SESSION_MAX_AGE_SECONDS = int(os.getenv("SESSION_MAX_AGE_SECONDS", "14400"))
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")

# Microsoft OAuth (set env vars MS_CLIENT_ID / MS_CLIENT_SECRET to enable)
MS_TENANT_ID = os.getenv("MS_TENANT_ID", " ")
MS_CLIENT_ID = os.getenv("MS_CLIENT_ID", " ")
MS_CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET", " ")
MS_REDIRECT_URI = os.getenv(
    "MS_REDIRECT_URI",
    " ",
)

# Email (verification)
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "election.noreply@gmail.com")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", EMAIL_SENDER)
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")

# Crypto mode for vote session-key wrapping.
# Set ENABLE_MLKEM=false in constrained runtimes (e.g., Replit) to avoid liboqs dependency.
ENABLE_MLKEM = os.getenv("ENABLE_MLKEM", "true").lower() == "true"

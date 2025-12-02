import os
from pathlib import Path

# Application-level configuration and environment-backed defaults.

DEV_OPEN_ADMIN = os.getenv("DEV_OPEN_ADMIN", "false").lower() == "true"

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_FIRST_NAME = os.getenv("ADMIN_FIRST_NAME", "Admin")
ADMIN_LAST_NAME = os.getenv("ADMIN_LAST_NAME", "User")
ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME") or f"{ADMIN_FIRST_NAME} {ADMIN_LAST_NAME}".strip()
ADMIN_STUDENT_ID = os.getenv("ADMIN_STUDENT_ID", "ADMIN001")

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

# Google OAuth (set env vars GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET to enable)
GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID",
    "963693618176-vc0vrg0varbkd0l8t1m0oddrninh3o5e.apps.googleusercontent.com",
)
GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET",
    "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",
)
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/authorize")

# Email (verification)
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "election.noreply@gmail.com")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", EMAIL_SENDER)
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD","miud xzce erzg pcca")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

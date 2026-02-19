import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from ..config import LOG_FILE_PATH
from ..database import AuditLog

# Configure logging for security events (one-time setup on import).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

security_logger = logging.getLogger("security")


def _truncate(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text[:max_len]


def log_security_event(
    event_type: str, details: str, ip_address: Optional[str] = None, user_id: Optional[str] = None
) -> None:
    security_logger.warning(
        "SECURITY EVENT: %s - %s - IP: %s - User: %s", event_type, details, ip_address, user_id
    )


def create_audit_log(
    db,
    table_name: str,
    record_id: int,
    action: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
):
    """Create audit log entry."""
    audit_entry = AuditLog(
        table_name=_truncate(table_name, 50) or "unknown",
        record_id=record_id,
        action=_truncate(action, 20) or "UNKNOWN",
        user_id=_truncate(user_id, 100),
        ip_address=_truncate(ip_address, 45),
        user_agent=_truncate(user_agent, 500),
        timestamp=datetime.utcnow(),
        is_authorized=True,
    )
    try:
        db.add(audit_entry)
        db.commit()
    except Exception as exc:
        db.rollback()
        security_logger.warning("Failed to write audit log: %s", exc)

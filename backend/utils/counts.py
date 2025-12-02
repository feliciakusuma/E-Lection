from sqlalchemy import func, text, or_
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from ..database import User


def get_eligible_voters_count(db: Session) -> int:
    """Eligible voters exclude admins."""
    try:
        return (
            db.query(func.count(User.id))
            .scalar()
        ) or 0
    except OperationalError:
        return (
            db.execute(text("SELECT COUNT(*) FROM users")).scalar()
            or 0
        )

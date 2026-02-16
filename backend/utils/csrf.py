import secrets
from fastapi import Request, HTTPException, status

TOKEN_KEY = "csrf_token"
FORM_FIELD = "csrf_token"
HEADER_NAME = "x-csrf-token"


def get_or_create_csrf_token(request: Request) -> str:
    """Return the session CSRF token, creating one if missing."""
    token = request.session.get(TOKEN_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[TOKEN_KEY] = token
    return token


def validate_csrf(request: Request, token: str | None) -> None:
    """Validate a CSRF token from form field or header."""
    session_token = request.session.get(TOKEN_KEY)
    header_token = request.headers.get(HEADER_NAME)
    provided = token or header_token
    if not session_token or not provided or not secrets.compare_digest(session_token, provided):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")

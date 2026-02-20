from __future__ import annotations

from typing import Mapping

from itsdangerous import BadSignature, URLSafeSerializer

from ..config import COOKIE_SAMESITE, SESSION_MAX_AGE_SECONDS, SESSION_SECRET_KEY

DEFAULT_COOKIE_KWARGS = {
    "httponly": True,
    "secure": True,
    "samesite": COOKIE_SAMESITE,
    "path": "/",
    "max_age": SESSION_MAX_AGE_SECONDS,
}


def set_secure_cookie(response, key: str, value: str, **overrides) -> None:
    """Set a secure, HTTP-only cookie with sane defaults."""
    kwargs = {**DEFAULT_COOKIE_KWARGS, **overrides}
    response.set_cookie(key, value, **kwargs)


def set_secure_cookies(response, values: Mapping[str, str], **overrides) -> None:
    """Set multiple secure cookies on the response."""
    for key, value in values.items():
        set_secure_cookie(response, key, value, **overrides)


def delete_secure_cookie(response, key: str) -> None:
    """Delete a cookie using the same path/samesite defaults."""
    response.delete_cookie(key, path="/")


_SIGNED_COOKIE_SALT = "election:signed-cookie:v1"
_signed_serializer = URLSafeSerializer(SESSION_SECRET_KEY, salt=_SIGNED_COOKIE_SALT)


def get_signed_cookie(request, key: str, default=None):
    """Read and verify a signed cookie value."""
    raw = request.cookies.get(key)
    if not raw:
        return default
    try:
        return _signed_serializer.loads(raw)
    except BadSignature:
        return default


def set_signed_cookie(response, key: str, value, **overrides) -> None:
    """Set a signed cookie value with secure defaults."""
    payload = _signed_serializer.dumps(value)
    set_secure_cookie(response, key, payload, **overrides)

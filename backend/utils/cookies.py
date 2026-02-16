from __future__ import annotations

from typing import Mapping

from ..config import COOKIE_SAMESITE, SESSION_MAX_AGE_SECONDS

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

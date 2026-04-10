import os
from urllib.parse import urlparse
from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from .database import SessionLocal
from .utils.csrf import get_or_create_csrf_token

# Shared template setup and static mounting helper.
templates = Jinja2Templates(directory="src")

# Defensive wrapper: swap args if TemplateResponse is called with context first.
_template_response = templates.TemplateResponse


def _safe_template_response(name, context=None, **kwargs):
    if isinstance(name, dict) and isinstance(context, str):
        name, context = context, name
    return _template_response(name=name, context=context, **kwargs)


templates.TemplateResponse = _safe_template_response


def asset(request: Request, path: str) -> str:
    """Cache-busting helper for static assets."""
    full = os.path.join("static", path)
    ver = int(os.path.getmtime(full)) if os.path.exists(full) else 0
    return f"{request.url_for('static', path=path)}?v={ver}"


def csrf_token(request: Request) -> str:
    """Expose a CSRF token for templates."""
    return get_or_create_csrf_token(request)


def csp_nonce(request: Request) -> str:
    """Expose CSP nonce for templates."""
    return getattr(request.state, "csp_nonce", "")


def safe_url(value: str | None, fallback: str = "") -> str:
    """Allow only http(s) URLs; otherwise return a safe fallback."""
    if not value:
        return fallback
    try:
        parsed = urlparse(value)
    except Exception:
        return fallback
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    return fallback


# Jinja filters
templates.env.filters["safe_url"] = safe_url


def get_db():
    """Yield a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

import os
from urllib.parse import urlparse
from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from .database import SessionLocal
from .utils.csrf import get_or_create_csrf_token

# Shared template setup and static mounting helper.
templates = Jinja2Templates(directory="src")


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

# Compatibility wrapper for TemplateResponse across Starlette/FastAPI versions.
_template_response = templates.TemplateResponse


def _safe_template_response(*args, **kwargs):
    if args:
        # Newer/older signatures: (request, name, context) or (name, context).
        if len(args) >= 3 and isinstance(args[0], Request):
            return _template_response(*args, **kwargs)
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            ctx = args[1]
            req = ctx.get("request") if isinstance(ctx, dict) else None
            if req is not None:
                return _template_response(req, args[0], ctx, *args[2:], **kwargs)
    if "name" in kwargs and "context" in kwargs:
        ctx = kwargs.get("context")
        req = ctx.get("request") if isinstance(ctx, dict) else None
        if req is not None:
            extra = {k: v for k, v in kwargs.items() if k not in ("name", "context")}
            return _template_response(req, kwargs["name"], ctx, **extra)
    return _template_response(*args, **kwargs)


templates.TemplateResponse = _safe_template_response


def get_db():
    """Yield a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

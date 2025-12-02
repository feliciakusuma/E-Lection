import os
from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from .database import SessionLocal

# Shared template setup and static mounting helper.
templates = Jinja2Templates(directory="src")


def asset(request: Request, path: str) -> str:
    """Cache-busting helper for static assets."""
    full = os.path.join("static", path)
    ver = int(os.path.getmtime(full)) if os.path.exists(full) else 0
    return f"{request.url_for('static', path=path)}?v={ver}"


def get_db():
    """Yield a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from backend.database import Base, engine, SessionLocal, User, Admin
from backend.config import (
    SESSION_SECRET_KEY,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    COOKIE_SAMESITE,
)
from backend.dependencies import asset, templates, csrf_token, csp_nonce
from backend.routers import admins, auth, candidates, elections, users, votes
from backend.services import seed
from backend.services.audit import security_logger
import os
import uvicorn
import secrets
from fastapi import Response
from starlette.status import HTTP_204_NO_CONTENT

SECURITY_CSP_TEMPLATE = "; ".join([
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data: https://upload.wikimedia.org https://cdn-icons-png.flaticon.com",
    "font-src 'self' data:",
    "style-src 'self'",
    "script-src 'self' 'nonce-{nonce}'",
    "connect-src 'self'",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "report-to csp-endpoint",
])
SECURITY_HEADERS = {
    "x-frame-options": "DENY",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
}
REPORT_TO_HEADER = (
    '{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://localhost:8000/csp-report"}],"include_subdomains":true}'
)
REPORTING_ENDPOINTS_HEADER = 'csp-endpoint="https://localhost:8000/csp-report"'


class SecurityHeadersMiddleware:

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        nonce = secrets.token_urlsafe(16)
        scope.setdefault("state", {})
        scope["state"]["csp_nonce"] = nonce
        csp_value = SECURITY_CSP_TEMPLATE.format(nonce=nonce)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                # Remove any existing CSP header so we always enforce the current policy.
                headers = [(k, v) for (k, v) in headers
                           if k.lower() != b"content-security-policy"]
                existing = {k.lower() for k, _ in headers}
                csp_key = b"content-security-policy"
                headers.append((csp_key, csp_value.encode("latin-1")))
                for name, value in SECURITY_HEADERS.items():
                    key = name.encode("latin-1")
                    if key not in existing:
                        headers.append((key, value.encode("latin-1")))
                if b"report-to" not in existing:
                    headers.append(
                        (b"report-to", REPORT_TO_HEADER.encode("latin-1")))
                if b"reporting-endpoints" not in existing:
                    headers.append(
                        (b"reporting-endpoints",
                         REPORTING_ENDPOINTS_HEADER.encode("latin-1")))
                if b"cache-control" not in existing:
                    if path.startswith("/static"):
                        headers.append(
                            (b"cache-control",
                             b"public, max-age=31536000, immutable"))
                    else:
                        headers.append(
                            (b"cache-control",
                             b"no-store, no-cache, must-revalidate"))
                        if b"pragma" not in existing:
                            headers.append((b"pragma", b"no-cache"))
                        if b"expires" not in existing:
                            headers.append((b"expires", b"0"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    https_only=True,
    session_cookie=SESSION_COOKIE_NAME,
    max_age=SESSION_MAX_AGE_SECONDS,
    same_site=COOKIE_SAMESITE,
)


def apply_security_headers(response):
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    return response


# Static files and templates
app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates.env.globals["asset"] = asset
templates.env.globals["csrf_token"] = csrf_token
templates.env.globals["csp_nonce"] = csp_nonce


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    security_logger.info("Request: %s %s from %s", request.method, request.url,
                         request.client.host)

    path = request.url.path
    public_paths = {
        "/",
        "/login",
        "/register",
        "/verify-code",
        "/resend-code",
        "/health",
        "/login/microsoft",
        "/auth/microsoft/callback",
        "/admin",
    }
    public_prefixes = ("/static", "/favicon")

    def is_public(p: str) -> bool:
        if p in public_paths or p.startswith("/verify/"):
            return True
        return any(p.startswith(pref) for pref in public_prefixes)

    admin_exact_paths = {"/add-election"}
    admin_prefixes = ("/edit-election", "/delete-election")
    is_admin_path = ((path.startswith("/admin") and path not in {"/admin"})
                     or path in admin_exact_paths
                     or path.startswith(admin_prefixes))

    if is_admin_path:
        email_cookie = request.cookies.get("user_email")
        db = SessionLocal()
        try:
            if not email_cookie:
                return apply_security_headers(
                    RedirectResponse(url="/admin", status_code=302))
            admin_row = db.query(Admin).filter(
                Admin.email == email_cookie, Admin.is_active == True).first()
            if not admin_row:
                return apply_security_headers(
                    RedirectResponse(url="/admin", status_code=302))
        finally:
            db.close()
    elif not is_public(path):
        email_cookie = request.cookies.get("user_email")
        db = SessionLocal()
        try:
            if email_cookie:
                user = User.find_by_email(db, email_cookie)
                if not user:
                    return apply_security_headers(
                        RedirectResponse(url="/login", status_code=302))
                if not user.is_active or user.status != "verified":
                    return apply_security_headers(
                        RedirectResponse(url="/login", status_code=302))
            else:
                return apply_security_headers(
                    RedirectResponse(url="/login", status_code=302))
        finally:
            db.close()

    response = await call_next(request)
    return apply_security_headers(response)


@app.on_event("startup")
async def startup():
    seed.ensure_core_schema()
    Base.metadata.create_all(bind=engine)
    seed.seed_cohorts_and_majors()
    seed.ensure_admins_table_and_account()


# Routers
app.include_router(auth.router)
app.include_router(elections.router)
app.include_router(candidates.router)
app.include_router(votes.router)
app.include_router(admins.router)
app.include_router(users.router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "security_mode": "enabled",
        "encryption": "active",
        "audit_logging": "enabled",
        "admin_access": "enabled",
    }


@app.post("/csp-report")
async def csp_report(request: Request):
    try:
        payload = await request.json()
        security_logger.warning("CSP_REPORT: %s", payload)
    except Exception:
        pass
    return Response(status_code=HTTP_204_NO_CONTENT)


if __name__ == "__main__":
    uvicorn.run("main:app",
                host="0.0.0.0",
                port=int(os.getenv("PORT", "5000")))

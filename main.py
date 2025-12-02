from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from backend.database import Base, engine, SessionLocal, User, Admin
from backend.dependencies import asset, templates
from backend.routers import admins, auth, candidates, elections, users, votes
from backend.services import seed
from backend.services.audit import security_logger
import uvicorn

app = FastAPI()

# Static files and templates
app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates.env.globals["asset"] = asset


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    security_logger.info("Request: %s %s from %s", request.method, request.url, request.client.host)

    path = request.url.path
    public_paths = {"/", "/login", "/register", "/health", "/login/google", "/auth/google/callback", "/authorize", "/admin"}
    public_prefixes = ("/static", "/favicon")

    def is_public(p: str) -> bool:
        if p in public_paths:
            return True
        return any(p.startswith(pref) for pref in public_prefixes)

    is_admin_path = path.startswith("/admin") and path not in {"/admin"}

    if is_admin_path:
        email_cookie = request.cookies.get("user_email")
        db = SessionLocal()
        try:
            if not email_cookie:
                return RedirectResponse(url="/admin", status_code=302)
            admin_row = db.query(Admin).filter(Admin.email == email_cookie, Admin.is_active == True).first()
            if not admin_row:
                return RedirectResponse(url="/admin", status_code=302)
        finally:
            db.close()
    elif not is_public(path):
        email_cookie = request.cookies.get("user_email")
        db = SessionLocal()
        try:
            if email_cookie:
                user = User.find_by_email(db, email_cookie)
                if not user:
                    return RedirectResponse(url="/login", status_code=302)
            else:
                return RedirectResponse(url="/login", status_code=302)
        finally:
            db.close()

    response = await call_next(request)
    return response


@app.on_event("startup")
def startup():
    seed.ensure_core_schema()
    Base.metadata.create_all(bind=engine)
    seed.seed_default_accounts()
    seed.seed_cohorts_and_majors()
    seed.ensure_support_admin()
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


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

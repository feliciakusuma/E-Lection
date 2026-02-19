import base64
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
import secrets
import requests
import smtplib
from email.message import EmailMessage
from jose import jwt

from ..config import (
    DEV_OPEN_ADMIN,
    MS_CLIENT_ID,
    MS_CLIENT_SECRET,
    MS_REDIRECT_URI,
    MS_TENANT_ID,
    EMAIL_SENDER,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_USE_TLS,
    RESEND_API_KEY,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH_TOKEN,
    GMAIL_API_USER,
)
from ..dependencies import get_db, templates
from ..database import User, Candidate, Election, Admin, Cohort, Major
from ..services.audit import create_audit_log, log_security_event, security_logger
from ..services.security import get_password_hash, verify_password
from ..utils.validation import MAJOR_CODE_MAP, SUPPORTED_COHORTS, is_valid_email_address
from ..utils.csrf import validate_csrf
from ..utils.cookies import set_secure_cookie, set_secure_cookies, delete_secure_cookie

router = APIRouter()

# Microsoft login is enabled only if both client ID and secret are present
MS_LOGIN_ENABLED = bool(MS_CLIENT_ID and MS_CLIENT_SECRET)
ALLOWED_EMAIL_DOMAIN = "@my.sampoernauniversity.ac.id"


def is_allowed_domain(email: str | None) -> bool:
    if not email:
        return False
    return email.strip().lower().endswith(ALLOWED_EMAIL_DOMAIN)


def parse_email_change_token(token: str | None):
    """Return (code, pending_email) if token is for email change, else (None, None)."""
    if not token:
        return None, None
    if token.startswith("change:"):
        parts = token.split(":", 2)
        if len(parts) == 3:
            return parts[1], parts[2]
    return None, None


def find_user_by_pending_email(db: Session, email: str | None):
    """Locate a user who is changing to the given email."""
    if not email:
        return None, None, None
    target = email.strip().lower()
    try:
        for candidate in db.query(User).all():
            code, pending_email = parse_email_change_token(getattr(candidate, "verification_token", None))
            if pending_email and pending_email.strip().lower() == target:
                return candidate, code, pending_email
    except Exception:
        pass
    return None, None, None


@router.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    msg = None
    qp = request.query_params
    if "verified" in qp:
        msg = "Email verified. You can sign in."
    elif "check_email" in qp:
        msg = "Check your email for the verification link to activate your account."
    err = qp.get("error")
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "ms_enabled": MS_LOGIN_ENABLED,
            "success": msg,
            "error": err,
        },
    )


def send_verification_email(to_email: str, first_name: str, last_name: str, code: str):
    """Send a verification code email via Gmail API, then Resend, then SMTP."""

    msg = EmailMessage()
    msg["From"] = EMAIL_SENDER
    msg["To"] = to_email
    msg["Subject"] = f"[{code}] Verification Code for your E-Lection Account"
    plain_body = (
        f"Hi {first_name} {last_name},\n\n"
        "Thank you for registering with E-Lection.\n"
        "To complete your registration and activate your account, we’ve generated a verification code.\n\n"
        f"Verification code: {code}\n\n"
        "Please enter this code on the E-Lection verification page to confirm your email address and complete your registration.\n\n"
        "Important:\n"
        "• This code will expire in 5 minutes.\n"
        "• Do not share this code with anyone. E-Lection will never ask you for this code.\n\n"
        "If you did not request this registration, you can safely ignore this email and no account will be created.\n\n"
        "Best regards,\n"
        "E-Lection Team\n\n"
        "(This is an automated message. Please do not reply to this email.)"
    )
    html_body = (
        f"<p>Hi {first_name} {last_name},</p>"
        f"<p>Thank you for registering with E-Lection.<br>"
        f"To complete your registration and activate your account, we’ve generated a verification code.</p>"
        f"<p>Verification code: <strong>{code}</strong></p>"
        "<p>Please enter this code on the E-Lection verification page to confirm your email address and complete your registration.</p>"
        "<p><strong>Important:</strong><br>"
        "• This code will expire in 5 minutes.<br>"
        "• Do not share this code with anyone. E-Lection will never ask you for this code.</p>"
        "<p>If you did not request this registration, you can safely ignore this email and no account will be created.</p>"
        "<p>Best regards,<br>E-Lection Team</p>"
        "<p><em>This is an automated message. Please do not reply to this email.</em></p>"
    )
    msg.set_content(plain_body)
    msg.add_alternative(html_body, subtype="html")

    errors: list[str] = []

    # Prefer Gmail API (HTTPS + OAuth refresh token).
    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN:
        try:
            token_resp = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "refresh_token": GOOGLE_REFRESH_TOKEN,
                    "grant_type": "refresh_token",
                },
                timeout=10,
            )
            if not (200 <= token_resp.status_code < 300):
                raise RuntimeError(f"Token exchange failed: {token_resp.status_code} {token_resp.text}")

            access_token = token_resp.json().get("access_token")
            if not access_token:
                raise RuntimeError("Token exchange succeeded but access_token is missing")

            raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
            gmail_resp = requests.post(
                f"https://gmail.googleapis.com/gmail/v1/users/{GMAIL_API_USER}/messages/send",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json={"raw": raw_message},
                timeout=10,
            )
            if not (200 <= gmail_resp.status_code < 300):
                raise RuntimeError(f"Gmail API send failed: {gmail_resp.status_code} {gmail_resp.text}")
            return
        except Exception as exc:
            errors.append(str(exc))

    if RESEND_API_KEY:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": EMAIL_SENDER,
                "to": [to_email],
                "subject": msg["Subject"],
                "html": html_body,
                "text": plain_body,
            },
            timeout=10,
        )
        if 200 <= resp.status_code < 300:
            return
        errors.append(f"Resend API error: {resp.status_code} {resp.text}")

    if SMTP_HOST and SMTP_PORT and SMTP_USERNAME and SMTP_PASSWORD and EMAIL_SENDER:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        try:
            if SMTP_USE_TLS:
                server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            return
        except Exception as exc:
            errors.append(f"SMTP send failed: {exc}")
        finally:
            server.quit()

    if not errors:
        raise RuntimeError(
            "Email provider not configured (set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REFRESH_TOKEN, "
            "or RESEND_API_KEY, or SMTP config)."
        )
    raise RuntimeError("All email providers failed: " + " | ".join(errors))

def fetch_ms_jwks(tenant_id: str) -> dict:
    jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    resp = requests.get(jwks_url, timeout=10)
    resp.raise_for_status()
    return resp.json()


def verify_ms_id_token(id_token_value: str) -> dict:
    unverified_header = jwt.get_unverified_header(id_token_value)
    unverified_claims = jwt.get_unverified_claims(id_token_value)

    issuer_tenant = unverified_claims.get("tid") or MS_TENANT_ID
    if not issuer_tenant:
        raise ValueError("Missing tenant id in token")

    jwks = fetch_ms_jwks(issuer_tenant)
    keys = jwks.get("keys", [])
    key = next((k for k in keys if k.get("kid") == unverified_header.get("kid")), None)
    if not key:
        raise ValueError("Unable to find matching JWK for token")

    issuer = f"https://login.microsoftonline.com/{issuer_tenant}/v2.0"
    return jwt.decode(
        id_token_value,
        key,
        algorithms=["RS256"],
        audience=MS_CLIENT_ID,
        issuer=issuer,
    )


@router.get("/login/microsoft")
def login_microsoft(request: Request):
    """Start Microsoft OAuth 2.0 login."""
    if not MS_LOGIN_ENABLED:
        return RedirectResponse(
            url="/login?error=Microsoft+login+is+disabled",
            status_code=302
        )

    # CSRF protection state token
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": MS_CLIENT_ID,
        "redirect_uri": MS_REDIRECT_URI,
        "response_type": "code",
        "response_mode": "query",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    tenant = MS_TENANT_ID or "common"
    auth_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"

    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie(
        "oauth_state",
        state,
        max_age=600,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/auth/microsoft/callback")
def microsoft_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    """Handle Microsoft OAuth callback and issue application session."""
    if not MS_LOGIN_ENABLED:
        return RedirectResponse(
            url="/login?error=Microsoft+login+is+disabled",
            status_code=302
        )

    # Validate state (CSRF protection)
    expected_state = request.cookies.get("oauth_state")
    if not state or not expected_state or state != expected_state:
        return RedirectResponse(
            url="/login?error=Invalid+login+state",
            status_code=302
        )

    if not code:
        return RedirectResponse(
            url="/login?error=Missing+authorization+code",
            status_code=302
        )

    try:
        # Exchange authorization code for tokens
        tenant = MS_TENANT_ID or "common"
        token_resp = requests.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "code": code,
                "client_id": MS_CLIENT_ID,
                "client_secret": MS_CLIENT_SECRET,
                "redirect_uri": MS_REDIRECT_URI,
                "grant_type": "authorization_code",
                "scope": "openid email profile",
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        # Verify ID token
        id_token_value = token_data.get("id_token")
        if not id_token_value:
            raise ValueError("Missing id_token from Microsoft response")

        id_info = verify_ms_id_token(id_token_value)

        email = id_info.get("email") or id_info.get("preferred_username") or id_info.get("upn")
        if not email:
            log_security_event(
                "LOGIN_MICROSOFT_BLOCKED",
                "Microsoft account email missing",
                request.client.host,
            )
            return RedirectResponse(
                url="/login?error=Microsoft+account+email+missing",
                status_code=302,
            )

        if not is_allowed_domain(email):
            log_security_event(
                "LOGIN_MICROSOFT_BLOCKED",
                f"Microsoft email not allowed: {email}",
                request.client.host,
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Please use your Sampoerna University email.",
                    "ms_enabled": MS_LOGIN_ENABLED,
                },
            )

        # Look up local user linked to this email
        user = User.find_by_email(db, email)
        if not user:
            log_security_event(
                "LOGIN_MICROSOFT_BLOCKED",
                f"Microsoft account not linked: {email}",
                request.client.host,
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "No account exists for this Microsoft email. Please register first.",
                    "ms_enabled": MS_LOGIN_ENABLED,
                },
            )

        if not user.is_active:
            log_security_event(
                "LOGIN_MICROSOFT_BLOCKED",
                f"Inactive Microsoft user: {email}",
                request.client.host,
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Account inactive. Contact an administrator.",
                    "ms_enabled": MS_LOGIN_ENABLED,
                },
            )

        # Mark verified if needed
        if user.status != "verified":
            user.status = "verified"
        db.commit()

        try:
            # Keep action <= 20 chars for older DB schemas.
            create_audit_log(
                db,
                "users",
                user.id,
                "MS_LOGIN_SUCCESS",
                user_id=str(user.id),
                ip_address=request.client.host,
            )
        except Exception as audit_exc:
            security_logger.warning("Audit write failed on Microsoft login: %s", audit_exc)

        response = RedirectResponse(url="/dashboard", status_code=302)
        response.delete_cookie("oauth_state", path="/")
        try:
            set_secure_cookies(
                response,
                {
                    "user_email": user.email or "",
                    "first_name": user.first_name or "",
                    "last_name": user.last_name or "",
                },
            )
        except Exception:
            # Cookie failure shouldn't break login entirely
            pass

        return response

    except Exception as exc:
        db.rollback()
        log_security_event(
            "LOGIN_MICROSOFT_ERROR",
            f"Microsoft login failed: {exc}",
            request.client.host,
        )
        return RedirectResponse(
            url="/login?error=Microsoft+login+failed",
            status_code=302,
        )


@router.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    client_ip = request.client.host
    base_ctx = {"request": request, "ms_enabled": MS_LOGIN_ENABLED}
    email = (email or "").strip().lower()

    try:
        # Password login disabled; require Microsoft OAuth
        return templates.TemplateResponse(
            "login.html",
            {
                **base_ctx,
                "error": "Password login disabled. Use Microsoft Sign-In.",
                "form_data": {"email": email},
            },
        )
    except Exception as exc:
        log_security_event(
            "LOGIN_ERROR",
            f"Login error for {email}: {exc}",
            client_ip,
        )
        return templates.TemplateResponse(
            "login.html",
            {
                **base_ctx,
                "error": "Email not found or not registered",
                "form_data": {"email": email},
            },
        )


@router.get("/admin", response_class=HTMLResponse)
def admin_login_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})


@router.post("/admin")
def admin_login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    client_ip = request.client.host
    email = (email or "").strip().lower()
    form_data = {"email": email}

    if DEV_OPEN_ADMIN:
        return RedirectResponse(url="/admin-dashboard", status_code=302)

    try:
        if not is_valid_email_address(email):
            return templates.TemplateResponse(
                "admin.html",
                {
                    "request": request,
                    "error": "Email address is invalid",
                    "form_data": form_data,
                },
            )

        if not password:
            return templates.TemplateResponse(
                "admin.html",
                {
                    "request": request,
                    "error": "Password is required",
                    "form_data": form_data,
                },
            )

        admin_row = (
            db.query(Admin)
            .filter(Admin.email == email, Admin.is_active == True)
            .first()
        )
        if admin_row and verify_password(password, admin_row.password_hash):
            create_audit_log(
                db,
                "admins",
                admin_row.id,
                "ADMIN_LOGIN_SUCCESS",
                user_id=str(admin_row.id),
                ip_address=client_ip,
            )
            response = RedirectResponse(url="/admin-dashboard", status_code=302)
            try:
                set_secure_cookie(response, "user_email", admin_row.email or "")
                # Derive display name from admin full_name or linked user record
                full_name = (admin_row.full_name or "").strip()
                if not full_name:
                    linked_user = User.find_by_email(db, admin_row.email)
                    if linked_user:
                        full_name = f"{linked_user.first_name or ''} {linked_user.last_name or ''}".strip() or linked_user.email
                parts = full_name.split(" ", 1)
                first = parts[0] if parts else ""
                last = parts[1] if len(parts) > 1 else ""
                set_secure_cookies(
                    response,
                    {
                        "full_name": full_name or "",
                        "first_name": first,
                        "last_name": last,
                    },
                )
            except Exception:
                pass
            return response

        log_security_event(
            "ADMIN_LOGIN_FAILED",
            f"Invalid admin credentials for: {email}",
            client_ip,
        )
        return templates.TemplateResponse(
            "admin.html",
            {
                "request": request,
                "error": "Invalid admin credentials",
                "form_data": form_data,
            },
        )

    except Exception as exc:
        log_security_event(
            "ADMIN_LOGIN_ERROR",
            f"Admin login error for {email}: {exc}",
            client_ip,
        )
        return templates.TemplateResponse(
            "admin.html",
            {
                "request": request,
                "error": "Invalid admin credentials",
                "form_data": form_data,
            },
        )


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@router.get("/logout")
def user_logout():
    """Logout regular users and send them to /login."""
    response = RedirectResponse(url="/login", status_code=302)
    for ck in ["user_email", "first_name", "last_name", "full_name", "avatar_url", "oauth_state"]:
        delete_secure_cookie(response, ck)
    return response


@router.get("/admin-logout")
def admin_logout():
    """Logout admins and send them to /admin."""
    response = RedirectResponse(url="/admin", status_code=302)
    for ck in ["user_email", "first_name", "last_name", "full_name", "avatar_url", "oauth_state"]:
        delete_secure_cookie(response, ck)
    return response


@router.get("/verify-code", response_class=HTMLResponse)
def verify_code_page(request: Request, email: str | None = None, changing: int | None = None):
    success_msg = None
    if request.query_params.get("changing"):
        success_msg = "We sent a verification code to your new email. Confirm it to finish updating your account."
    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "email": email or "",
            "success": success_msg,
        },
    )


@router.post("/verify-code")
def verify_code_submit(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    code = (code or "").strip()
    user = db.query(User).filter(User.email == email).first()
    pending_code = None
    pending_email = None
    pending_mode = False

    if not user:
        user, pending_code, pending_email = find_user_by_pending_email(db, email)
        pending_mode = user is not None
    else:
        pending_code, pending_email = parse_email_change_token(getattr(user, "verification_token", None))
        pending_mode = bool(pending_email)

    if not user:
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "Account not found. Please register again.",
                "email": email,
            },
        )

    if pending_mode and pending_email and pending_email.strip().lower() != email.strip().lower():
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "This code is tied to a different email. Please use the latest verification link.",
                "email": email,
            },
        )

    expected_code = pending_code if pending_mode else (user.verification_token or "")
    if not code or code.strip() != expected_code:
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "Invalid or expired verification code.",
                "email": email,
            },
        )

    try:
        if pending_mode and pending_email:
            user.email = pending_email
            user.verification_token = None
        else:
            user.status = "verified"
            user.is_active = True
        db.commit()
        if pending_mode:
            response = RedirectResponse(url="/profile?email_updated=1", status_code=302)
            try:
                set_secure_cookies(
                    response,
                    {
                        "user_email": user.email or "",
                        "first_name": user.first_name or "",
                        "last_name": user.last_name or "",
                        "full_name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                    },
                )
            except Exception:
                pass
            return response
        return RedirectResponse(url="/login?verified=1", status_code=302)
    except Exception:
        db.rollback()
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "Verification failed. Please try again.",
                "email": email,
            },
        )


@router.post("/resend-code")
def resend_code(
    request: Request,
    email: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = db.query(User).filter(User.email == email).first()
    pending_code = None
    pending_email = None
    pending_mode = False

    if not user:
        user, pending_code, pending_email = find_user_by_pending_email(db, email)
        pending_mode = user is not None
    else:
        pending_code, pending_email = parse_email_change_token(getattr(user, "verification_token", None))
        pending_mode = bool(pending_email)

    if not user:
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "Account not found. Please register again.",
                "email": email,
            },
        )

    # Generate and set a new code
    new_code = f"{secrets.randbelow(10**6):06d}"
    if pending_mode and pending_email:
        user.verification_token = f"change:{new_code}:{pending_email}"
    else:
        user.verification_token = new_code
    db.commit()

    try:
        send_verification_email(
            to_email=pending_email if pending_mode and pending_email else email,
            first_name=user.first_name,
            last_name=user.last_name,
            code=new_code,
        )
        success_msg = "A new verification code has been sent to your new email." if pending_mode else "A new verification code has been sent."
    except Exception as send_exc:
        success_msg = None
        security_logger.warning(f"Resend code failed for {email}: {send_exc}")

    email_for_form = pending_email if pending_mode and pending_email else email
    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "success": success_msg,
            "error": None if success_msg else "Unable to send code. Please try again.",
            "email": email_for_form,
        },
    )

@router.post("/register")
def register_post(
    request: Request,
    firstName: str = Form(...),
    lastName: str = Form(...),
    email: str = Form(...),
    studentId: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    client_ip = request.client.host
    form_values = {
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "studentId": studentId,
    }

    def resolve_ids(
        student_id_val: str,
        cohort_hint: str | None = None,
        major_hint: str | None = None,
    ):
        sid = (student_id_val or "").strip()
        cohort_num = None
        major_code = None

        if sid.isdigit() and len(sid) >= 6:
            cohort_num = int(sid[:4])
            major_code = int(sid[4:6])

        if cohort_hint and str(cohort_hint).isdigit():
            cohort_num = int(cohort_hint)

        if major_hint:
            rev_map = {v.lower(): int(k) for k, v in MAJOR_CODE_MAP.items()}
            major_code = rev_map.get(major_hint.lower(), major_code)

        cohort_id = None
        major_id = None

        if cohort_num is not None:
            row = db.query(Cohort).filter(Cohort.cohort_num == cohort_num).first()
            cohort_id = getattr(row, "cohort_id", None) if row else None

        if major_code is not None:
            row = db.query(Major).filter(Major.major_code == major_code).first()
            major_id = getattr(row, "major_id", None) if row else None

        return cohort_id, major_id

    try:
        if not is_valid_email_address(email):
            log_security_event(
                "REGISTRATION_BLOCKED",
                f"Invalid email: {email}",
                client_ip,
            )
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Email address is invalid",
                    "form_data": form_values,
                },
            )
        if not is_allowed_domain(email):
            log_security_event(
                "REGISTRATION_BLOCKED",
                f"Email domain not allowed: {email}",
                client_ip,
            )
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Please use your Sampoerna University email.",
                    "form_data": form_values,
                },
            )

        sid = (studentId or "").strip()
        if not (sid.isdigit() and len(sid) == 10):
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Student ID is invalid",
                    "form_data": form_values,
                },
            )

        cohort_prefix = int(sid[:4])
        if cohort_prefix not in SUPPORTED_COHORTS:
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Student ID is invalid",
                    "form_data": form_values,
                },
            )

        existing_user = User.find_by_email(db, email)
        if existing_user:
            log_security_event(
                "REGISTRATION_DUPLICATE",
                f"Duplicate registration attempt: {email}",
                client_ip,
            )
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "User already exists",
                    "form_data": form_values,
                },
            )

        # Duplicate student ID check (decrypting existing records)
        try:
            all_users = db.query(User).all()
            for u in all_users:
                try:
                    if u.student_id == studentId:
                        return templates.TemplateResponse(
                            "register.html",
                            {
                                "request": request,
                                "error": "Email or Student ID already registered",
                                "form_data": form_values,
                            },
                        )
                except Exception:
                    continue
        except Exception:
            pass

        cohort_id, major_id = resolve_ids(studentId)

        verification_code = f"{secrets.randbelow(10**6):06d}"

        new_user = User(
            first_name=firstName,
            last_name=lastName,
            email=email,
            student_id=studentId,
            cohort_id=cohort_id,
            major_id=major_id,
        )
        new_user.status = "pending"
        new_user.is_active = True
        new_user.verification_token = verification_code

        db.add(new_user)
        db.flush()

        # Validate cohort and major against reference tables
        try:
            sid = (studentId or "").strip()
            if not (len(sid) >= 6 and sid[:4].isdigit() and sid[4:6].isdigit()):
                db.rollback()
                return templates.TemplateResponse(
                    "register.html",
                    {
                        "request": request,
                        "error": "Student ID is invalid",
                        "form_data": form_values,
                    },
                )

            cohort_num = int(sid[:4])
            major_code = int(sid[4:6])
            major_name = MAJOR_CODE_MAP.get(f"{major_code:02d}")

            cohort_row = db.execute(
                text("SELECT cohort_id FROM cohort WHERE cohort_num = :cohort"),
                {"cohort": cohort_num},
            ).first()
            major_row = db.execute(
                text("SELECT major_id FROM majors WHERE major_code = :major_code"),
                {"major_code": major_code},
            ).first()

            if cohort_row is None or major_row is None or major_name is None:
                db.rollback()
                return templates.TemplateResponse(
                    "register.html",
                    {
                        "request": request,
                        "error": "Student ID is invalid",
                        "form_data": form_values,
                    },
                )
        except Exception as meta_exc:
            db.rollback()
            security_logger.warning(f"Cohort/Major validation failed for {email}: {meta_exc}")
            return templates.TemplateResponse(
                "register.html",
                {
                    "request": request,
                    "error": "Registration failed. Please try again.",
                    "form_data": form_values,
                },
            )

        db.commit()

        # Send verification code via email
        try:
            send_verification_email(
                to_email=email,
                first_name=firstName,
                last_name=lastName,
                code=verification_code,
            )
        except Exception as send_exc:
            security_logger.warning(f"Verification email failed for {email}: {send_exc}")

        create_audit_log(
            db,
            "users",
            new_user.id,
            "REGISTRATION_SUCCESS",
            user_id=email,
            ip_address=client_ip,
        )
        security_logger.info(f"New user registered: {email} from {client_ip}")

        return RedirectResponse(url=f"/verify-code?email={email}", status_code=302)

    except Exception as exc:
        db.rollback()
        log_security_event(
            "REGISTRATION_ERROR",
            f"Registration error for {email}: {exc}",
            client_ip,
        )
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "Registration failed. Please try again.",
                "form_data": form_values,
            },
        )


@router.get("/verify/{token}")
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    """Verify user email using token."""
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        return RedirectResponse(url="/login?error=Invalid+or+expired+verification+link", status_code=302)
    try:
        user.status = "verified"
        db.commit()
        return RedirectResponse(url="/login?verified=1", status_code=302)
    except Exception as exc:
        db.rollback()
        log_security_event("VERIFICATION_ERROR", f"Error verifying user {getattr(user, 'id', 'unknown')}: {exc}", request.client.host)
        return RedirectResponse(url="/login?error=Verification+failed", status_code=302)

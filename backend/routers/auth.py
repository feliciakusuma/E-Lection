from urllib.parse import urlencode
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
import secrets
import requests
import smtplib
from email.message import EmailMessage
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from ..config import (
    DEV_OPEN_ADMIN,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    EMAIL_SENDER,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_USE_TLS,
)
from ..dependencies import get_db, templates
from ..database import User, Candidate, Election, Admin, Cohort, Major
from ..services.audit import create_audit_log, log_security_event, security_logger
from ..services.security import get_password_hash, verify_password
from ..utils.validation import MAJOR_CODE_MAP, SUPPORTED_COHORTS, is_valid_email_address

router = APIRouter()

# Google login is enabled only if both client ID and secret are present
GOOGLE_LOGIN_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


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
            "google_enabled": GOOGLE_LOGIN_ENABLED,
            "success": msg,
            "error": err,
        },
    )


def send_verification_email(to_email: str, first_name: str, last_name: str, code: str):
    """Send a verification code email."""
    if not (SMTP_HOST and SMTP_PORT and SMTP_USERNAME and SMTP_PASSWORD and EMAIL_SENDER):
        raise RuntimeError("SMTP settings are not configured")

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

    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
    try:
        if SMTP_USE_TLS:
            server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
    finally:
        server.quit()

@router.get("/login/google")
def login_google(request: Request):
    """Start Google OAuth 2.0 login."""
    if not GOOGLE_LOGIN_ENABLED:
        return RedirectResponse(
            url="/login?error=Google+login+is+disabled",
            status_code=302
        )

    # CSRF protection state token
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "include_granted_scopes": "true",
        "state": state,
        "prompt": "select_account",
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie(
        "oauth_state",
        state,
        max_age=600,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/auth/google/callback")
@router.get("/authorize")
def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    """Handle Google OAuth callback and issue application session."""
    if not GOOGLE_LOGIN_ENABLED:
        return RedirectResponse(
            url="/login?error=Google+login+is+disabled",
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
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()

        # Verify ID token
        id_info = id_token.verify_oauth2_token(
            token_data.get("id_token"),
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )

        email = id_info.get("email")
        email_verified = id_info.get("email_verified", False)

        if not email or not email_verified:
            log_security_event(
                "LOGIN_GOOGLE_BLOCKED",
                "Google email missing or unverified",
                request.client.host,
            )
            return RedirectResponse(
                url="/login?error=Google+account+email+not+verified",
                status_code=302,
            )

        # Look up local user linked to this email
        user = User.find_by_email(db, email)
        if not user:
            log_security_event(
                "LOGIN_GOOGLE_BLOCKED",
                f"Google account not linked: {email}",
                request.client.host,
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "No account exists for this Google email. Please register first.",
                    "google_enabled": GOOGLE_LOGIN_ENABLED,
                },
            )

        if not user.is_active:
            log_security_event(
                "LOGIN_GOOGLE_BLOCKED",
                f"Inactive Google user: {email}",
                request.client.host,
            )
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Account inactive. Contact an administrator.",
                    "google_enabled": GOOGLE_LOGIN_ENABLED,
                },
            )

        # Mark verified if needed
        if user.status != "verified":
            user.status = "verified"
        db.commit()

        create_audit_log(
            db,
            "users",
            user.id,
            "LOGIN_GOOGLE_SUCCESS",
            user_id=str(user.id),
            ip_address=request.client.host,
        )

        response = RedirectResponse(url="/dashboard", status_code=302)
        response.delete_cookie("oauth_state")
        try:
            response.set_cookie("user_email", user.email, httponly=False)
            response.set_cookie("first_name", user.first_name, httponly=False)
            response.set_cookie("last_name", user.last_name, httponly=False)
        except Exception:
            # Cookie failure shouldn't break login entirely
            pass

        return response

    except Exception as exc:
        db.rollback()
        log_security_event(
            "LOGIN_GOOGLE_ERROR",
            f"Google login failed: {exc}",
            request.client.host,
        )
        return RedirectResponse(
            url="/login?error=Google+login+failed",
            status_code=302,
        )


@router.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host
    base_ctx = {"request": request, "google_enabled": GOOGLE_LOGIN_ENABLED}
    email = (email or "").strip().lower()

    try:
        # Password login disabled; require Google OAuth
        return templates.TemplateResponse(
            "login.html",
            {
                **base_ctx,
                "error": "Password login disabled. Use Google Sign-In.",
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
    db: Session = Depends(get_db),
):
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
                response.set_cookie("user_email", admin_row.email, httponly=False)
                # Derive display name from admin full_name or linked user record
                full_name = (admin_row.full_name or "").strip()
                if not full_name:
                    linked_user = User.find_by_email(db, admin_row.email)
                    if linked_user:
                        full_name = f"{linked_user.first_name or ''} {linked_user.last_name or ''}".strip() or linked_user.email
                parts = full_name.split(" ", 1)
                first = parts[0] if parts else ""
                last = parts[1] if len(parts) > 1 else ""
                response.set_cookie("full_name", full_name or "", httponly=False)
                response.set_cookie("first_name", first, httponly=False)
                response.set_cookie("last_name", last, httponly=False)
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
        response.delete_cookie(ck)
    return response


@router.get("/admin-logout")
def admin_logout():
    """Logout admins and send them to /admin."""
    response = RedirectResponse(url="/admin", status_code=302)
    for ck in ["user_email", "first_name", "last_name", "full_name", "avatar_url", "oauth_state"]:
        response.delete_cookie(ck)
    return response


@router.get("/verify-code", response_class=HTMLResponse)
def verify_code_page(request: Request, email: str | None = None):
    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "email": email or "",
        },
    )


@router.post("/verify-code")
def verify_code_submit(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "Account not found. Please register again.",
                "email": email,
            },
        )

    if not code or code.strip() != (user.verification_token or ""):
        return templates.TemplateResponse(
            "verify.html",
            {
                "request": request,
                "error": "Invalid or expired verification code.",
                "email": email,
            },
        )

    try:
        user.status = "verified"
        user.is_active = True
        db.commit()
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
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()
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
    user.verification_token = new_code
    db.commit()

    try:
        send_verification_email(
            to_email=email,
            first_name=user.first_name,
            last_name=user.last_name,
            code=new_code,
        )
        success_msg = "A new verification code has been sent."
    except Exception as send_exc:
        success_msg = None
        security_logger.warning(f"Resend code failed for {email}: {send_exc}")

    return templates.TemplateResponse(
        "verify.html",
        {
            "request": request,
            "success": success_msg,
            "error": None if success_msg else "Unable to send code. Please try again.",
            "email": email,
        },
    )

@router.post("/register")
def register_post(
    request: Request,
    firstName: str = Form(...),
    lastName: str = Form(...),
    email: str = Form(...),
    studentId: str = Form(...),
    db: Session = Depends(get_db),
):
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

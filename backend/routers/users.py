import secrets
from fastapi import APIRouter, Form, Request, Depends
from sqlalchemy.orm import Session

from ..dependencies import templates, get_db
from ..database import User
from fastapi.responses import HTMLResponse, RedirectResponse
from ..utils.validation import is_valid_email_address
from ..routers.auth import send_verification_email

router = APIRouter()


@router.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, db: Session = Depends(get_db)):
    form_data = {}
    try:
        email_cookie = request.cookies.get("user_email")
        if email_cookie:
            user = User.find_by_email(db, email_cookie)
            if user:
                form_data = {
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "student_id": user.student_id,
                }
    except Exception:
        form_data = {}
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "form_data": form_data,
            "success": request.query_params.get("email_updated") and "Email updated successfully." or None,
            "error": None,
        },
    )


def _build_email_change_token(new_email: str) -> tuple[str, str]:
    """Create a verification code and token string for email change flow."""
    code = f"{secrets.randbelow(10**6):06d}"
    return code, f"change:{code}:{new_email}"


@router.post("/profile", response_class=HTMLResponse)
def profile_submit(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    student_id: str = Form(""),
    email: str = Form(...),
    password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
):
    form_data = {
        "first_name": first_name or "",
        "last_name": last_name or "",
        "student_id": student_id or "",
        "email": email or "",
    }
    email_cookie = request.cookies.get("user_email")
    if not email_cookie:
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "form_data": form_data,
                "error": "Session expired. Please log in again.",
                "success": None,
            },
        )

    user = User.find_by_email(db, email_cookie)
    if not user:
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "form_data": form_data,
                "error": "User not found.",
                "success": None,
            },
        )

    if not is_valid_email_address(email):
        return templates.TemplateResponse(
            "profile.html",
            {"request": request, "form_data": form_data, "error": "Please enter a valid email address.", "success": None},
        )
    if (password or confirm_password) and password != confirm_password:
        return templates.TemplateResponse(
            "profile.html",
            {"request": request, "form_data": form_data, "error": "Passwords do not match.", "success": None},
        )

    normalized_email = email.strip().lower()
    current_email = (user.email or "").strip().lower()

    # Prevent duplicate emails when the user changes it.
    if normalized_email != current_email:
        existing = db.query(User).filter(User.email == normalized_email).first()
        if existing:
            return templates.TemplateResponse(
                "profile.html",
                {
                    "request": request,
                    "form_data": form_data,
                    "error": "Email is already in use by another account.",
                    "success": None,
                },
            )

    pending_code = None
    pending_token = None
    try:
        user.first_name = first_name.strip()
        user.last_name = last_name.strip()
        if student_id:
            user.student_id = student_id.strip()

        email_changed = normalized_email != current_email
        if email_changed:
            pending_code, pending_token = _build_email_change_token(normalized_email)
            user.verification_token = pending_token  # store pending change token, keep old email until verified
        else:
            user.email = normalized_email

        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "form_data": form_data,
                "error": "Unable to update profile. Please try again.",
                "success": None,
            },
        )

    # If the email changed, send verification and redirect to verify page.
    if normalized_email != current_email:
        try:
            if pending_token:
                # Ensure token persisted even if previous refresh succeeded.
                user.verification_token = pending_token
                db.commit()
            send_verification_email(
                to_email=normalized_email,
                first_name=user.first_name,
                last_name=user.last_name,
                code=pending_code or "000000",
            )
        except Exception:
            db.rollback()
        response = RedirectResponse(
            url=f"/verify-code?email={normalized_email}&changing=1",
            status_code=303,
        )
        try:
            response.set_cookie("first_name", user.first_name or "", httponly=False)
            response.set_cookie("last_name", user.last_name or "", httponly=False)
            response.set_cookie("full_name", f"{user.first_name or ''} {user.last_name or ''}".strip(), httponly=False)
            response.set_cookie("user_email", user.email or "", httponly=False)
        except Exception:
            pass
        return response

    updated_form = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "student_id": user.student_id,
    }
    display_full = f"{user.first_name or ''} {user.last_name or ''}".strip() or user.email

    response = templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "form_data": updated_form,
            "success": "Profile updated successfully.",
            "error": None,
        },
    )
    try:
        response.set_cookie("first_name", user.first_name or "", httponly=False)
        response.set_cookie("last_name", user.last_name or "", httponly=False)
        response.set_cookie("full_name", display_full, httponly=False)
        response.set_cookie("user_email", user.email or "", httponly=False)
    except Exception:
        # Do not block the response if cookies fail to set
        pass
    return response

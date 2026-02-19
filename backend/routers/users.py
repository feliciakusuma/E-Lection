from fastapi import APIRouter, Form, Request, Depends
from sqlalchemy.orm import Session

from ..dependencies import templates, get_db
from ..database import User
from fastapi.responses import HTMLResponse, RedirectResponse
from ..utils.csrf import validate_csrf
from ..utils.cookies import set_secure_cookies

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
            "success": None,
            "error": None,
        },
    )


@router.post("/profile", response_class=HTMLResponse)
def profile_submit(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    student_id: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
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

    if (password or confirm_password) and password != confirm_password:
        return templates.TemplateResponse(
            "profile.html",
            {"request": request, "form_data": form_data, "error": "Passwords do not match.", "success": None},
        )

    try:
        user.first_name = first_name.strip()
        user.last_name = last_name.strip()
        if student_id:
            user.student_id = student_id.strip()
        # Email is immutable for voter accounts.
        if email and email.strip().lower() != (user.email or "").strip().lower():
            return templates.TemplateResponse(
                "profile.html",
                {
                    "request": request,
                    "form_data": {
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "email": user.email,
                        "student_id": user.student_id,
                    },
                    "error": "Email cannot be changed.",
                    "success": None,
                },
            )

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
        set_secure_cookies(
            response,
            {
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "full_name": display_full,
                "user_email": user.email or "",
            },
        )
    except Exception:
        # Do not block the response if cookies fail to set
        pass
    return response

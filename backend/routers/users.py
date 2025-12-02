from fastapi import APIRouter, Form, Request, Depends
from sqlalchemy.orm import Session

from ..dependencies import templates, get_db
from ..database import User
from fastapi.responses import HTMLResponse
from ..utils.validation import is_valid_email_address

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
    email: str = Form(...),
    password: str = Form(""),
    confirm_password: str = Form(""),
):
    form_data = {
        "first_name": first_name or "",
        "last_name": last_name or "",
        "student_id": student_id or "",
        "email": email or "",
    }
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

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "form_data": form_data,
            "success": "Profile updated (demo only, not persisted).",
            "error": None,
        },
    )

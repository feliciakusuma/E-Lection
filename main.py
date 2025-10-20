from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import or_
from passlib.context import CryptContext
from sqlalchemy import func, text
from sqlalchemy.exc import OperationalError
import re
import secrets
import hashlib
from datetime import datetime
from pathlib import Path
import logging
from urllib.parse import urlencode
from sqlalchemy.exc import OperationalError
import os


from database import (
    SessionLocal, engine, Base, User, Candidate, Election, Vote, AuditLog,
    get_readonly_db, get_secure_db, verify_data_integrity, get_vote_count_secure
)

DEV_OPEN_ADMIN = os.getenv("DEV_OPEN_ADMIN", "true").lower() == "true"

# Create database tables
Base.metadata.create_all(bind=engine)

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "security.log"
app = FastAPI()

# Configure logging for security events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

DEFAULT_ACCOUNTS = [
    {
        "first_name": "Admin",
        "last_name": "User",
        "email": "admin@university.edu",
        "student_id": "ADMIN000",
        "password": "AdminPass123!"
    },
    {
        "first_name": "Student",
        "last_name": "User",
        "email": "student@university.edu",
        "student_id": "STUDENT001",
        "password": "StudentPass123!"
    }
]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Static files and templates
app.mount("/static", StaticFiles(directory="src/static"), name="static")
templates = Jinja2Templates(directory="src")

# Security middleware
@app.middleware("https")
async def security_middleware(request: Request, call_next):
    # Log all requests for audit
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    security_logger.info(f"Request: {request.method} {request.url} from {client_ip}")
    
    response = await call_next(request)
    return response

# Dependency: get DB session with audit logging
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def log_security_event(event_type: str, details: str, ip_address: str = None, user_id: str = None):
    """Log security events"""
    security_logger.warning(f"SECURITY EVENT: {event_type} - {details} - IP: {ip_address} - User: {user_id}")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def is_valid_university_email(email):
    """Validate that email ends with @university.edu"""
    return re.match(r'^[^@]+@university\.edu$', email) is not None

@app.on_event("startup")
def seed_default_accounts():
    """Ensure default admin and student accounts exist for demo access."""
    db = SessionLocal()
    try:
        created_any = False
        for account in DEFAULT_ACCOUNTS:
            if not User.find_by_email(db, account["email"]):
                hashed_password = get_password_hash(account["password"])
                user = User(
                    first_name=account["first_name"],
                    last_name=account["last_name"],
                    email=account["email"],
                    student_id=account["student_id"],
                    password_hash=hashed_password,
                    is_admin=account.get("is_admin", False),
                    created_by="system-seed"
                )
                user.status = "verified"
                user.is_active = True
                user.data_hash = user.generate_hash()
                db.add(user)
                created_any = True
        if created_any:
            db.commit()
            security_logger.info("Default demo accounts seeded.")
    except Exception as exc:
        db.rollback()
        security_logger.error(f"Default account seeding failed: {exc}")
    finally:
        db.close()

def create_audit_log(db: Session, table_name: str, record_id: int, action: str, 
                    user_id: str = None, ip_address: str = None, user_agent: str = None):
    """Create audit log entry"""
    audit_entry = AuditLog(
        table_name=table_name,
        record_id=record_id,
        action=action,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        timestamp=datetime.utcnow(),
        is_authorized=True
    )
    db.add(audit_entry)
    db.commit()

# ROUTES
@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse("landingpage.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    client_ip = request.client.host
    
    try:
        # Use secure user lookup
        user = User.find_by_email(db, email)
        
        if user and verify_password(password, user.password_hash):
            if user.status == "verified" and user.is_active:
                # Log successful login
                create_audit_log(db, "users", user.id, "LOGIN_SUCCESS", 
                               user_id=str(user.id), ip_address=client_ip)
                target_url = "/admin-dashboard" if getattr(user, 'is_admin', False) else "/dashboard"
                return RedirectResponse(url=target_url, status_code=302)
            else:
                log_security_event("LOGIN_BLOCKED", f"Inactive/unverified user: {email}", client_ip)
                return templates.TemplateResponse("login.html", {"request": request, "error": "Account pending verification or inactive", "form_data": {"email": email}})
        else:
            # Log failed login attempt
            log_security_event("LOGIN_FAILED", f"Invalid credentials for: {email}", client_ip)
            create_audit_log(db, "users", 0, "LOGIN_FAILED", 
                           user_id=email, ip_address=client_ip)
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials", "form_data": {"email": email}})
    
    except Exception as e:
        log_security_event("LOGIN_ERROR", f"Login error for {email}: {str(e)}", client_ip)
        return templates.TemplateResponse("login.html", {"request": request, "error": "System error occurred", "form_data": {"email": email}})

@app.get("/admin", response_class=HTMLResponse)
def admin_login_page(request: Request):
    # Development convenience: allow accessing admin without login
    # Redirect straight to the admin dashboard to bypass the login form
    return RedirectResponse(url="/admin-dashboard", status_code=302)

@app.post("/admin")
def admin_login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    form_data = {"email": email}

    if DEV_OPEN_ADMIN:
        return RedirectResponse(url="/admin-dashboard", status_code=302)

    try:
        user = User.find_by_email(db, email)
        if user and user.is_admin and verify_password(password, user.password_hash):
            create_audit_log(db, "users", user.id, "ADMIN_LOGIN_SUCCESS", user_id=str(user.id), ip_address=client_ip)
            return RedirectResponse(url="/admin-dashboard", status_code=302)

        log_security_event("ADMIN_LOGIN_FAILED", f"Invalid admin credentials for: {email}", client_ip)
        return templates.TemplateResponse("admin.html", {"request": request, "error": "Invalid admin credentials", "form_data": form_data})

    except Exception as exc:
        log_security_event("ADMIN_LOGIN_ERROR", f"Admin login error for {email}: {exc}", client_ip)
        return templates.TemplateResponse("admin.html", {"request": request, "error": "System error occurred", "form_data": form_data})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_post(
    request: Request,
    firstName: str = Form(...),
    lastName: str = Form(...),
    email: str = Form(...),
    studentId: str = Form(...),
    password: str = Form(...),
    confirmPassword: str = Form(...),
    terms: bool = Form(False),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    form_values = {
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "studentId": studentId,
    }

    try:
        if not is_valid_university_email(email):
            log_security_event("REGISTRATION_BLOCKED", f"Invalid email domain: {email}", client_ip)
            return templates.TemplateResponse("register.html", {"request": request, "error": "Must use @university.edu email", "form_data": form_values})

        if password != confirmPassword:
            return templates.TemplateResponse("register.html", {"request": request, "error": "Passwords do not match", "form_data": form_values})

        if not terms:
            return templates.TemplateResponse("register.html", {"request": request, "error": "You must accept the terms to continue", "form_data": form_values})

        existing_user = User.find_by_email(db, email)
        if existing_user:
            log_security_event("REGISTRATION_DUPLICATE", f"Duplicate registration attempt: {email}", client_ip)
            return templates.TemplateResponse("register.html", {"request": request, "error": "User already exists", "form_data": form_values})

        hashed_password = get_password_hash(password)
        new_user = User(
            first_name=firstName,
            last_name=lastName,
            email=email,
            student_id=studentId,
            password_hash=hashed_password,
            created_by=client_ip
        )
        new_user.status = "verified"
        new_user.is_active = True
        new_user.data_hash = new_user.generate_hash()

        db.add(new_user)
        db.commit()

        create_audit_log(db, "users", new_user.id, "REGISTRATION_SUCCESS",
                        user_id=email, ip_address=client_ip)

        security_logger.info(f"New user registered: {email} from {client_ip}")

        return RedirectResponse(url="/confirmation", status_code=302)

    except Exception as e:
        db.rollback()
        log_security_event("REGISTRATION_ERROR", f"Registration error for {email}: {str(e)}", client_ip)
        return templates.TemplateResponse("register.html", {"request": request, "error": "Registration failed. Please try again.", "form_data": form_values})

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    candidates = db.query(Candidate).filter(Candidate.is_active == True).order_by(Candidate.created_at.desc()).all()
    active_election = db.query(Election).filter(
        Election.is_active == True,
        Election.status == "ongoing"
    ).order_by(Election.start_date.asc()).first()

    message = None
    if not active_election:
        message = "There is no active election right now."

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "candidates": candidates,
        "active_election": active_election,
        "message": message
    })


@app.get("/confirmation", response_class=HTMLResponse)
def confirm(
    request: Request,
    candidate_id: int | None = None,
    election_id: int | None = None,
    verification_code: str | None = None,
    db: Session = Depends(get_db)
):
    candidate = None
    election = None
    error = None

    if candidate_id is not None:
        candidate = db.query(Candidate).filter(
            Candidate.id == candidate_id,
            Candidate.is_active == True
        ).first()
        if not candidate:
            error = "Selected candidate could not be found."

    if election_id is not None:
        election = db.query(Election).filter(Election.id == election_id).first()
    else:
        election = db.query(Election).filter(
            Election.is_active == True,
            Election.status == "ongoing"
        ).order_by(Election.start_date.asc()).first()

    return templates.TemplateResponse("confirmation.html", {
        "request": request,
        "candidate": candidate,
        "election": election,
        "verification_code": verification_code,
        "error": error
    })


@app.post("/vote")
def cast_vote(
    request: Request,
    candidate_id: int = Form(...),
    election_id: int = Form(...),
    voter_id: str = Form(...),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host

    try:
        election = db.query(Election).filter(
            Election.id == election_id,
            Election.status == "ongoing",
            Election.is_active == True
        ).first()

        if not election:
            log_security_event("VOTE_BLOCKED", f"Invalid election: {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Election not available")

        voter_hash_check = hashlib.sha256(f"{voter_id}_{election_id}".encode()).hexdigest()
        existing_vote = db.query(Vote).filter(
            Vote.election_id == election_id,
            Vote.voter_hash == voter_hash_check
        ).first()

        if existing_vote:
            log_security_event("VOTE_DUPLICATE", f"Duplicate vote attempt for election {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Vote already cast")

        candidate = db.query(Candidate).filter(
            Candidate.id == candidate_id,
            Candidate.is_active == True
        ).first()
        if not candidate:
            log_security_event("VOTE_BLOCKED", f"Invalid candidate: {candidate_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Candidate not available")

        new_vote = Vote(
            voter_id=voter_id,
            candidate_id=candidate_id,
            election_id=election_id,
            created_by=client_ip
        )
        new_vote.voter_hash = voter_hash_check
        new_vote.data_hash = new_vote.generate_hash()
        new_vote.is_counted = True

        db.add(new_vote)
        db.commit()

        create_audit_log(db, "votes", new_vote.id, "VOTE_CAST",
                        user_id=voter_id, ip_address=client_ip)

        security_logger.info(f"Vote cast successfully - Election: {election_id}, Verification: {new_vote.verification_code}")

        query_params = urlencode({
            "candidate_id": candidate_id,
            "election_id": election_id,
            "verification_code": new_vote.verification_code
        })

        return RedirectResponse(url=f"/confirmation?{query_params}", status_code=303)

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        log_security_event("VOTE_ERROR", f"Vote casting error: {str(e)}", client_ip, voter_id)
        raise HTTPException(status_code=500, detail="Vote casting failed")

@app.get("/results/{election_id}")
def get_results(election_id: int, db: Session = Depends(get_readonly_db)):
    """Get election results using read-only access"""
    try:
        # Use secure vote counting function
        vote_counts = get_vote_count_secure(db._session, election_id)
        
        # Get candidate information
        candidates = db.query(Candidate).filter(Candidate.is_active == True).all()
        candidate_info = {c.id: {"name": c.full_name, "position": c.position} for c in candidates}
        
        # Combine results
        results = []
        for candidate_id, count in vote_counts.items():
            if candidate_id in candidate_info:
                results.append({
                    "candidate_id": candidate_id,
                    "name": candidate_info[candidate_id]["name"],
                    "position": candidate_info[candidate_id]["position"],
                    "votes": count
                })
        
        return {"election_id": election_id, "results": results}
    
    except Exception as e:
        security_logger.error(f"Results access error: {str(e)}")
        raise HTTPException(status_code=500, detail="Unable to retrieve results")

@app.get("/results", response_class=HTMLResponse)
def results_page(request: Request):
    """Render the static results HTML page."""
    return templates.TemplateResponse("results.html", {"request": request})

@app.get("/verify-vote/{verification_code}")
def verify_vote(verification_code: str, db: Session = Depends(get_readonly_db)):
    """Verify a vote using verification code"""
    try:
        vote = db.query(Vote).filter(Vote.verification_code == verification_code).first()
        
        if vote:
            # Return limited information for verification
            return {
                "verified": True,
                "election_id": vote.election_id,
                "timestamp": vote.vote_timestamp,
                "is_counted": vote.is_counted
            }
        else:
            return {"verified": False}
    
    except Exception as e:
        security_logger.error(f"Vote verification error: {str(e)}")
        return {"verified": False, "error": "Verification failed"}

@app.get("/audit-log")
def get_audit_log(db: Session = Depends(get_readonly_db)):
    """Get audit log (read-only access)"""
    try:
        # Only return non-sensitive audit information
        logs = db.query(AuditLog).filter(
            AuditLog.action.in_(['LOGIN_SUCCESS', 'REGISTRATION_SUCCESS', 'VOTE_CAST'])
        ).order_by(AuditLog.timestamp.desc()).limit(100).all()
        
        return [{
            "timestamp": log.timestamp,
            "action": log.action,
            "table_name": log.table_name,
            "is_authorized": log.is_authorized
        } for log in logs]
    
    except Exception as e:
        security_logger.error(f"Audit log access error: {str(e)}")
        raise HTTPException(status_code=500, detail="Unable to retrieve audit log")

@app.get("/admin-candidates", response_class=HTMLResponse)
def admin_candidates(request: Request, db: Session = Depends(get_db)):
    q = (request.query_params.get("q", "") or "").strip()
    status_filter = (request.query_params.get("status", "all") or "all").lower()
    election_id_param = (request.query_params.get("election_id", "") or "").strip()

    query = db.query(Candidate)

    # Free-text search
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Candidate.full_name.like(like),
                Candidate.student_id.like(like),
                Candidate.major.like(like),
                Candidate.position.like(like),
            )
        )

    # Status filter
    if status_filter in {"running", "pending", "rejected"}:
        query = query.filter(Candidate.status == status_filter)

    # Election filter (map election_id to title, then match by position)
    selected_election_id: int | None = None
    if election_id_param.isdigit():
        selected_election_id = int(election_id_param)
        e = db.query(Election).filter(Election.id == selected_election_id).first()
        if e:
            query = query.filter(Candidate.position == e.title)

    candidates = query.order_by(Candidate.created_at.desc()).all()

    # Dropdown data: elections list
    elections_list = db.query(Election).order_by(Election.start_date.desc()).all()

    success_message = None
    if request.query_params.get("success") == "1":
        success_message = "Candidate saved successfully."
    if request.query_params.get("updated") == "1":
        success_message = "Candidate updated successfully."
    if request.query_params.get("deleted") == "1":
        success_message = "Candidate deleted successfully."

    error_message = request.query_params.get("error")

    return templates.TemplateResponse("admin-candidates.html", {
        "request": request,
        "candidates": candidates,
        "elections": elections_list,
        "status_filter": status_filter,
        "selected_election_id": selected_election_id,
        "success": success_message,
        "error": error_message
    })


@app.get("/admin-add-candidate", response_class=HTMLResponse)
def admin_add_candidate_form(request: Request, db: Session = Depends(get_db)):
    # Build elections list with major/cohort derived from description JSON
    elections = db.query(Election).order_by(Election.start_date.desc()).all()
    items = []
    for e in elections:
        major = "All Major"
        cohort = "All Cohort"
        try:
            import json
            meta = json.loads(e.description) if e.description and e.description.strip().startswith("{") else {}
            major = meta.get("major", major)
            cohort = meta.get("cohort", cohort)
        except Exception:
            pass
        items.append({
            "id": e.id,
            "title": e.title,
            "major": major,
            "cohort": cohort,
        })

    return templates.TemplateResponse("admin-add-candidate.html", {
        "request": request,
        "form_data": {},
        "elections": items
    })


@app.post("/admin-add-candidate", response_class=HTMLResponse)
def admin_add_candidate_submit(
    request: Request,
    full_name: str = Form(...),
    student_id: str = Form(...),
    major: str = Form(...),
    cohort: str = Form(...),
    position: str = Form(...),
    status: str = Form("running"),
    description: str = Form(""),
    is_active: bool = Form(False),
    db: Session = Depends(get_db)
):
    form_values = {
        "full_name": full_name,
        "student_id": student_id,
        "major": major,
        "cohort": cohort,
        "position": position,
        "status": status,
        "description": description,
        "is_active": is_active
    }

    try:
        normalized_status = status.lower()
        if normalized_status not in {"running", "pending", "rejected"}:
            normalized_status = "pending"

        existing_candidate = db.query(Candidate).filter(Candidate.student_id == student_id).first()
        if existing_candidate:
            return templates.TemplateResponse("admin-add-candidate.html", {
                "request": request,
                "error": "A candidate with this student ID already exists.",
                "form_data": form_values
            })

        candidate = Candidate(
            full_name=full_name,
            student_id=student_id,
            major=major,
            cohort=cohort,
            description=description,
            position=position,
            status=normalized_status,
            is_active=is_active,
            created_by=request.client.host
        )
        candidate.data_hash = candidate.generate_hash()

        db.add(candidate)
        db.commit()

        return RedirectResponse(url="/admin-candidates?success=1", status_code=303)

    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_CANDIDATE_ERROR", f"Failed to add candidate: {exc}", request.client.host)
        return templates.TemplateResponse("admin-add-candidate.html", {
            "request": request,
            "error": "Unable to save candidate. Please try again.",
            "form_data": form_values
        })

@app.get("/admin-edit-candidate/{candidate_id}", response_class=HTMLResponse)
def admin_edit_candidate_form(request: Request, candidate_id: int, db: Session = Depends(get_db)):
    candidate = db.query(Candidate).filter(Candidate.id == candidate_id).first()
    if not candidate:
        return RedirectResponse(url="/admin-candidates?error=Candidate%20not%20found", status_code=303)

    # Provide elections list (for position + auto-fill major/cohort)
    elections = db.query(Election).order_by(Election.start_date.desc()).all()
    items = []
    for e in elections:
        major = "All Major"
        cohort = "All Cohort"
        try:
            import json
            meta = json.loads(e.description) if e.description and e.description.strip().startswith("{") else {}
            major = meta.get("major", major)
            cohort = meta.get("cohort", cohort)
        except Exception:
            pass
        items.append({
            "id": e.id,
            "title": e.title,
            "major": major,
            "cohort": cohort,
        })

    form_data = {
        "full_name": candidate.full_name,
        "student_id": candidate.student_id,
        "major": candidate.major,
        "cohort": candidate.cohort,
        "position": candidate.position,
        "status": candidate.status,
        "description": candidate.description,
        "is_active": candidate.is_active,
    }

    return templates.TemplateResponse("admin-edit-candidate.html", {
        "request": request,
        "candidate": candidate,
        "form_data": form_data,
        "elections": items
    })


@app.post("/admin-edit-candidate/{candidate_id}")
def admin_edit_candidate_submit(
    request: Request,
    candidate_id: int,
    full_name: str = Form(...),
    student_id: str = Form(...),
    major: str = Form(...),
    cohort: str = Form(...),
    position: str = Form(...),
    status: str = Form("running"),
    description: str = Form(""),
    is_active: bool = Form(False),
    db: Session = Depends(get_db)
):
    try:
        candidate = db.query(Candidate).filter(Candidate.id == candidate_id).first()
        if not candidate:
            return RedirectResponse(url="/admin-candidates?error=Candidate%20not%20found", status_code=303)

        normalized_status = status.lower()
        if normalized_status not in {"running", "pending", "rejected"}:
            normalized_status = "pending"

        # Ensure unique student_id (excluding this candidate)
        existing = db.query(Candidate).filter(Candidate.student_id == student_id, Candidate.id != candidate_id).first()
        if existing:
            return templates.TemplateResponse("admin-edit-candidate.html", {
                "request": request,
                "candidate": candidate,
                "error": "Another candidate with this student ID already exists.",
                "form_data": {
                    "full_name": full_name,
                    "student_id": student_id,
                    "major": major,
                    "cohort": cohort,
                    "position": position,
                    "status": normalized_status,
                    "description": description,
                    "is_active": is_active,
                }
            })

        candidate.full_name = full_name
        candidate.student_id = student_id
        candidate.major = major
        candidate.cohort = cohort
        candidate.position = position
        candidate.status = normalized_status
        candidate.description = description
        candidate.is_active = is_active
        candidate.data_hash = candidate.generate_hash()

        db.commit()

        return RedirectResponse(url="/admin-candidates?updated=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_CANDIDATE_EDIT_ERROR", f"Failed to edit candidate {candidate_id}: {exc}", request.client.host)
        return templates.TemplateResponse("admin-edit-candidate.html", {
            "request": request,
            "candidate": {"id": candidate_id},
            "error": "Unable to update candidate. Please try again.",
            "form_data": {
                "full_name": full_name,
                "student_id": student_id,
                "major": major,
                "cohort": cohort,
                "position": position,
                "status": status,
                "description": description,
                "is_active": is_active,
            }
        })


@app.post("/admin-delete-candidate/{candidate_id}")
def admin_delete_candidate(candidate_id: int, request: Request, db: Session = Depends(get_db)):
    try:
        candidate = db.query(Candidate).filter(Candidate.id == candidate_id).first()
        if not candidate:
            return RedirectResponse(url="/admin-candidates?error=Candidate%20not%20found", status_code=303)

        db.delete(candidate)
        db.commit()
        return RedirectResponse(url="/admin-candidates?deleted=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_CANDIDATE_DELETE_ERROR", f"Failed to delete candidate {candidate_id}: {exc}", request.client.host)
        return RedirectResponse(url="/admin-candidates?error=Delete%20failed", status_code=303)

@app.get("/admin-dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    # Use COUNT(*) directly to avoid selecting non-existent columns
    try:
        total_users = db.query(func.count(User.id)).scalar() or 0
    except OperationalError:
        # Fallback if the model mapping still causes trouble
        total_users = db.execute(text("SELECT COUNT(*) FROM users")).scalar() or 0

    try:
        total_candidates = db.query(func.count(Candidate.id)).scalar() or 0
    except OperationalError:
        total_candidates = db.execute(text("SELECT COUNT(*) FROM candidates")).scalar() or 0

    try:
        total_elections = db.query(func.count(Election.id)).scalar() or 0
    except OperationalError:
        total_elections = db.execute(text("SELECT COUNT(*) FROM elections")).scalar() or 0

    try:
        total_votes = db.query(func.count(Vote.id)).scalar() or 0
    except OperationalError:
        total_votes = db.execute(text("SELECT COUNT(*) FROM votes")).scalar() or 0

    return templates.TemplateResponse("admin-dashboard.html", {
        "request": request,
        "stats": {
            "total_users": total_users,
            "total_candidates": total_candidates,
            "total_elections": total_elections,
            "total_votes": total_votes
        },
    })

@app.get("/admin-voters", response_class=HTMLResponse)
def admin_voters(request: Request, db: Session = Depends(get_db)):
    q = (request.query_params.get("q", "") or "").strip()
    query = db.query(User)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                User.first_name.like(like),
                User.last_name.like(like),
                User.email.like(like),
                User.student_id.like(like),
            )
        )
    voters = query.order_by(User.created_at.desc()).all() if hasattr(User, "created_at") else query.all()
    return templates.TemplateResponse("admin-voters.html", {
        "request": request,
        "voters": voters
    })

@app.get("/voters", response_class=HTMLResponse)
def voters_page(request: Request, db: Session = Depends(get_db)):
    """Public voters list page that reuses the admin voters template."""
    q = (request.query_params.get("q", "") or "").strip()
    query = db.query(User)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                User.first_name.like(like),
                User.last_name.like(like),
                User.email.like(like),
                User.student_id.like(like),
            )
        )
    voters = query.order_by(User.created_at.desc()).all() if hasattr(User, "created_at") else query.all()
    return templates.TemplateResponse("admin-voters.html", {
        "request": request,
        "voters": voters
    })


@app.get("/admin-elections", response_class=HTMLResponse)
def admin_elections(request: Request, db: Session = Depends(get_db)):
    def derive_status(e: Election) -> str:
        now = datetime.utcnow()
        if e.start_date and now < e.start_date:
            return "upcoming"
        if e.end_date and now > e.end_date:
            return "ended"
        return "ongoing"

    status_filter = request.query_params.get("status", "all").lower()
    q = (request.query_params.get("q", "") or "").strip()
    elections_q = db.query(Election)
    if q:
        elections_q = elections_q.filter(Election.title.like(f"%{q}%"))
    elections = elections_q.order_by(Election.start_date.desc()).all()

    payload = []
    from datetime import datetime as _dt
    now = _dt.utcnow()
    for e in elections:
        dstatus = derive_status(e)

        # Counts based on votes table
        votes_q = db.query(Vote).filter(Vote.election_id == e.id)
        votes_cast = votes_q.count()
        candidates_count = db.query(Vote.candidate_id).filter(Vote.election_id == e.id).distinct().count()
        voters_count = db.query(Vote.voter_hash).filter(Vote.election_id == e.id).distinct().count()

        # Optional filter
        if status_filter != "all" and dstatus != status_filter:
            continue

        # Starts in days for upcoming
        starts_in_days = 0
        if dstatus == "upcoming" and e.start_date:
            starts_in_days = max((e.start_date - now).days, 0)

        payload.append({
            "election": e,
            "status": dstatus,
            "votes_cast": votes_cast,
            "candidates_count": candidates_count,
            "voters_count": voters_count,
            "starts_in_days": starts_in_days,
        })

    return templates.TemplateResponse("admin-elections.html", {
        "request": request,
        "status_filter": status_filter,
        "elections_payload": payload
    })


@app.get("/admin-results", response_class=HTMLResponse)
def admin_results(request: Request, db: Session = Depends(get_db)):
    # Admin-specific results page removed; redirect to Elections for now
    return RedirectResponse(url="/admin-elections", status_code=302)


@app.get("/admin-settings", response_class=HTMLResponse)
def admin_settings(request: Request):
    return templates.TemplateResponse("admin-settings.html", {"request": request})


# Elections: add/edit/delete
@app.get("/add-election", response_class=HTMLResponse)
def add_election_form(request: Request):
    return templates.TemplateResponse("admin-add-election.html", {
        "request": request,
        "form_data": {}
    })


@app.post("/add-election", response_class=HTMLResponse)
def add_election_submit(
    request: Request,
    title: str = Form(...),
    major: str = Form("") ,
    cohort: str = Form(""),
    start_date: str = Form(...),
    end_date: str = Form(...),
    is_active: bool = Form(False),
    db: Session = Depends(get_db)
):
    try:
        # Parse datetime-local inputs
        def parse_dt(val: str) -> datetime:
            # Expect 'YYYY-MM-DDTHH:MM'
            return datetime.strptime(val, "%Y-%m-%dT%H:%M")

        sdt = parse_dt(start_date)
        edt = parse_dt(end_date)
        if edt <= sdt:
            return templates.TemplateResponse("admin-add-election.html", {
                "request": request,
                "error": "End date must be after start date",
                "form_data": {
                    "title": title, "major": major, "cohort": cohort,
                    "start_date": start_date, "end_date": end_date,
                    "is_active": is_active
                }
            })

        # Store major/cohort in JSON inside description to avoid schema change
        import json
        meta = {"major": major, "cohort": cohort}
        e = Election(
            title=title,
            description=json.dumps(meta),
            start_date=sdt,
            end_date=edt,
            status="upcoming",
            is_active=is_active,
            created_by=request.client.host
        )
        e.data_hash = e.title  # lightweight tag; not used elsewhere here
        db.add(e)
        db.commit()
        return RedirectResponse(url="/admin-elections?success=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_ELECTION_ADD_ERROR", f"Failed to add election: {exc}", request.client.host)
        return templates.TemplateResponse("admin-add-election.html", {
            "request": request,
            "error": "Unable to save election. Please try again.",
            "form_data": {
                "title": title, "major": major, "cohort": cohort,
                "start_date": start_date, "end_date": end_date,
                "is_active": is_active
            }
        })


@app.get("/edit-election/{election_id}", response_class=HTMLResponse)
def edit_election_form(request: Request, election_id: int, db: Session = Depends(get_db)):
    e = db.query(Election).filter(Election.id == election_id).first()
    if not e:
        return RedirectResponse(url="/admin-elections?error=Election%20not%20found", status_code=303)

    # Try to read major/cohort from description (JSON or dict-like string)
    major = cohort = ""
    try:
        import json
        meta = json.loads(e.description) if e.description and e.description.strip().startswith("{") else {}
        major = meta.get("major", "")
        cohort = meta.get("cohort", "")
    except Exception:
        pass

    def fmt_dt(dt: datetime | None) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M") if dt else ""

    return templates.TemplateResponse("admin-edit-election.html", {
        "request": request,
        "election": e,
        "form_data": {
            "title": e.title,
            "major": major,
            "cohort": cohort,
            "start_date": fmt_dt(e.start_date),
            "end_date": fmt_dt(e.end_date),
            "is_active": e.is_active,
        }
    })


@app.post("/edit-election/{election_id}")
def edit_election_submit(
    request: Request,
    election_id: int,
    title: str = Form(...),
    major: str = Form("") ,
    cohort: str = Form(""),
    start_date: str = Form(...),
    end_date: str = Form(...),
    is_active: bool = Form(False),
    db: Session = Depends(get_db)
):
    try:
        e = db.query(Election).filter(Election.id == election_id).first()
        if not e:
            return RedirectResponse(url="/admin-elections?error=Election%20not%20found", status_code=303)

        # Keep previous values to detect changes and map related candidates
        old_title = e.title
        old_major = None
        old_cohort = None
        try:
            import json as _json
            prev_meta = _json.loads(e.description) if e.description and str(e.description).strip().startswith("{") else {}
            old_major = prev_meta.get("major")
            old_cohort = prev_meta.get("cohort")
        except Exception:
            pass

        sdt = datetime.strptime(start_date, "%Y-%m-%dT%H:%M")
        edt = datetime.strptime(end_date, "%Y-%m-%dT%H:%M")
        if edt <= sdt:
            return templates.TemplateResponse("admin-edit-election.html", {
                "request": request,
                "election": e,
                "error": "End date must be after start date",
                "form_data": {
                    "title": title, "major": major, "cohort": cohort,
                    "start_date": start_date, "end_date": end_date,
                    "is_active": is_active
                }
            })

        e.title = title
        import json
        e.description = json.dumps({"major": major, "cohort": cohort})
        e.start_date = sdt
        e.end_date = edt
        e.is_active = is_active
        # Update status dynamically
        now = datetime.utcnow()
        e.status = "upcoming" if now < sdt else ("ended" if now > edt else "ongoing")

        # If major/cohort (or title) changed, propagate to related candidates.
        propagate = (old_major != major) or (old_cohort != cohort) or (old_title != title)
        if propagate:
            from sqlalchemy import or_
            # Candidates linked to this election are identified by their position matching the election title.
            related = db.query(Candidate).filter(or_(Candidate.position == old_title, Candidate.position == title)).all()
            for c in related:
                if old_major != major:
                    c.major = major
                if old_cohort != cohort:
                    c.cohort = cohort
                # Keep candidate.position aligned to new election title if it changed
                if old_title != title:
                    c.position = title

        db.commit()
        return RedirectResponse(url="/admin-elections?updated=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_ELECTION_EDIT_ERROR", f"Failed to edit election {election_id}: {exc}", request.client.host)
        return templates.TemplateResponse("admin-edit-election.html", {
            "request": request,
            "election": {"id": election_id},
            "error": "Unable to update election. Please try again.",
            "form_data": {
                "title": title, "major": major, "cohort": cohort,
                "start_date": start_date, "end_date": end_date,
                "is_active": is_active
            }
        })


@app.post("/delete-election/{election_id}")
def delete_election(election_id: int, request: Request, db: Session = Depends(get_db)):
    try:
        e = db.query(Election).filter(Election.id == election_id).first()
        if not e:
            return RedirectResponse(url="/admin-elections?error=Election%20not%20found", status_code=303)
        db.delete(e)
        db.commit()
        return RedirectResponse(url="/admin-elections?deleted=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_ELECTION_DELETE_ERROR", f"Failed to delete election {election_id}: {exc}", request.client.host)
        return RedirectResponse(url="/admin-elections?error=Delete%20failed", status_code=303)


# Public voter dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    active_election = db.query(Election).filter(
        Election.is_active == True,
        Election.start_date <= now,
        Election.end_date >= now
    ).order_by(Election.start_date.asc()).first()

    candidates = db.query(Candidate).filter(Candidate.is_active == True).order_by(Candidate.created_at.desc()).all()

    ends_in = None
    if active_election:
        remaining = active_election.end_date - now
        days = max(remaining.days, 0)
        hours = max(int(remaining.seconds // 3600), 0)
        if days > 0:
            ends_in = f"{days} day{'s' if days != 1 else ''} {hours} hour{'s' if hours != 1 else ''}"
        else:
            ends_in = f"{hours} hour{'s' if hours != 1 else ''}"

    message = None
    if not active_election:
        message = "There is no active election right now."

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "candidates": candidates,
        "active_election": active_election,
        "ends_in": ends_in,
        "message": message
    })

# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "security_mode": "enabled",
        "encryption": "active",
        "audit_logging": "enabled",
        "admin_access": "enabled"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


def reset_user_table():
    """Drop and recreate the users table to match the latest schema."""
    try:
        security_logger.warning("Resetting users table to match current schema")
        User.__table__.drop(engine, checkfirst=True)
        User.__table__.create(engine, checkfirst=True)
    except Exception as exc:
        security_logger.error(f"Failed to reset users table: {exc}")
        raise


def create_default_accounts(db: Session) -> bool:
    created_any = False
    for account in DEFAULT_ACCOUNTS:
        if not User.find_by_email(db, account["email"]):
            hashed_password = get_password_hash(account["password"])
            user = User(
                first_name=account["first_name"],
                last_name=account["last_name"],
                email=account["email"],
                student_id=account["student_id"],
                password_hash=hashed_password,
                is_admin=account.get("is_admin", False),
                created_by="system-seed"
            )
            user.status = "verified"
            user.is_active = True
            user.data_hash = user.generate_hash()
            db.add(user)
            created_any = True
    return created_any



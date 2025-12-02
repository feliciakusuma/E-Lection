from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, or_, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from ..database import AuditLog, Candidate, CandidateTicket, Election, User, Vote, Admin, get_readonly_db
from ..dependencies import get_db, templates
from ..services.audit import log_security_event, security_logger
from ..utils.counts import get_eligible_voters_count

router = APIRouter()


@router.get("/admin-dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    total_voters = get_eligible_voters_count(db)
    tz_offset = timedelta(hours=7)
    selected_election_id = request.query_params.get("election_id")

    def relative_time(dt: datetime | None) -> str:
        if not dt:
            return ""
        now = datetime.utcnow()
        diff = now - dt
        seconds = diff.total_seconds()
        if seconds < 60:
            return "Just now" if seconds < 5 else f"{int(seconds)} seconds ago"
        minutes = seconds // 60
        if minutes < 60:
            return f"{int(minutes)} minutes ago"
        hours = minutes // 60
        if hours < 24:
            return f"{int(hours)} hours ago"
        days = hours // 24
        return f"{int(days)} days ago"

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

    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    if now.month == 1:
        prev_month_start = datetime(now.year - 1, 12, 1)
    else:
        prev_month_start = datetime(now.year, now.month - 1, 1)

    try:
        this_month_new = (
            db.query(func.count(User.id)).filter(User.created_at >= month_start).scalar()
        ) or 0
        last_month_new = (
            db.query(func.count(User.id)).filter(User.created_at >= prev_month_start, User.created_at < month_start).scalar()
        ) or 0
    except OperationalError:
        this_month_new = (db.execute(text("SELECT COUNT(*) FROM users WHERE created_at >= :ms"), {"ms": month_start}).scalar() or 0)
        last_month_new = (
            db.execute(
                text("SELECT COUNT(*) FROM users WHERE created_at >= :pms AND created_at < :ms"),
                {"pms": prev_month_start, "ms": month_start},
            ).scalar()
            or 0
        )

    if last_month_new == 0:
        voters_growth_pct = 0
    else:
        voters_growth_pct = round(((this_month_new - last_month_new) / last_month_new) * 100)

    # Candidate growth month-over-month
    try:
        this_month_candidates = (
            db.query(func.count(Candidate.id)).filter(Candidate.created_at >= month_start).scalar()
        ) or 0
        last_month_candidates = (
            db.query(func.count(Candidate.id)).filter(Candidate.created_at >= prev_month_start, Candidate.created_at < month_start).scalar()
        ) or 0
    except OperationalError:
        this_month_candidates = (
            db.execute(text("SELECT COUNT(*) FROM candidates WHERE created_at >= :ms"), {"ms": month_start}).scalar() or 0
        )
        last_month_candidates = (
            db.execute(
                text("SELECT COUNT(*) FROM candidates WHERE created_at >= :pms AND created_at < :ms"),
                {"pms": prev_month_start, "ms": month_start},
            ).scalar()
            or 0
        )

    if last_month_candidates == 0:
        candidates_growth_pct = 100 if this_month_candidates > 0 else 0
    elif this_month_candidates == 0:
        # Avoid showing -100% when there are no candidates this month
        candidates_growth_pct = 0
    else:
        candidates_growth_pct = round(((this_month_candidates - last_month_candidates) / last_month_candidates) * 100)

    try:
        active_elections = (
            db.query(Election).filter(Election.is_active == True, Election.start_date <= now, Election.end_date >= now).count()
        )
        ending_today = (
            db.query(Election)
            .filter(
                Election.is_active == True,
                Election.end_date >= datetime(now.year, now.month, now.day),
                Election.end_date < datetime(now.year, now.month, now.day) + timedelta(days=1),
            )
            .count()
        )
    except Exception:
        try:
            active_list = db.query(Election).filter(Election.is_active == True, Election.start_date <= now, Election.end_date >= now).all()
        except Exception:
            active_list = []
        active_elections = len(active_list)
        today_date = now.date()
        ending_today = sum(1 for e in active_list if (e.end_date or now).date() == today_date)

    turnout_pct = round((total_votes / total_voters) * 100, 1) if total_voters > 0 else 0.0

    try:
        pending_users = db.query(func.count(User.id)).filter(User.status == "pending").scalar() or 0
    except OperationalError:
        pending_users = db.execute(text("SELECT COUNT(*) FROM users WHERE status = 'pending'")).scalar() or 0

    try:
        pending_candidates = db.query(func.count(Candidate.id)).filter(Candidate.status == "pending").scalar() or 0
    except OperationalError:
        pending_candidates = db.execute(text("SELECT COUNT(*) FROM candidates WHERE status = 'pending'")).scalar() or 0

    pending_approvals = (pending_users or 0) + (pending_candidates or 0)

    try:
        active_candidates = (
            db.query(Candidate).filter(Candidate.is_active == True).order_by(Candidate.created_at.desc()).limit(3).all()
        )
        for c in active_candidates:
            if getattr(c, "created_at", None):
                try:
                    c.display_created_at = c.created_at + tz_offset
                except Exception:
                    c.display_created_at = c.created_at
    except Exception:
        active_candidates = []

    # Build recent activity stream
    activity_items = []
    try:
        votes_recent = db.query(Vote).order_by(Vote.created_at.desc()).limit(3).all()
        for v in votes_recent:
            try:
                election = db.query(Election).filter(Election.id == v.election_id).first()
                title = election.title if election else "an election"
            except Exception:
                title = "an election"
            ts = getattr(v, "created_at", None)
            activity_items.append(
                {"icon": "fa-vote-yea", "color": "green", "text": f"New vote cast in {title}", "time": relative_time(ts), "ts": ts}
            )
    except Exception:
        pass

    try:
        new_users = db.query(User).order_by(User.created_at.desc()).limit(3).all()
        for u in new_users:
            ts = getattr(u, "created_at", None)
            activity_items.append(
                {
                    "icon": "fa-user-plus",
                    "color": "blue",
                    "text": f"New voter registered: {u.first_name} {u.last_name}",
                    "time": relative_time(ts),
                    "ts": ts,
                }
            )
    except Exception:
        pass

    try:
        new_candidates = db.query(Candidate).order_by(Candidate.created_at.desc()).limit(3).all()
        for c in new_candidates:
            ts = getattr(c, "created_at", None)
            activity_items.append(
                {
                    "icon": "fa-user-tie",
                    "color": "purple",
                    "text": f"New candidate added: {c.full_name}",
                    "time": relative_time(ts),
                    "ts": ts,
                }
            )
    except Exception:
        pass

    # New elections created
    try:
        new_elections = db.query(Election).order_by(Election.created_at.desc()).limit(3).all()
        for e in new_elections:
            ts = getattr(e, "created_at", None) or getattr(e, "start_date", None)
            activity_items.append(
                {
                    "icon": "fa-square-poll-horizontal",
                    "color": "orange",
                    "text": f"New election created: {e.title}",
                    "time": relative_time(ts),
                    "ts": ts,
                }
            )
    except Exception:
        pass

    try:
        now = datetime.utcnow()
        soon_limit = now + timedelta(days=1)
        ending_soon = (
            db.query(Election)
            .filter(Election.end_date != None)  # noqa: E711
            .order_by(Election.end_date.asc())
            .limit(10)
            .all()
        )
        for e in ending_soon:
            ts = getattr(e, "end_date", None)
            if ts and now < ts <= soon_limit:
                activity_items.append(
                    {
                        "icon": "fa-clock",
                        "color": "red",
                        "text": f"Election \"{e.title}\" ends soon",
                        "time": relative_time(ts),
                        "ts": ts,
                    }
                )
    except Exception:
        pass

    activity_items = [a for a in activity_items if a.get("ts")]
    activity_items.sort(key=lambda x: x.get("ts") or datetime.utcnow(), reverse=True)

    try:
        elections = db.query(Election).order_by(Election.start_date.desc()).all()
    except Exception:
        elections = []

    current_election = None
    if elections:
        try:
            sel_id_int = int(selected_election_id) if selected_election_id else None
        except ValueError:
            sel_id_int = None
        if sel_id_int:
            current_election = next((e for e in elections if e.id == sel_id_int), elections[0])
        else:
            current_election = elections[0]

    recent_voters = []
    try:
        recent_users = db.query(User).order_by(User.created_at.desc()).limit(3).all()
        recent_voters = [(u, False) for u in recent_users]
    except Exception:
        recent_voters = []

    # Build chart candidates (ticket names if available, else paired candidates by position)
    chart_candidates = []
    try:
        if current_election:
            tickets = db.query(CandidateTicket).filter(CandidateTicket.election_id == current_election.id).all()
            if tickets:
                for t in tickets:
                    pres = db.query(Candidate).filter(Candidate.id == t.president_candidate_id).first()
                    if not pres:
                        continue
                    vice = (
                        db.query(Candidate).filter(Candidate.id == t.vice_president_candidate_id).first()
                        if t.vice_president_candidate_id
                        else None
                    )
                    name = (getattr(pres, "full_name", "") or "").strip()
                    if vice:
                        name = f"{name} & {getattr(vice, 'full_name', '').strip()}"
                    if not name:
                        continue
                    chart_candidates.append({"full_name": name})
            else:
                candidates = db.query(Candidate).filter(Candidate.position == current_election.title).all()
                for i in range(0, len(candidates), 2):
                    pres = candidates[i]
                    vice = candidates[i + 1] if i + 1 < len(candidates) else None
                    name = getattr(pres, "full_name", f"Candidate {pres.id}")
                    if vice:
                        name = f"{name} & {getattr(vice, 'full_name', f'Candidate {vice.id}')}"
                    chart_candidates.append({"full_name": name})
    except Exception:
        chart_candidates = chart_candidates or []

    return templates.TemplateResponse(
        "admin-dashboard.html",
        {
            "request": request,
            "stats": {
                "total_voters": total_voters,
                "total_candidates": total_candidates,
                "total_elections": total_elections,
                "total_votes": total_votes,
                "voters_growth_pct": voters_growth_pct,
                "candidates_growth_pct": candidates_growth_pct,
                "active_elections": active_elections,
                "ending_today": ending_today,
                "turnout_pct": turnout_pct,
                "pending_approvals": pending_approvals,
            },
            "active_candidates": active_candidates,
            "chart_candidates": chart_candidates,
            "elections": elections,
            "recent_voters": recent_voters,
            "recent_activity": activity_items,
            "current_election": current_election,
        },
    )


@router.get("/admin-voters", response_class=HTMLResponse)
def admin_voters(request: Request, db: Session = Depends(get_db)):
    tz_offset = timedelta(hours=7)
    q = (request.query_params.get("q", "") or "").strip()
    sf = (request.query_params.get("status", "all") or "all").lower()
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
    # Vote linkage is anonymized; we cannot reliably map to users, so skip vote filters.
    voters = query.order_by(User.created_at.desc()).all() if hasattr(User, "created_at") else query.all()
    voter_rows = []
    for v in voters:
        has_voted = False
        if getattr(v, "created_at", None):
            try:
                v.display_created_at = v.created_at + tz_offset
            except Exception:
                v.display_created_at = v.created_at
        voter_rows.append((v, has_voted))

    return templates.TemplateResponse(
        "admin-voters.html",
        {"request": request, "voters": voter_rows, "status_filter": sf, "success": None, "error": None},
    )


@router.get("/voters", response_class=HTMLResponse)
def voters_page(request: Request, db: Session = Depends(get_db)):
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
    return templates.TemplateResponse("admin-voters.html", {"request": request, "voters": voters})


@router.get("/admin-results", response_class=HTMLResponse)
def admin_results(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse(url="/admin-elections", status_code=302)


@router.get("/admin-settings", response_class=HTMLResponse)
def admin_settings(request: Request, db: Session = Depends(get_db)):
    email_cookie = request.cookies.get("user_email")
    admin = db.query(Admin).filter(Admin.email == email_cookie).first() if email_cookie else None
    return templates.TemplateResponse(
        "admin-settings.html",
        {
            "request": request,
            "admin": admin,
            "saved": request.query_params.get("saved"),
            "error": None if admin else "Admin not found" if email_cookie else None,
        },
    )


@router.post("/admin-settings")
def admin_settings_save(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    db: Session = Depends(get_db),
):
    email_cookie = request.cookies.get("user_email")
    if not email_cookie:
        return RedirectResponse(url="/admin", status_code=302)

    admin_row = db.query(Admin).filter(Admin.email == email_cookie).first()
    if not admin_row:
        return RedirectResponse(url="/admin", status_code=302)

    admin_row.full_name = full_name.strip()
    admin_row.email = email.strip().lower()
    db.commit()

    # Update cookies to reflect new info
    response = RedirectResponse(url="/admin-settings?saved=1", status_code=303)
    try:
        response.set_cookie("user_email", admin_row.email, httponly=False)
        response.set_cookie("full_name", admin_row.full_name, httponly=False)
        # best-effort split for display names
        parts = admin_row.full_name.split(" ", 1)
        first = parts[0] if parts else ""
        last = parts[1] if len(parts) > 1 else ""
        response.set_cookie("first_name", first, httponly=False)
        response.set_cookie("last_name", last, httponly=False)
    except Exception:
        pass
    return response


@router.get("/audit-log")
def get_audit_log(db=Depends(get_readonly_db)):
    try:
        logs = (
            db.query(AuditLog)
            .filter(AuditLog.action.in_(["LOGIN_SUCCESS", "REGISTRATION_SUCCESS", "VOTE_CAST"]))
            .order_by(AuditLog.timestamp.desc())
            .limit(100)
            .all()
        )

        return [
            {
                "timestamp": log.timestamp,
                "action": log.action,
                "table_name": log.table_name,
                "is_authorized": log.is_authorized,
            }
            for log in logs
        ]

    except Exception as exc:
        security_logger.error(f"Audit log access error: {exc}")
        raise

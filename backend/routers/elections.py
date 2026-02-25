import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_, func
from sqlalchemy.orm import Session
from uuid import UUID

from ..database import Candidate, CandidateTicket, Election, Vote, SessionLocal, User
from ..dependencies import get_db, templates
from ..services.audit import log_security_event
from ..utils.counts import get_eligible_voters_count
from ..utils.validation import MAJOR_CODE_MAP
from ..utils.csrf import validate_csrf
from ..utils.cookies import get_signed_cookie

router = APIRouter()
_VOTED_ELECTIONS_COOKIE = "voted_elections"


@router.get("/dashboard", response_class=HTMLResponse)
def public_dashboard(request: Request, db: Session = Depends(get_db)):
    def slugify(val: str | None, fallback: str) -> str:
        if not val:
            return fallback
        slug = val.strip().lower().replace(" ", "-")
        return slug or fallback

    def derive_user_meta():
        email_cookie = request.cookies.get("user_email")
        if not email_cookie:
            return None, None
        user = User.find_by_email(db, email_cookie)
        if not user:
            return None, None
        sid = (user.student_id or "").strip()
        cohort = sid[:4] if len(sid) >= 4 and sid[:4].isdigit() else None
        major_code = sid[4:6] if len(sid) >= 6 and sid[4:6].isdigit() else None
        major_name = MAJOR_CODE_MAP.get(major_code) if major_code else None
        return major_name, cohort
    def current_user_profile():
        email_cookie = request.cookies.get("user_email")
        if not email_cookie:
            return None
        user = User.find_by_email(db, email_cookie)
        if not user:
            return None
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        return {
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "full_name": full_name or user.email,
        }

    def election_matches_user(e: Election, user_major: str | None, user_cohort: str | None) -> bool:
        try:
            meta = json.loads(e.description) if e.description and str(e.description).strip().startswith("{") else {}
        except Exception:
            meta = {}
        meta_major = meta.get("major")
        raw_cohort = meta.get("cohort")
        # Support multiple cohorts stored as comma-separated string or list
        meta_cohorts: list[str] = []
        if raw_cohort is not None:
            if isinstance(raw_cohort, list):
                meta_cohorts = [str(c).strip() for c in raw_cohort if str(c).strip()]
            else:
                meta_cohorts = [c.strip() for c in str(raw_cohort).split(",") if c.strip()]
        meta_cohort = meta_cohorts[0] if len(meta_cohorts) == 1 else None
        if meta_major:
            majors = [m.strip() for m in str(meta_major).split(",") if m.strip()]
            has_all_major = any(m.lower() in {"all", "all majors", "all major"} for m in majors)
            if not has_all_major:
                if user_major and user_major not in majors:
                    return False
        # If cohort is declared, respect it unless it's marked as open/all
        if meta_cohorts:
            if any(str(c).lower() in {"all", "all cohort", "all cohorts"} for c in meta_cohorts):
                pass
            elif user_cohort and user_cohort not in meta_cohorts:
                return False
        return True

    user_major, user_cohort = derive_user_meta()
    user_profile = current_user_profile()
    now = datetime.utcnow()
    tz_offset = timedelta(hours=7)

    # pick first eligible ongoing election
    active_election = None
    try:
        ongoing = (
            db.query(Election)
            .filter(Election.is_active == True, Election.start_date <= now, Election.end_date >= now)
            .order_by(Election.start_date.asc())
            .all()
        )
        for e in ongoing:
            if election_matches_user(e, user_major, user_cohort):
                try:
                    if e.start_date:
                        e.display_start = e.start_date + tz_offset
                    if e.end_date:
                        e.display_end = e.end_date + tz_offset
                except Exception:
                    pass
                active_election = e
                break
    except Exception:
        active_election = None

    candidates = db.query(Candidate).filter(Candidate.is_active == True).order_by(Candidate.created_at.desc()).all()
    for c in candidates:
        if getattr(c, "created_at", None):
            try:
                c.display_created_at = c.created_at + tz_offset
            except Exception:
                c.display_created_at = c.created_at

    elections = []
    try:
        all_elections = db.query(Election).filter(Election.is_active == True).order_by(Election.start_date.asc()).all()
        for e in all_elections:
            if not election_matches_user(e, user_major, user_cohort):
                continue
            status = "upcoming"
            if e.start_date and e.end_date:
                if e.start_date <= now <= e.end_date:
                    status = "ongoing"
                elif now > e.end_date:
                    status = "ended"
            # Count distinct valid ticket presidents to avoid duplicate/orphan ticket inflation.
            try:
                candidates_count = (
                    db.query(func.count(func.distinct(CandidateTicket.president_candidate_id)))
                    .join(Candidate, Candidate.id == CandidateTicket.president_candidate_id)
                    .filter(
                        CandidateTicket.election_id == e.id,
                        Candidate.is_active == True,
                    )
                    .scalar()
                    or 0
                )
                if candidates_count == 0:
                    # Fallback to individual candidates tied to the election title
                    candidates_count = (
                        db.query(Candidate)
                        .filter(Candidate.position == e.title, Candidate.is_active == True)
                        .count()
                    )
            except Exception:
                candidates_count = 0
            disp_start = (e.start_date + tz_offset) if e.start_date else None
            disp_end = (e.end_date + tz_offset) if e.end_date else None
            elections.append(
                {
                    "election": e,
                    "status": status,
                    "candidates_count": candidates_count,
                    "user_has_voted": False,
                    "results_published": (status == "ended"),
                    "display_start": disp_start,
                    "display_end": disp_end,
                }
            )
    except Exception:
        elections = []

    ends_in = None
    if active_election:
        try:
            if active_election.start_date:
                active_election.display_start = active_election.start_date + tz_offset
            if active_election.end_date:
                active_election.display_end = active_election.end_date + tz_offset
        except Exception:
            pass
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

    # Mark elections as voted for the logged-in user (so the UI shows "View Results" instead of "Vote Now")
    try:
        user_email = request.cookies.get("user_email")
        user_obj = User.find_by_email(db, user_email) if user_email else None
        if user_obj and elections:
            data = get_signed_cookie(request, _VOTED_ELECTIONS_COOKIE, default=[])
            voted_ids = {str(x) for x in data} if isinstance(data, list) else set()
            for entry in elections:
                if str(entry["election"].id) in voted_ids:
                    entry["user_has_voted"] = True
    except Exception:
        pass

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "candidates": candidates,
            "active_election": active_election,
            "ends_in": ends_in,
            "message": message,
            "elections": elections,
            "page_title": f"dashboard/{slugify(user_major, 'all-majors')}/{slugify(user_cohort, 'all-cohorts')}",
            "user_profile": user_profile,
        },
    )


@router.get("/admin-elections", response_class=HTMLResponse)
def admin_elections(request: Request, db: Session = Depends(get_db)):
    def meta_offset(e: Election):
        try:
            if e.description and str(e.description).strip().startswith("{"):
                meta = json.loads(e.description)
                return int(meta.get("tz_offset_minutes", 0))
        except Exception:
            return None
        return None

    server_offset_minutes = int(round((datetime.now() - datetime.utcnow()).total_seconds() / 60))

    def derive_status(e: Election) -> str:
        offset = meta_offset(e)
        now = datetime.utcnow()
        start_utc = e.start_date
        end_utc = e.end_date
        if offset is None:
            if start_utc:
                start_utc = start_utc - timedelta(minutes=server_offset_minutes)
            if end_utc:
                end_utc = end_utc - timedelta(minutes=server_offset_minutes)
        if start_utc and now < start_utc:
            return "upcoming"
        if end_utc and now > end_utc:
            return "ended"
        return "ongoing"

    status_filter = request.query_params.get("status", "all").lower()
    q = (request.query_params.get("q", "") or "").strip()
    elections_q = db.query(Election)
    if q:
        elections_q = elections_q.filter(Election.title.like(f"%{q}%"))
    elections = elections_q.order_by(Election.start_date.desc()).all()

    payload = []
    now = datetime.utcnow()
    for e in elections:
        tz_meta = meta_offset(e)
        start_for_calc = e.start_date
        end_for_calc = e.end_date
        eligible_voters = get_eligible_voters_count(db)
        try:
            if e.description and str(e.description).strip().startswith("{"):
                meta = json.loads(e.description)
                if meta.get("eligible_voters") is not None:
                    eligible_voters = int(meta.get("eligible_voters") or 0)
        except Exception:
            pass
        if tz_meta is None:
            if start_for_calc:
                start_for_calc = start_for_calc - timedelta(minutes=server_offset_minutes)
            if end_for_calc:
                end_for_calc = end_for_calc - timedelta(minutes=server_offset_minutes)

        dstatus = derive_status(e)

        votes_q = db.query(Vote).filter(Vote.election_id == e.id)
        votes = votes_q.all()
        votes_cast = len(votes)

        # Count distinct valid ticket presidents to avoid duplicate/orphan ticket inflation.
        candidates_count = (
            db.query(func.count(func.distinct(CandidateTicket.president_candidate_id)))
            .join(Candidate, Candidate.id == CandidateTicket.president_candidate_id)
            .filter(
                CandidateTicket.election_id == e.id,
                Candidate.is_active == True,
            )
            .scalar()
            or 0
        )
        if candidates_count == 0:
            candidates_count = (
                db.query(Candidate)
                .filter(Candidate.position == e.title, Candidate.is_active == True)
                .count()
            )
        # Count voters for this election only. Prefer unique voter ids from ballot payload;
        # fallback to vote count when voter ids are unavailable (legacy/redis key expiry).
        unique_voter_ids = set()
        for vote in votes:
            try:
                voter_id = getattr(vote, "voter_id_plain", "") or ""
                if voter_id:
                    unique_voter_ids.add(str(voter_id))
            except Exception:
                continue
        voters_count = len(unique_voter_ids) if unique_voter_ids else votes_cast

        if status_filter != "all" and dstatus != status_filter:
            continue

        starts_in_days = 0
        if dstatus == "upcoming" and start_for_calc:
            starts_in_days = max((start_for_calc - now).days, 0)

        start_iso = ""
        end_iso = ""
        if start_for_calc:
            start_iso = start_for_calc.isoformat() + ("Z" if tz_meta is not None else "")
        if end_for_calc:
            end_iso = end_for_calc.isoformat() + ("Z" if tz_meta is not None else "")

        payload.append(
            {
                "election": e,
                "status": dstatus,
                "votes_cast": votes_cast,
                "candidates_count": candidates_count,
                "voters_count": voters_count,
                "eligible_voters": eligible_voters,
                "starts_in_days": starts_in_days,
                "start_iso": start_iso,
                "end_iso": end_iso,
            }
        )

    return templates.TemplateResponse(
        "admin-elections.html", {"request": request, "status_filter": status_filter, "elections_payload": payload}
    )


@router.get("/add-election", response_class=HTMLResponse)
def add_election_form(request: Request):
    db = SessionLocal()
    eligible_voters = get_eligible_voters_count(db)
    db.close()
    return templates.TemplateResponse(
        "admin-add-election.html", {"request": request, "form_data": {}, "eligible_voters": eligible_voters}
    )


@router.post("/add-election", response_class=HTMLResponse)
def add_election_submit(
    request: Request,
    title: str = Form(...),
    major: str = Form(...),
    cohort: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    is_active: bool = Form(False),
    eligible_voters: int = Form(0),
    timezone_offset_minutes: int = Form(0),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    try:
        offset_minutes = int(timezone_offset_minutes or 0)

        if not (major or "").strip() or not (cohort or "").strip():
            missing_field = "Major" if not (major or "").strip() else "Cohort"
            return templates.TemplateResponse(
                "admin-add-election.html",
                {
                    "request": request,
                    "error": f"Please fill out the {missing_field} field.",
                    "form_data": {
                        "title": title,
                        "major": major,
                        "cohort": cohort,
                        "start_date": start_date,
                        "end_date": end_date,
                        "is_active": is_active,
                        "eligible_voters": eligible_voters,
                        "timezone_offset_minutes": timezone_offset_minutes,
                    },
                },
            )

        def parse_dt(val: str) -> datetime:
            return datetime.strptime(val, "%Y-%m-%dT%H:%M")

        sdt_local = parse_dt(start_date)
        edt_local = parse_dt(end_date)
        sdt = sdt_local - timedelta(minutes=offset_minutes)
        edt = edt_local - timedelta(minutes=offset_minutes)
        if edt <= sdt:
            return templates.TemplateResponse(
                "admin-add-election.html",
                {
                    "request": request,
                    "error": "End date must be after start date",
                    "form_data": {
                        "title": title,
                        "major": major,
                        "cohort": cohort,
                        "start_date": start_date,
                        "end_date": end_date,
                        "is_active": is_active,
                    },
                },
            )

        meta = {"major": major, "cohort": cohort, "tz_offset_minutes": offset_minutes, "eligible_voters": int(eligible_voters or 0)}
        e = Election(
            title=title,
            description=json.dumps(meta),
            start_date=sdt,
            end_date=edt,
            status="upcoming",
            is_active=is_active,
        )
        db.add(e)
        db.commit()
        return RedirectResponse(url="/admin-elections?success=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_ELECTION_ADD_ERROR", f"Failed to add election: {exc}", request.client.host)
        return templates.TemplateResponse(
            "admin-add-election.html",
            {
                "request": request,
                "error": "Unable to save election. Please try again.",
                "form_data": {
                    "title": title,
                    "major": major,
                    "cohort": cohort,
                    "start_date": start_date,
                    "end_date": end_date,
                    "is_active": is_active,
                    "eligible_voters": eligible_voters,
                    "timezone_offset_minutes": timezone_offset_minutes,
                },
            },
        )


@router.get("/edit-election/{election_id}", response_class=HTMLResponse)
def edit_election_form(request: Request, election_id: UUID, db: Session = Depends(get_db)):
    e = db.query(Election).filter(Election.id == election_id).first()
    if not e:
        return RedirectResponse(url="/admin-elections?error=Election%20not%20found", status_code=303)

    major = cohort = ""
    tz_offset_minutes = 0
    eligible_voters = get_eligible_voters_count(db)
    try:
        meta = json.loads(e.description) if e.description and e.description.strip().startswith("{") else {}
        major = meta.get("major", "")
        cohort = meta.get("cohort", "")
        tz_offset_minutes = int(meta.get("tz_offset_minutes", 0) or 0)
        if meta.get("eligible_voters") is not None:
            eligible_voters = int(meta.get("eligible_voters") or 0)
    except Exception:
        pass

    server_offset_minutes = int(round((datetime.now() - datetime.utcnow()).total_seconds() / 60))

    def derive_status(obj: Election) -> str:
        now = datetime.utcnow()
        start_utc = obj.start_date
        end_utc = obj.end_date
        if start_utc and end_utc is not None and tz_offset_minutes == 0 and obj.description and "tz_offset_minutes" in str(obj.description):
            pass
        elif tz_offset_minutes is None or tz_offset_minutes == 0:
            if start_utc:
                start_utc = start_utc - timedelta(minutes=server_offset_minutes)
            if end_utc:
                end_utc = end_utc - timedelta(minutes=server_offset_minutes)
        if start_utc and now < start_utc:
            return "upcoming"
        if end_utc and now > end_utc:
            return "ended"
        return "ongoing"

    def fmt_dt_local(dt: datetime | None) -> str:
        if not dt:
            return ""
        local_dt = dt + timedelta(minutes=tz_offset_minutes)
        return local_dt.strftime("%Y-%m-%dT%H:%M")

    return templates.TemplateResponse(
        "admin-edit-election.html",
        {
            "request": request,
            "election": e,
            "form_data": {
                "title": e.title,
                "major": major,
                "cohort": cohort,
                "start_date": fmt_dt_local(e.start_date),
                "end_date": fmt_dt_local(e.end_date),
                "is_active": e.is_active,
                "timezone_offset_minutes": tz_offset_minutes,
            },
            "status_display": derive_status(e),
            "eligible_voters": eligible_voters,
        },
    )


@router.post("/edit-election/{election_id}")
def edit_election_submit(
    request: Request,
    election_id: UUID,
    title: str = Form(...),
    major: str = Form(...),
    cohort: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    is_active: bool = Form(False),
    eligible_voters: int = Form(0),
    timezone_offset_minutes: int = Form(0),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    try:
        e = db.query(Election).filter(Election.id == election_id).first()
        if not e:
            return RedirectResponse(url="/admin-elections?error=Election%20not%20found", status_code=303)

        offset_minutes = int(timezone_offset_minutes or 0)

        if not (major or "").strip() or not (cohort or "").strip():
            missing_field = "Major" if not (major or "").strip() else "Cohort"
            return templates.TemplateResponse(
                "admin-edit-election.html",
                {
                    "request": request,
                    "error": f"Please fill out the {missing_field} field.",
                    "form_data": {
                        "title": title,
                        "major": major,
                        "cohort": cohort,
                        "start_date": start_date,
                        "end_date": end_date,
                        "is_active": is_active,
                        "eligible_voters": eligible_voters,
                        "timezone_offset_minutes": timezone_offset_minutes,
                    },
                },
            )

        old_title = e.title
        old_major = None
        old_cohort = None
        try:
            prev_meta = json.loads(e.description) if e.description and str(e.description).strip().startswith("{") else {}
            old_major = prev_meta.get("major")
            old_cohort = prev_meta.get("cohort")
        except Exception:
            pass

        sdt_local = datetime.strptime(start_date, "%Y-%m-%dT%H:%M")
        edt_local = datetime.strptime(end_date, "%Y-%m-%dT%H:%M")
        sdt = sdt_local - timedelta(minutes=offset_minutes)
        edt = edt_local - timedelta(minutes=offset_minutes)
        if edt <= sdt:
            return templates.TemplateResponse(
                "admin-edit-election.html",
                {
                    "request": request,
                    "election": e,
                    "error": "End date must be after start date",
                    "form_data": {
                        "title": title,
                        "major": major,
                        "cohort": cohort,
                        "start_date": start_date,
                        "end_date": end_date,
                        "is_active": is_active,
                        "eligible_voters": eligible_voters,
                        "timezone_offset_minutes": timezone_offset_minutes,
                    },
                },
            )

        e.title = title
        e.description = json.dumps(
            {"major": major, "cohort": cohort, "tz_offset_minutes": offset_minutes, "eligible_voters": int(eligible_voters or 0)}
        )
        e.start_date = sdt
        e.end_date = edt
        e.is_active = is_active
        now = datetime.utcnow()
        e.status = "upcoming" if now < sdt else ("ended" if now > edt else "ongoing")

        propagate = (old_major != major) or (old_cohort != cohort) or (old_title != title)
        if propagate:
            # Avoid DB errors on fixed-length fields when propagating updates.
            safe_major = major[:100] if major else major
            safe_cohort = cohort[:20] if cohort else cohort
            related = db.query(Candidate).filter(or_(Candidate.position == old_title, Candidate.position == title)).all()
            for c in related:
                if old_title != title:
                    c.position = title

        db.commit()
        return RedirectResponse(url="/admin-elections?updated=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_ELECTION_EDIT_ERROR", f"Failed to edit election {election_id}: {exc}", request.client.host)
        return templates.TemplateResponse(
            "admin-edit-election.html",
            {
                "request": request,
                "election": {"id": election_id},
                "error": "Unable to update election. Please try again.",
                "form_data": {
                    "title": title,
                    "major": major,
                    "cohort": cohort,
                    "start_date": start_date,
                    "end_date": end_date,
                    "is_active": is_active,
                },
            },
        )


@router.post("/delete-election/{election_id}")
def delete_election(
    election_id: UUID,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    try:
        e = db.query(Election).filter(Election.id == election_id).first()
        if not e:
            return RedirectResponse(url="/admin-elections?error=Election%20not%20found", status_code=303)
        # Remove related candidates/tickets for this election to keep data in sync.
        try:
            db.query(CandidateTicket).filter(CandidateTicket.election_id == election_id).delete()
            db.query(Candidate).filter(Candidate.position == e.title).delete()
        except Exception:
            pass
        db.delete(e)
        db.commit()
        return RedirectResponse(url="/admin-elections?deleted=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_ELECTION_DELETE_ERROR", f"Failed to delete election {election_id}: {exc}", request.client.host)
        return RedirectResponse(url="/admin-elections?error=Delete%20failed", status_code=303)

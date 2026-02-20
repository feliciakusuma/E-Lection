from __future__ import annotations

import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from uuid import UUID

from ..database import Candidate, Election, User, CandidateTicket, Cohort, Major
from ..dependencies import get_db, templates
from ..services.audit import log_security_event, security_logger
from ..utils.validation import MAJOR_CODE_MAP
from ..utils.csrf import validate_csrf
from ..utils.cookies import get_signed_cookie

router = APIRouter()
_VOTED_ELECTIONS_COOKIE = "voted_elections"

@router.get("/candidates", response_class=HTMLResponse)
def candidates_page(request: Request, db: Session = Depends(get_db)):
    """Render candidates for a specific election (via election_id) or the current active one."""
    election_id_param = (request.query_params.get("election_id", "") or "").strip()
    user_obj: User | None = None

    def derive_user_meta():
        email_cookie = request.cookies.get("user_email")
        if not email_cookie:
            return None, None
        nonlocal user_obj
        user = User.find_by_email(db, email_cookie)
        user_obj = user
        if not user:
            return None, None
        sid = (user.student_id or "").strip()
        cohort = sid[:4] if len(sid) >= 4 and sid[:4].isdigit() else None
        major_code = sid[4:6] if len(sid) >= 6 and sid[4:6].isdigit() else None
        major_name = MAJOR_CODE_MAP.get(major_code) if major_code else None
        return major_name, cohort

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
    majors_map = {m.major_id: m for m in db.query(Major).all()}
    cohorts_map = {c.cohort_id: c for c in db.query(Cohort).all()}

    active_election = None
    active_status = None
    if election_id_param:
        try:
            active_election = db.query(Election).filter(Election.id == UUID(election_id_param)).first()
        except (ValueError, TypeError):
            active_election = None
    if not active_election:
        now = datetime.utcnow()
        active_election = (
            db.query(Election)
            .filter(Election.is_active == True, Election.start_date <= now, Election.end_date >= now)
            .order_by(Election.start_date.asc())
            .first()
        )

    if active_election:
        if not election_matches_user(active_election, user_major, user_cohort):
            return RedirectResponse(url="/dashboard?error=Election%20not%20available%20for%20your%20group", status_code=303)

        server_offset_minutes = int(round((datetime.now() - datetime.utcnow()).total_seconds() / 60))

        def meta_offset(e: Election) -> int | None:
            try:
                if e.description and str(e.description).strip().startswith("{"):
                    meta = json.loads(e.description)
                    return int(meta.get("tz_offset_minutes", 0) or 0)
            except Exception:
                return None
            return None

        offset = meta_offset(active_election)
        start_utc = active_election.start_date
        end_utc = active_election.end_date
        if offset is None:
            if start_utc:
                start_utc = start_utc - timedelta(minutes=server_offset_minutes)
            if end_utc:
                end_utc = end_utc - timedelta(minutes=server_offset_minutes)

        now = datetime.utcnow()
        if start_utc and now < start_utc:
            active_status = "upcoming"
        elif end_utc and now > end_utc:
            active_status = "ended"
        else:
            active_status = "ongoing"
        active_election.status = active_status
        # Provide display-adjusted timestamps for templates (UTC+7 to match other dashboards).
        try:
            tz_offset = timedelta(hours=7)
            base_start = start_utc if start_utc else active_election.start_date
            base_end = end_utc if end_utc else active_election.end_date
            active_election.display_start = base_start + tz_offset if base_start else None
            active_election.display_end = base_end + tz_offset if base_end else None
        except Exception:
            pass

    def has_voted(user: User | None, election_id: UUID | None) -> bool:
        if not user or not election_id:
            return False
        data = get_signed_cookie(request, _VOTED_ELECTIONS_COOKIE, default=[])
        if isinstance(data, list):
            return str(election_id) in {str(x) for x in data if x is not None}
        return False

    if active_election and has_voted(user_obj, active_election.id):
        return RedirectResponse(url=f"/results/{active_election.id}", status_code=303)

    query = db.query(Candidate).filter(Candidate.is_active == True)
    candidates = []
    if active_election:
        ticket_rows = (
            db.query(CandidateTicket)
            .filter(CandidateTicket.election_id == active_election.id)
            .all()
        )
        cand_ids = []
        for t in ticket_rows:
            if t.president_candidate_id:
                cand_ids.append(t.president_candidate_id)
            if t.vice_president_candidate_id:
                cand_ids.append(t.vice_president_candidate_id)
        if cand_ids:
            candidates = (
                query.filter(Candidate.id.in_(cand_ids))
                .order_by(Candidate.created_at.desc())
                .all()
            )
        else:
            candidates = (
                query.filter(Candidate.position == active_election.title)
                .order_by(Candidate.created_at.desc())
                .all()
            )
    else:
        candidates = query.order_by(Candidate.created_at.desc()).all()

    # Attach vice details and hide standalone vice rows
    tickets_q = db.query(CandidateTicket)
    if active_election:
        tickets_q = tickets_q.filter(
            or_(
                CandidateTicket.election_id == active_election.id,
                CandidateTicket.election_id == None,  # noqa: E711
            )
        )
    tickets = tickets_q.all()
    vice_ids = {t.vice_president_candidate_id for t in tickets if t.vice_president_candidate_id}
    candidates = [c for c in candidates if c.id not in vice_ids]

    ticket_by_pres = {t.president_candidate_id: t for t in tickets if t.president_candidate_id}
    vice_map = {}
    if vice_ids:
        vice_rows = db.query(Candidate).filter(Candidate.id.in_(list(vice_ids))).all()
        vice_map = {v.id: v for v in vice_rows}

    def derive_major_and_cohort(student_id: str | None, major_id: UUID | None, cohort_id: UUID | None, meta_major=None, meta_cohort=None):
        sid = (student_id or "").strip()
        major_val = meta_major
        cohort_val = meta_cohort

        if major_id and major_id in majors_map:
            major_val = majors_map[major_id].major_name
        elif sid.isdigit() and len(sid) >= 6:
            major_val = MAJOR_CODE_MAP.get(sid[4:6], major_val)

        if cohort_id and cohort_id in cohorts_map:
            cohort_val = str(cohorts_map[cohort_id].cohort_num)
        elif sid.isdigit() and len(sid) >= 4:
            cohort_val = sid[:4] if sid[:4].isdigit() else cohort_val

        return major_val, cohort_val
    for c in candidates:
        t = ticket_by_pres.get(c.id)
        vice_obj = vice_map.get(t.vice_president_candidate_id) if t and t.vice_president_candidate_id else None
        c.vice_full_name = getattr(vice_obj, "full_name", "")
        c.vice_student_id = getattr(vice_obj, "student_id", "")

        # Derive display major/cohort from candidate data (not election meta)
        disp_major, disp_cohort = derive_major_and_cohort(c.student_id, c.major_id, c.cohort_id, None, None)
        c.display_major = disp_major or "-"
        c.display_cohort = disp_cohort or "-"
        c.major = c.display_major
        c.cohort = c.display_cohort

        if vice_obj:
            v_major, v_cohort = derive_major_and_cohort(
                vice_obj.student_id, vice_obj.major_id, vice_obj.cohort_id, None, None
            )
            c.vice_display_major = v_major or "-"
            c.vice_display_cohort = v_cohort or "-"
        else:
            c.vice_display_major = "-"
            c.vice_display_cohort = "-"

        c.vice_major = c.vice_display_major
        c.vice_cohort = c.vice_display_cohort

    return templates.TemplateResponse(
        "candidate.html",
        {"request": request, "candidates": candidates, "active_election": active_election, "active_status": active_status},
    )


@router.get("/admin-candidates", response_class=HTMLResponse)
def admin_candidates(request: Request, db: Session = Depends(get_db)):
    tz_offset = timedelta(hours=7)
    q = (request.query_params.get("q", "") or "").strip()
    def _safe_int(val, default):
        try:
            return int(val)
        except Exception:
            return default
    page = max(_safe_int(request.query_params.get("page", 1) or 1, 1), 1)
    page_size = 7
    offset = (page - 1) * page_size
    page = max(int(request.query_params.get("page", 1) or 1), 1)
    page_size = 7
    offset = (page - 1) * page_size
    status_filter = (request.query_params.get("status", "all") or "all").lower()
    election_id_param = (request.query_params.get("election_id", "") or "").strip()

    query = db.query(Candidate)
    majors_map = {m.major_id: m for m in db.query(Major).all()}
    cohorts_map = {c.cohort_id: c for c in db.query(Cohort).all()}

    def derive_major_and_cohort(student_id: str | None, major_id: UUID | None, cohort_id: UUID | None, meta_major=None, meta_cohort=None):
        sid = (student_id or "").strip()
        major_val = meta_major
        cohort_val = meta_cohort
        if major_id and major_id in majors_map:
            major_val = majors_map[major_id].major_name
        elif sid.isdigit() and len(sid) >= 6:
            major_val = MAJOR_CODE_MAP.get(sid[4:6], major_val)
        if cohort_id and cohort_id in cohorts_map:
            cohort_val = str(cohorts_map[cohort_id].cohort_num)
        elif sid.isdigit() and len(sid) >= 4:
            cohort_val = sid[:4] if sid[:4].isdigit() else cohort_val
        return major_val, cohort_val

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Candidate.full_name.like(like),
                Candidate.student_id.like(like),
                Candidate.position.like(like),
            )
        )

    if status_filter != "all":
        query = query.filter(Candidate.status == status_filter)

    selected_election_id = None
    if election_id_param.isdigit():
        election = db.query(Election).filter(Election.id == UUID(election_id_param)).first()
        if election:
            selected_election_id = election.id
            ticket_rows = db.query(CandidateTicket).filter(CandidateTicket.election_id == election.id).all()
            cand_ids = []
            for t in ticket_rows:
                if t.president_candidate_id:
                    cand_ids.append(t.president_candidate_id)
                if t.vice_president_candidate_id:
                    cand_ids.append(t.vice_president_candidate_id)
            if cand_ids:
                query = query.filter(Candidate.id.in_(cand_ids))
            else:
                query = query.filter(Candidate.position == election.title)

    tickets = db.query(CandidateTicket).all()
    vice_ids = {t.vice_president_candidate_id for t in tickets if t.vice_president_candidate_id}
    total_count = query.count()
    candidates = (
        query.order_by(Candidate.created_at.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )
    for c in candidates:
        raw_ts = getattr(c, "updated_at", None) or getattr(c, "created_at", None)
        if raw_ts:
            try:
                display_ts = raw_ts + tz_offset
            except Exception:
                display_ts = raw_ts
            c.last_updated_str = display_ts.strftime("%b %d, %Y %H:%M")
        else:
            c.last_updated_str = "-"
    # Hide standalone vice rows; we will render them under their president
    candidates = [c for c in candidates if c.id not in vice_ids]

    # Attach vice details to president objects for template rendering
    ticket_by_pres = {t.president_candidate_id: t for t in tickets if t.president_candidate_id}
    vice_map = {}
    if vice_ids:
        vice_rows = db.query(Candidate).filter(Candidate.id.in_(list(vice_ids))).all()
        vice_map = {v.id: v for v in vice_rows}
    for c in candidates:
        t = ticket_by_pres.get(c.id)
        vice_obj = vice_map.get(t.vice_president_candidate_id) if t and t.vice_president_candidate_id else None
        major_val, cohort_val = derive_major_and_cohort(c.student_id, c.major_id, c.cohort_id, None, None)
        c.major = major_val or "-"
        c.cohort = cohort_val or "-"
        c.vice_full_name = getattr(vice_obj, "full_name", "")
        c.vice_student_id = getattr(vice_obj, "student_id", "")
        if vice_obj:
            v_major, v_cohort = derive_major_and_cohort(
                vice_obj.student_id, vice_obj.major_id, vice_obj.cohort_id, None, None
            )
            c.vice_major = v_major or "-"
            c.vice_cohort = v_cohort or "-"
        else:
            c.vice_major = "-"
            c.vice_cohort = "-"
    elections = db.query(Election).order_by(Election.start_date.desc()).all()

    total_pages = (total_count + page_size - 1) // page_size if total_count else 1

    return templates.TemplateResponse(
        "admin-candidates.html",
        {
            "request": request,
            "candidates": candidates,
            "elections": elections,
            "status_filter": status_filter,
            "q": q,
            "selected_election_id": selected_election_id,
            "total_count": total_count,
            "page": page,
            "total_pages": total_pages,
        },
    )


@router.get("/admin-add-candidate", response_class=HTMLResponse)
def admin_add_candidate_form(request: Request, db: Session = Depends(get_db)):
    elections = db.query(Election).order_by(Election.start_date.desc()).all()
    return templates.TemplateResponse(
        "admin-add-candidate.html", {"request": request, "elections": elections, "form_data": {}, "error": None}
    )


@router.post("/admin-add-candidate", response_class=HTMLResponse)
def admin_add_candidate_submit(
    request: Request,
    full_name: str = Form(...),
    student_id: str = Form(...),
    major: str = Form(""),
    cohort: str = Form(""),
    position: str = Form(...),
    status: str = Form("pending"),
    vice_full_name: str = Form(""),
    vice_student_id: str = Form(""),
    vice_major: str = Form(""),
    vice_cohort: str = Form(""),
    is_active: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    try:
        election = db.query(Election).filter(Election.title == position).first()
        if not election:
            return templates.TemplateResponse(
                "admin-edit-candidate.html",
                {
                    "request": request,
                    "candidate": {"id": candidate_id},
                    "error": "Please select a valid election before saving.",
                    "form_data": {
                        "full_name": full_name,
                        "student_id": student_id,
                        "major": major,
                        "cohort": cohort,
                        "position": position,
                        "status": status,
                        "vice_full_name": vice_full_name,
                        "vice_student_id": vice_student_id,
                        "vice_major": vice_major,
                        "vice_cohort": vice_cohort,
                        "is_active": is_active,
                    },
                },
            )
        if not election:
            return templates.TemplateResponse(
                "admin-add-candidate.html",
                {
                    "request": request,
                    "error": "Please select a valid election before adding a candidate.",
                    "form_data": {
                        "full_name": full_name,
                        "student_id": student_id,
                        "major": major,
                        "cohort": cohort,
                        "position": position,
                        "status": status,
                        "vice_full_name": vice_full_name,
                        "vice_student_id": vice_student_id,
                        "vice_major": vice_major,
                        "vice_cohort": vice_cohort,
                        "is_active": is_active,
                    },
                },
            )

        def resolve_ids(student_id_val: str, major_hint: str | None, cohort_hint: str | None):
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
                cohort_id = row.cohort_id if row else None
            if major_code is not None:
                row = db.query(Major).filter(Major.major_code == major_code).first()
                major_id = row.major_id if row else None
            return cohort_id, major_id

        cand_cohort_id, cand_major_id = resolve_ids(student_id, major, cohort)

        candidate = Candidate(
            full_name=full_name,
            student_id=student_id,
            position=position,
            status=status,
            is_active=is_active,
            cohort_id=cand_cohort_id,
            major_id=cand_major_id,
        )

        db.add(candidate)
        db.flush()

        ticket = None
        vice_candidate = None
        has_vice = any([vice_full_name.strip(), vice_student_id.strip(), vice_major.strip(), vice_cohort.strip()])
        if has_vice:
            v_cohort_id, v_major_id = resolve_ids(vice_student_id or student_id, vice_major or major, vice_cohort or cohort)
            vice_candidate = Candidate(
                full_name=vice_full_name or "",
                student_id=vice_student_id or "",
                position=position,
                status=status,
                is_active=is_active,
                cohort_id=v_cohort_id,
                major_id=v_major_id,
            )
            db.add(vice_candidate)
            db.flush()

        ticket = CandidateTicket(
            election_id=election.id,
            president_candidate_id=candidate.id,
            vice_president_candidate_id=vice_candidate.id if vice_candidate else None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(ticket)

        db.commit()

        return RedirectResponse(url="/admin-candidates?created=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_CANDIDATE_ADD_ERROR", f"Failed to add candidate: {exc}", request.client.host)
        return templates.TemplateResponse(
            "admin-add-candidate.html",
            {
                "request": request,
                "error": "Unable to save candidate. Please try again.",
                "form_data": {
                    "full_name": full_name,
                    "student_id": student_id,
                    "major": major,
                    "cohort": cohort,
                    "position": position,
                    "status": status,
                    "vice_full_name": vice_full_name,
                    "vice_student_id": vice_student_id,
                    "vice_major": vice_major,
                    "vice_cohort": vice_cohort,
                    "is_active": is_active,
                },
            },
        )


@router.get("/admin-edit-candidate/{candidate_id}", response_class=HTMLResponse)
def admin_edit_candidate_form(candidate_id: UUID, request: Request, db: Session = Depends(get_db)):
    candidate = db.query(Candidate).filter(Candidate.id == candidate_id).first()
    if not candidate:
        return RedirectResponse(url="/admin-candidates?error=Candidate%20not%20found", status_code=303)

    majors_map = {m.major_id: m for m in db.query(Major).all()}
    cohorts_map = {c.cohort_id: c for c in db.query(Cohort).all()}
    def derive_major_and_cohort(student_id: str | None, major_id: UUID | None, cohort_id: UUID | None):
        sid = (student_id or "").strip()
        major_val = None
        if major_id and major_id in majors_map:
            major_val = majors_map[major_id].major_name
        elif sid.isdigit() and len(sid) >= 6:
            major_val = MAJOR_CODE_MAP.get(sid[4:6])
        cohort_val = None
        if cohort_id and cohort_id in cohorts_map:
            cohort_val = str(cohorts_map[cohort_id].cohort_num)
        elif sid.isdigit() and len(sid) >= 4:
            cohort_val = sid[:4]
        return major_val, cohort_val

    cand_major, cand_cohort = derive_major_and_cohort(candidate.student_id, candidate.major_id, candidate.cohort_id)
    elections = db.query(Election).order_by(Election.start_date.desc()).all()

    ticket = (
        db.query(CandidateTicket)
        .filter(
            or_(
                CandidateTicket.president_candidate_id == candidate_id,
                CandidateTicket.vice_president_candidate_id == candidate_id,
            )
        )
        .first()
    )
    vice = None
    if ticket and ticket.vice_president_candidate_id:
        vice = db.query(Candidate).filter(Candidate.id == ticket.vice_president_candidate_id).first()

    form_data = {
        "full_name": candidate.full_name,
        "student_id": candidate.student_id,
        "major": cand_major or "",
        "cohort": cand_cohort or "",
        "position": candidate.position,
        "status": candidate.status,
        "vice_full_name": getattr(vice, "full_name", ""),
        "vice_student_id": getattr(vice, "student_id", ""),
        "vice_major": "",
        "vice_cohort": "",
        "is_active": candidate.is_active,
    }

    return templates.TemplateResponse(
        "admin-edit-candidate.html", {"request": request, "candidate": candidate, "elections": elections, "form_data": form_data}
    )


@router.post("/admin-edit-candidate/{candidate_id}")
def admin_edit_candidate_submit(
    candidate_id: UUID,
    request: Request,
    full_name: str = Form(...),
    student_id: str = Form(...),
    major: str = Form(""),
    cohort: str = Form(""),
    position: str = Form(...),
    status: str = Form("pending"),
    vice_full_name: str = Form(""),
    vice_student_id: str = Form(""),
    vice_major: str = Form(""),
    vice_cohort: str = Form(""),
    is_active: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    try:
        candidate = db.query(Candidate).filter(Candidate.id == candidate_id).first()
        if not candidate:
            return RedirectResponse(url="/admin-candidates?error=Candidate%20not%20found", status_code=303)

        election = db.query(Election).filter(Election.title == position).first()
        ticket = (
            db.query(CandidateTicket)
            .filter(
                or_(
                    CandidateTicket.president_candidate_id == candidate_id,
                    CandidateTicket.vice_president_candidate_id == candidate_id,
                )
            )
            .first()
        )
        current_vice = None
        if ticket and ticket.vice_president_candidate_id:
            current_vice = db.query(Candidate).filter(Candidate.id == ticket.vice_president_candidate_id).first()

        def resolve_ids(student_id_val: str, major_hint: str | None, cohort_hint: str | None):
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
                cohort_id = row.cohort_id if row else None
            if major_code is not None:
                row = db.query(Major).filter(Major.major_code == major_code).first()
                major_id = row.major_id if row else None
            return cohort_id, major_id

        cand_cohort_id, cand_major_id = resolve_ids(student_id, major, cohort)

        candidate.full_name = full_name
        candidate.student_id = student_id
        candidate.position = position
        candidate.status = status
        candidate.is_active = is_active
        candidate.cohort_id = cand_cohort_id
        candidate.major_id = cand_major_id
        candidate.updated_at = datetime.utcnow()

        has_vice = any([vice_full_name.strip(), vice_student_id.strip(), vice_major.strip(), vice_cohort.strip()])

        if ticket is None:
            # create a ticket for this candidate
            ticket = CandidateTicket(
                election_id=election.id if election else None,
                president_candidate_id=candidate.id,
                vice_president_candidate_id=None,
                created_at=datetime.utcnow(),
            )
            db.add(ticket)
            db.flush()

        if has_vice:
            v_cohort_id, v_major_id = resolve_ids(vice_student_id or student_id, vice_major or major, vice_cohort or cohort)
            if current_vice:
                current_vice.full_name = vice_full_name or current_vice.full_name
                current_vice.student_id = vice_student_id or current_vice.student_id
                current_vice.position = position
                current_vice.status = status
                current_vice.is_active = is_active
                current_vice.cohort_id = v_cohort_id
                current_vice.major_id = v_major_id
                current_vice.updated_at = datetime.utcnow()
            else:
                new_vice = Candidate(
                    full_name=vice_full_name or "",
                    student_id=vice_student_id or "",
                    position=position,
                    status=status,
                    is_active=is_active,
                    cohort_id=v_cohort_id,
                    major_id=v_major_id,
                )
                db.add(new_vice)
                db.flush()
                ticket.vice_president_candidate_id = new_vice.id
        else:
            # remove vice link if previously set
            if ticket:
                ticket.vice_president_candidate_id = None

        if ticket and election:
            ticket.election_id = election.id

        db.commit()

        return RedirectResponse(url="/admin-candidates?updated=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_CANDIDATE_EDIT_ERROR", f"Failed to edit candidate {candidate_id}: {exc}", request.client.host)
        return templates.TemplateResponse(
            "admin-edit-candidate.html",
            {
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
                    "vice_full_name": vice_full_name,
                    "vice_student_id": vice_student_id,
                    "vice_major": vice_major,
                    "vice_cohort": vice_cohort,
                    "is_active": is_active,
                },
            },
        )


@router.post("/admin-delete-candidate/{candidate_id}")
def admin_delete_candidate(
    candidate_id: UUID,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
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


@router.post("/admin-remove-vice/{candidate_id}")
def admin_remove_vice(
    candidate_id: UUID,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    try:
        candidate = db.query(Candidate).filter(Candidate.id == candidate_id).first()
        if not candidate:
            return RedirectResponse(url="/admin-candidates?error=Candidate%20not%20found", status_code=303)

        ticket = (
            db.query(CandidateTicket)
            .filter(
                or_(
                    CandidateTicket.president_candidate_id == candidate_id,
                    CandidateTicket.vice_president_candidate_id == candidate_id,
                )
            )
            .first()
        )

        # Remove vice record if present
        if ticket and ticket.vice_president_candidate_id:
            vice = db.query(Candidate).filter(Candidate.id == ticket.vice_president_candidate_id).first()
            ticket.vice_president_candidate_id = None
            if vice:
                db.delete(vice)

        if ticket:
            db.add(ticket)
        db.add(candidate)
        db.commit()
        return RedirectResponse(url="/admin-candidates?vp_removed=1", status_code=303)
    except Exception as exc:
        db.rollback()
        log_security_event("ADMIN_VICE_REMOVE_ERROR", f"Failed to remove vice for candidate {candidate_id}: {exc}", request.client.host)
        return RedirectResponse(url="/admin-candidates?error=Unable%20to%20remove%20vice%20president", status_code=303)

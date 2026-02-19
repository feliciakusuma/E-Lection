from __future__ import annotations

import json
from urllib.parse import urlencode
from datetime import datetime
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from uuid import UUID

from ..database import (
    Candidate,
    CandidateTicket,
    Election,
    ElectionTicketTally,
    Vote,
    User,
    VoterElectionStatus,
    increment_ticket_tally,
    get_readonly_db,
    get_secure_db,
    get_vote_count_secure,
)
from ..dependencies import get_db, templates
from ..services.audit import create_audit_log, log_security_event, security_logger
from ..utils.counts import get_eligible_voters_count
from ..utils.csrf import validate_csrf
from sqlalchemy.exc import IntegrityError

router = APIRouter()

_RANK_LABELS = ["Winner", "Runner-up", "Third place"]


def _apply_rank_labels(rows: list[dict], total_votes: int) -> None:
    """Assign rank_label with tie handling. Mutates rows in-place."""
    if not rows:
        return
    if total_votes <= 0:
        for r in rows:
            r["rank_label"] = "Candidate"
        return

    distinct_votes = []
    for r in rows:
        v = int(r.get("votes", 0))
        if v not in distinct_votes:
            distinct_votes.append(v)

    vote_to_label = {}
    for idx, v in enumerate(distinct_votes):
        if idx < len(_RANK_LABELS):
            vote_to_label[v] = _RANK_LABELS[idx]
        else:
            vote_to_label[v] = "Candidate"

    for r in rows:
        r["rank_label"] = vote_to_label.get(int(r.get("votes", 0)), "Candidate")

def _ticket_label(president: Candidate | None, vice: Candidate | None) -> str:
    """Consistently format ticket name with optional vice."""
    pres_name = (getattr(president, "full_name", "") or "").strip()
    vice_name = (getattr(vice, "full_name", "") or "").strip()
    if pres_name and vice_name:
        return f"{pres_name} & {vice_name}"
    return pres_name or vice_name or ""


def _reset_status_if_no_votes(db: Session, election_id: UUID) -> None:
    """If the votes table has no rows for this election (e.g., manual reset),
    mark all voter_election_status entries as not voted and clear stale tallies."""
    try:
        has_vote = db.query(Vote.id).filter(Vote.election_id == election_id).first()
    except Exception:
        has_vote = None
    if has_vote:
        return
    db.query(VoterElectionStatus).filter(
        VoterElectionStatus.election_id == election_id,
        VoterElectionStatus.has_voted == True,
    ).update({VoterElectionStatus.has_voted: False})
    db.query(ElectionTicketTally).filter(
        ElectionTicketTally.election_id == election_id,
    ).delete(synchronize_session=False)
    db.flush()


@router.get("/confirmation", response_class=HTMLResponse)
def confirm(
    request: Request,
    candidate_id: UUID | None = None,
    ticket_id: UUID | None = None,
    election_id: UUID | None = None,
    verification_code: str | None = None,
    db: Session = Depends(get_db),
):
    candidate = None
    ticket = None
    election = None
    error = None

    if ticket_id is not None:
        ticket = db.query(CandidateTicket).filter(CandidateTicket.id == ticket_id).first()
        if ticket:
            candidate = db.query(Candidate).filter(Candidate.id == ticket.president_candidate_id).first()
        else:
            error = "Selected ticket could not be found."
    elif candidate_id is not None:
        candidate = db.query(Candidate).filter(Candidate.id == candidate_id, Candidate.is_active == True).first()
        if not candidate:
            error = "Selected candidate could not be found."

    user_email = request.cookies.get("user_email")
    user_obj = User.find_by_email(db, user_email) if user_email else None

    now = datetime.utcnow()
    if election_id is not None:
        election = db.query(Election).filter(Election.id == election_id, Election.is_active == True).first()
    else:
        election = (
            db.query(Election)
            .filter(Election.is_active == True)
            .order_by(Election.start_date.asc())
            .first()
        )
    # Respect start/end window even if status wasn't flipped
    if election and election.start_date and now < election.start_date:
        election = None
    if election and election.end_date and now > election.end_date:
        election = None

    # Redirect voters who already cast a ballot for this election
    if election and user_obj:
        _reset_status_if_no_votes(db, election.id)
        vid = str(user_obj.id)
        status = (
            db.query(VoterElectionStatus)
            .filter(
                VoterElectionStatus.voter_id == vid,
                VoterElectionStatus.election_id == election.id,
                VoterElectionStatus.has_voted == True,
            )
            .first()
        )
        if status:
            return RedirectResponse(url=f"/results/{election.id}", status_code=303)

    return templates.TemplateResponse(
        "confirmation.html",
        {
            "request": request,
            "candidate": candidate,
            "ticket": ticket,
            "election": election,
            "verification_code": verification_code,
            "error": error,
        },
    )


@router.post("/vote")
def cast_vote(
    request: Request,
    ticket_id: UUID | None = Form(None),
    candidate_id: UUID | None = Form(None),  # legacy
    election_id: UUID = Form(...),
    voter_id: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    client_ip = request.client.host

    try:
        # Prefer authenticated user id from cookie
        user_cookie = request.cookies.get("user_email")
        user_obj = User.find_by_email(db, user_cookie) if user_cookie else None
        voter_identifier = str(user_obj.id) if user_obj else (voter_id or "").strip()
        if not voter_identifier:
            log_security_event("VOTE_BLOCKED", "Missing voter_id in submission", client_ip, None)
            raise HTTPException(status_code=400, detail="Login required to vote")

        now = datetime.utcnow()
        election = (
            db.query(Election)
            .filter(Election.id == election_id, Election.is_active == True)
            .first()
        )

        if not election:
            log_security_event("VOTE_BLOCKED", f"Invalid election: {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Election not available")
        if election.start_date and now < election.start_date:
            log_security_event("VOTE_BLOCKED", f"Election not started: {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Election not available")
        if election.end_date and now > election.end_date:
            log_security_event("VOTE_BLOCKED", f"Election ended: {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Election not available")

        _reset_status_if_no_votes(db, election_id)

        status_row = (
            db.query(VoterElectionStatus)
            .filter(
                VoterElectionStatus.voter_id == voter_identifier,
                VoterElectionStatus.election_id == election_id,
            )
            .first()
        )
        if status_row and status_row.has_voted:
            log_security_event("VOTE_DUPLICATE", f"Duplicate vote attempt for election {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Vote already cast")

        ticket = None
        if ticket_id is not None:
            ticket = (
                db.query(CandidateTicket)
                .filter(CandidateTicket.id == ticket_id, CandidateTicket.election_id == election_id)
                .first()
            )
            if not ticket:
                log_security_event("VOTE_BLOCKED", f"Invalid ticket: {ticket_id}", client_ip, voter_id)
                raise HTTPException(status_code=400, detail="Ticket not available")

        # If only candidate_id is provided, try to map it to a ticket for this election
        candidate = None
        if ticket is None and candidate_id is not None:
            candidate = db.query(Candidate).filter(Candidate.id == candidate_id, Candidate.is_active == True).first()
            if not candidate:
                log_security_event("VOTE_BLOCKED", f"Invalid candidate: {candidate_id}", client_ip, voter_id)
                raise HTTPException(status_code=400, detail="Candidate not available")
            ticket = (
                db.query(CandidateTicket)
                .filter(
                    CandidateTicket.election_id == election_id,
                    CandidateTicket.president_candidate_id == candidate_id,
                )
                .first()
            )
        if ticket is None:
            log_security_event("VOTE_BLOCKED", f"No valid ticket for election {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Ticket not available")

        effective_candidate_id = candidate_id
        if ticket is not None:
            effective_candidate_id = ticket.president_candidate_id

        new_vote = Vote(
            voter_id=voter_identifier,
            election_id=election_id,
            ticket_id=ticket.id if ticket else None,
        )
        new_vote.is_counted = True
        if status_row is None:
            status_row = VoterElectionStatus(
                voter_id=voter_identifier,
                election_id=election_id,
                has_voted=True,
            )
            db.add(status_row)
        else:
            status_row.has_voted = True
            db.add(status_row)

        increment_ticket_tally(db, election_id, ticket.id if ticket else None, step=1)
        db.add(new_vote)
        db.commit()

        create_audit_log(db, "votes", new_vote.id, "VOTE_CAST", user_id=voter_id, ip_address=client_ip)
        security_logger.info(
            "Vote cast successfully - Election: %s, Verification: %s", election_id, new_vote.verification_code
        )

        # After a successful, encrypted ballot write, send the voter straight to the results page
        query_params = urlencode({"verification_code": new_vote.verification_code})
        return RedirectResponse(url=f"/results/{election_id}?{query_params}", status_code=303)

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError:
        db.rollback()
        log_security_event("VOTE_DUPLICATE", f"Duplicate vote attempt for election {election_id}", client_ip, voter_id)
        raise HTTPException(status_code=400, detail="Vote already cast")
    except Exception as exc:
        db.rollback()
        log_security_event("VOTE_ERROR", f"Vote casting error: {exc}", client_ip, voter_id)
        raise HTTPException(status_code=500, detail="Vote casting failed")


@router.get("/api/results/{election_id}")
def api_results(election_id: UUID, db=Depends(get_readonly_db)):
    """Get election results as JSON for the specified election only."""
    try:
        election = db.query(Election).filter(Election.id == election_id).first()
        if not election:
            return {"election_id": election_id, "results": []}

        vote_counts = get_vote_count_secure(db._session, election_id)
        raw = []
        tickets = (
            db.query(CandidateTicket)
            .filter(CandidateTicket.election_id == election_id)
            .all()
        )
        for t in tickets:
            pres = db.query(Candidate).filter(Candidate.id == t.president_candidate_id).first()
            if not pres:
                continue
            vice = db.query(Candidate).filter(Candidate.id == t.vice_president_candidate_id).first() if t.vice_president_candidate_id else None
            name = _ticket_label(pres, vice)
            if not name:
                continue
            raw.append({"name": name, "votes": int(vote_counts.get(str(t.id), 0))})

        # Fallback when no tickets: include individual candidates for this election title
        if not tickets:
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            for c in candidates:
                raw.append({"name": getattr(c, "full_name", f"Candidate {c.id}"), "votes": int(vote_counts.get(f"legacy_candidate_{c.id}", 0))})

        if tickets:
            # Only add legacy rows separately when tickets exist (avoids duplication when candidates already appended)
            for key, count in vote_counts.items():
                if isinstance(key, str) and key.startswith("legacy_candidate_"):
                    cid_str = key.split("_")[-1]
                    try:
                        cid = UUID(cid_str)
                    except Exception:
                        continue
                    c = db.query(Candidate).filter(Candidate.id == cid).first()
                    # If this candidate is already in a ticket, label it with president & vice to merge tallies correctly
                    ticket_match = (
                        db.query(CandidateTicket)
                        .filter(CandidateTicket.election_id == election_id, CandidateTicket.president_candidate_id == cid)
                        .first()
                    )
                    if ticket_match:
                        pres = c
                        vice = (
                            db.query(Candidate).filter(Candidate.id == ticket_match.vice_president_candidate_id).first()
                            if ticket_match.vice_president_candidate_id
                            else None
                        )
                        name = _ticket_label(pres, vice)
                    else:
                        name = getattr(c, "full_name", f"Candidate {cid}")
                    raw.append({"name": name, "votes": int(count)})

        if not raw:
            # If no tickets or votes, synthesize ticket-like pairs from candidates
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            if candidates:
                for i in range(0, len(candidates), 2):
                    pres = candidates[i]
                    vice = candidates[i + 1] if i + 1 < len(candidates) else None
                    name = getattr(pres, "full_name", f"Candidate {pres.id}")
                    if vice:
                        name = f"{name} & {getattr(vice, 'full_name', f'Candidate {vice.id}')}"
                    raw.append({"name": name, "votes": 0})
            else:
                raw.append({"name": "No candidates", "votes": 0})

        # Merge duplicate names (e.g., legacy + ticket results for same candidate)
        aggregated = {}
        for r in raw:
            aggregated[r["name"]] = aggregated.get(r["name"], 0) + r["votes"]
        raw = [{"name": name, "votes": votes} for name, votes in aggregated.items()]

        total = sum(r["votes"] for r in raw) or 0
        palette = ["#10b981", "#3b82f6", "#6b7280", "#f59e0b", "#ef4444"]
        raw.sort(key=lambda x: x["votes"], reverse=True)
        results = []
        for idx, r in enumerate(raw):
            pct = (r["votes"] / total * 100) if total > 0 else 0
            results.append(
                {
                    "name": r["name"],
                    "votes": r["votes"],
                    "percent": pct,
                    "color": palette[idx % len(palette)],
                }
            )
        _apply_rank_labels(results, total)

        return {"election_id": election.id, "title": election.title, "results": results}
    except Exception as exc:
        log_security_event("RESULTS_ERROR", f"Error fetching results for {election_id}: {exc}", None, None)
        return {"election_id": election_id, "results": []}


@router.get("/results/{election_id}", response_class=HTMLResponse)
def election_results_page(request: Request, election_id: UUID, db=Depends(get_secure_db)):
    election = db.query(Election).filter(Election.id == election_id).first()
    if not election:
        return RedirectResponse(url="/dashboard?error=Election%20not%20found", status_code=303)

    # Eligible voters ceiling for charts (priority: DB count, then election metadata)
    try:
        eligible_voters = get_eligible_voters_count(db._session if hasattr(db, "_session") else db)
    except Exception:
        eligible_voters = 0
    try:
        meta = {}
        if election.description and str(election.description).strip().startswith("{"):
            meta = json.loads(election.description)
        meta_eligible = int(meta.get("eligible_voters") or 0)
        if meta_eligible > 0:
            eligible_voters = meta_eligible
    except Exception:
        pass

    results = []
    try:
        vote_counts = get_vote_count_secure(db, election_id)

        tickets = db.query(CandidateTicket).filter(CandidateTicket.election_id == election_id).all()
        raw = []
        for t in tickets:
            pres = db.query(Candidate).filter(Candidate.id == t.president_candidate_id).first()
            if not pres:
                continue
            vice = db.query(Candidate).filter(Candidate.id == t.vice_president_candidate_id).first() if t.vice_president_candidate_id else None
            name = _ticket_label(pres, vice)
            if not name:
                continue
            raw.append({"name": name, "votes": int(vote_counts.get(str(t.id), 0))})

        if not tickets:
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            for c in candidates:
                raw.append({"name": getattr(c, "full_name", f"Candidate {c.id}"), "votes": int(vote_counts.get(f"legacy_candidate_{c.id}", 0))})

        if tickets:
            for key, count in vote_counts.items():
                if isinstance(key, str) and key.startswith("legacy_candidate_"):
                    cid_str = key.split("_")[-1]
                    try:
                        cid = UUID(cid_str)
                    except Exception:
                        continue
                    c = db.query(Candidate).filter(Candidate.id == cid).first()
                    ticket_match = (
                        db.query(CandidateTicket)
                        .filter(CandidateTicket.election_id == election_id, CandidateTicket.president_candidate_id == cid)
                        .first()
                    )
                    if ticket_match:
                        pres = c
                        vice = (
                            db.query(Candidate).filter(Candidate.id == ticket_match.vice_president_candidate_id).first()
                            if ticket_match.vice_president_candidate_id
                            else None
                        )
                        name = _ticket_label(pres, vice)
                    else:
                        name = getattr(c, "full_name", f"Candidate {cid}")
                    raw.append({"name": name, "votes": int(count)})

        if not raw:
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            if candidates:
                for i in range(0, len(candidates), 2):
                    pres = candidates[i]
                    vice = candidates[i + 1] if i + 1 < len(candidates) else None
                    name = getattr(pres, "full_name", f"Candidate {pres.id}")
                    if vice:
                        name = f"{name} & {getattr(vice, 'full_name', f'Candidate {vice.id}')}"
                    raw.append({"name": name, "votes": 0})
            else:
                raw.append({"name": "No candidates", "votes": 0})

        aggregated = {}
        for r in raw:
            aggregated[r["name"]] = aggregated.get(r["name"], 0) + r["votes"]
        raw = [{"name": name, "votes": votes} for name, votes in aggregated.items()]

        total = sum(r["votes"] for r in raw) or 0
        palette = ["#10b981", "#3b82f6", "#6b7280", "#f59e0b", "#ef4444"]
        raw.sort(key=lambda x: x["votes"], reverse=True)
        for idx, r in enumerate(raw):
            pct = (r["votes"] / total * 100) if total > 0 else 0
            results.append(
                {
                    "name": r["name"],
                    "votes": r["votes"],
                    "percent": pct,
                    "color": palette[idx % len(palette)],
                }
            )
        _apply_rank_labels(results, total)
    except Exception as exc:
        log_security_event("RESULTS_ERROR", f"Error building results for {election_id}: {exc}", None, None)
        results = []

    # Fallback: if we still don't have results (e.g., no votes or an earlier error),
    # surface the candidates for this election with zeroed stats so the UI can
    # show real names instead of placeholders.
    if not results:
        try:
            palette = ["#10b981", "#3b82f6", "#6b7280", "#f59e0b", "#ef4444"]
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            if candidates:
                pair_idx = 0
                for i in range(0, len(candidates), 2):
                    pres = candidates[i]
                    vice = candidates[i + 1] if i + 1 < len(candidates) else None
                    name = getattr(pres, "full_name", f"Candidate {pres.id}")
                    if vice:
                        name = f"{name} & {getattr(vice, 'full_name', f'Candidate {vice.id}')}"
                    results.append(
                        {
                            "name": name,
                            "votes": 0,
                            "percent": 0,
                            "color": palette[pair_idx % len(palette)],
                        }
                    )
                    pair_idx += 1
            _apply_rank_labels(results, 0)
        except Exception:
            # If the fallback also fails, leave results empty and let the template handle it.
            pass

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "election": election,
            "results": results,
            "eligible_voters": eligible_voters,
        },
    )


@router.get("/verify-vote/{verification_code}", response_class=HTMLResponse)
def verify_vote(verification_code: str, request: Request, db: Session = Depends(get_db)):
    """Verify vote status by verification code."""
    vote = db.query(Vote).filter(Vote.verification_code == verification_code).first()
    if not vote:
        return templates.TemplateResponse(
            "verify-vote.html", {"request": request, "verification_code": verification_code, "found": False}
        )

    return templates.TemplateResponse(
        "verify-vote.html",
        {
            "request": request,
            "verification_code": verification_code,
            "found": True,
            "ticket_id": vote.ticket_id_plain,
            "candidate_id": vote.candidate_id_plain,
            "election_id": vote.election_id,
            "timestamp": vote.vote_timestamp,
        },
    )

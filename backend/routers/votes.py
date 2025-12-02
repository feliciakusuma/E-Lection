from __future__ import annotations

import hashlib
from urllib.parse import urlencode
from datetime import datetime
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..database import Candidate, CandidateTicket, Election, Vote, get_readonly_db, get_secure_db, get_vote_count_secure
from ..dependencies import get_db, templates
from ..services.audit import create_audit_log, log_security_event, security_logger

router = APIRouter()


@router.get("/confirmation", response_class=HTMLResponse)
def confirm(
    request: Request,
    candidate_id: int | None = None,
    ticket_id: int | None = None,
    election_id: int | None = None,
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

    if election_id is not None:
        election = db.query(Election).filter(Election.id == election_id).first()
    else:
        election = (
            db.query(Election)
            .filter(Election.is_active == True, Election.status == "ongoing")
            .order_by(Election.start_date.asc())
            .first()
        )

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
    ticket_id: int | None = Form(None),
    candidate_id: int | None = Form(None),  # legacy
    election_id: int = Form(...),
    voter_id: str = Form(...),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host

    try:
        election = (
            db.query(Election)
            .filter(Election.id == election_id, Election.status == "ongoing", Election.is_active == True)
            .first()
        )

        if not election:
            log_security_event("VOTE_BLOCKED", f"Invalid election: {election_id}", client_ip, voter_id)
            raise HTTPException(status_code=400, detail="Election not available")

        voter_hash_check = hashlib.sha256(f"{voter_id}_{election_id}".encode()).hexdigest()
        existing_vote = db.query(Vote).filter(Vote.election_id == election_id, Vote.voter_hash == voter_hash_check).first()

        if existing_vote:
            log_security_event(
                "VOTE_DUPLICATE", f"Duplicate vote attempt for election {election_id}", client_ip, voter_id
            )
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

        # Legacy fallback: allow direct candidate voting if ticket not provided
        if ticket is None and candidate_id is not None:
            candidate = db.query(Candidate).filter(Candidate.id == candidate_id, Candidate.is_active == True).first()
            if not candidate:
                log_security_event("VOTE_BLOCKED", f"Invalid candidate: {candidate_id}", client_ip, voter_id)
                raise HTTPException(status_code=400, detail="Candidate not available")

        effective_candidate_id = candidate_id
        if ticket is not None and effective_candidate_id is None:
            effective_candidate_id = ticket.president_candidate_id

        new_vote = Vote(
            voter_id=voter_id,
            election_id=election_id,
            ticket_id=ticket.id if ticket else None,
            candidate_id=effective_candidate_id,
        )
        new_vote.voter_hash = voter_hash_check
        new_vote.data_hash = new_vote.generate_hash()
        new_vote.is_counted = True

        db.add(new_vote)
        db.commit()

        create_audit_log(db, "votes", new_vote.id, "VOTE_CAST", user_id=voter_id, ip_address=client_ip)
        security_logger.info(
            "Vote cast successfully - Election: %s, Verification: %s", election_id, new_vote.verification_code
        )

        query_params = urlencode(
            {
                "ticket_id": ticket.id if ticket else None,
                "candidate_id": candidate_id if ticket is None else None,
                "election_id": election_id,
                "verification_code": new_vote.verification_code,
            }
        )
        return RedirectResponse(url=f"/confirmation?{query_params}", status_code=303)

    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        log_security_event("VOTE_ERROR", f"Vote casting error: {exc}", client_ip, voter_id)
        raise HTTPException(status_code=500, detail="Vote casting failed")


@router.get("/api/results/{election_id}")
def api_results(election_id: int, db=Depends(get_readonly_db)):
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
            name = (getattr(pres, "full_name", "") or "").strip()
            if vice:
                name = f"{name} & {getattr(vice, 'full_name', '').strip()}"
            if not name:
                continue
            raw.append({"name": name, "votes": int(vote_counts.get(t.id, 0))})

        # Fallback when no tickets: include individual candidates for this election title
        if not tickets:
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            for c in candidates:
                raw.append({"name": getattr(c, "full_name", f"Candidate {c.id}"), "votes": int(vote_counts.get(f"legacy_candidate_{c.id}", 0))})

        for key, count in vote_counts.items():
            if isinstance(key, str) and key.startswith("legacy_candidate_"):
                cid = int(key.split("_")[-1])
                c = db.query(Candidate).filter(Candidate.id == cid).first()
                raw.append({"name": getattr(c, "full_name", f"Candidate {cid}"), "votes": int(count)})

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

        return {"election_id": election.id, "title": election.title, "results": results}
    except Exception as exc:
        log_security_event("RESULTS_ERROR", f"Error fetching results for {election_id}: {exc}", None, None)
        return {"election_id": election_id, "results": []}


@router.get("/results/{election_id}", response_class=HTMLResponse)
def election_results_page(request: Request, election_id: int, db=Depends(get_secure_db)):
    election = db.query(Election).filter(Election.id == election_id).first()
    if not election:
        return RedirectResponse(url="/dashboard?error=Election%20not%20found", status_code=303)

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
            name = (getattr(pres, "full_name", "") or "").strip()
            if vice:
                name = f"{name} & {getattr(vice, 'full_name', '').strip()}"
            if not name:
                continue
            raw.append({"name": name, "votes": int(vote_counts.get(t.id, 0))})

        if not tickets:
            candidates = db.query(Candidate).filter(Candidate.position == election.title).all()
            for c in candidates:
                raw.append({"name": getattr(c, "full_name", f"Candidate {c.id}"), "votes": int(vote_counts.get(f"legacy_candidate_{c.id}", 0))})

        for key, count in vote_counts.items():
            if isinstance(key, str) and key.startswith("legacy_candidate_"):
                cid = int(key.split("_")[-1])
                c = db.query(Candidate).filter(Candidate.id == cid).first()
                raw.append({"name": getattr(c, "full_name", f"Candidate {cid}"), "votes": int(count)})

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

        total = sum(r["votes"] for r in raw) or 0
        palette = ["#10b981", "#3b82f6", "#6b7280", "#f59e0b", "#ef4444"]
        raw.sort(key=lambda x: x["votes"], reverse=True)
        for idx, r in enumerate(raw):
            pct = (r["votes"] / total * 100) if total > 0 else 0
            rank_label = "Winner" if idx == 0 else ("Runner-up" if idx == 1 else ("Third place" if idx == 2 else "Candidate"))
            results.append(
                {
                    "name": r["name"],
                    "votes": r["votes"],
                    "percent": pct,
                    "color": palette[idx % len(palette)],
                    "rank_label": rank_label,
                }
            )
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
                    rank_label = "Winner" if pair_idx == 0 else ("Runner-up" if pair_idx == 1 else ("Third place" if pair_idx == 2 else "Candidate"))
                    results.append(
                        {
                            "name": name,
                            "votes": 0,
                            "percent": 0,
                            "color": palette[pair_idx % len(palette)],
                            "rank_label": rank_label,
                        }
                    )
                    pair_idx += 1
        except Exception:
            # If the fallback also fails, leave results empty and let the template handle it.
            pass

    return templates.TemplateResponse("results.html", {"request": request, "election": election, "results": results})


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
            "ticket_id": vote.ticket_id,
            "candidate_id": vote.candidate_id,
            "election_id": vote.election_id,
            "timestamp": vote.vote_timestamp,
        },
    )

from backend.database import SessionLocal, Vote

def show_latest_vote():
    db = SessionLocal()
    v = db.query(Vote).order_by(Vote.id.desc()).first()
    if not v:
        print("No votes found.")
        return

    print("Vote id:", v.id)
    try:
        sess = v._session_key()
        print("Session key (first 8 hex):", sess.hex()[:16])
    except Exception as exc:
        print("Session key unavailable:", exc)

    print("Decrypted vote payload:", v.vote_data)          # voter_id, candidate_id, election_id, timestamp
    print("Decrypted vote timestamp:", v.vote_timestamp)   # ISO string


if __name__ == "__main__":
    show_latest_vote()

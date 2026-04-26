import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from database import AuditLog


GENESIS_HASH = "0" * 64


def _compute_hash(event: str, actor: str, detail: str, timestamp: str, prev_hash: str) -> str:
    block = json.dumps({
        "event": event,
        "actor": actor,
        "detail": detail,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
    }, sort_keys=True)
    return hashlib.sha256(block.encode()).hexdigest()


def append_log(db: Session, event: str, actor: str, detail: str = "") -> AuditLog:
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last.current_hash if last else GENESIS_HASH
    now = datetime.now(timezone.utc)
    timestamp_str = now.isoformat()
    current_hash = _compute_hash(event, actor, detail, timestamp_str, prev_hash)

    log = AuditLog(
        event=event,
        actor=actor,
        detail=detail,
        timestamp=now,
        prev_hash=prev_hash,
        current_hash=current_hash,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def verify_chain(db: Session) -> list[dict]:
    """Walk the entire chain and flag any tampered entries."""
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    results = []
    prev_hash = GENESIS_HASH

    for log in logs:
        expected = _compute_hash(
            log.event, log.actor, log.detail or "",
            log.timestamp.isoformat() if hasattr(log.timestamp, "isoformat") else log.timestamp,
            prev_hash,
        )
        tampered = expected != log.current_hash
        if tampered:
            log.tampered = True
            db.commit()
        results.append({
            "id": log.id,
            "event": log.event,
            "actor": log.actor,
            "timestamp": str(log.timestamp),
            "current_hash": log.current_hash[:16] + "...",
            "tampered": tampered,
        })
        prev_hash = log.current_hash

    return results

from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy.orm import Session
from database import ThreatLog

# In-memory counters (reset on server restart — fine for demo)
_message_counts: dict[str, list] = defaultdict(list)   # username -> [timestamps]
_login_failures: dict[str, int] = defaultdict(int)
_login_ips: dict[str, set] = defaultdict(set)

MSG_RATE_LIMIT = 10       # messages per 10 seconds
LOGIN_FAIL_LIMIT = 5      # failed attempts before flag
MULTI_IP_LIMIT = 3        # distinct IPs before flag


def _log_threat(db: Session, actor: str, threat_type: str, detail: str, severity: str):
    threat = ThreatLog(actor=actor, threat_type=threat_type, detail=detail, severity=severity)
    db.add(threat)
    db.commit()
    return threat


def check_message_rate(db: Session, username: str) -> dict | None:
    now = datetime.utcnow()
    window = now - timedelta(seconds=10)
    _message_counts[username] = [t for t in _message_counts[username] if t > window]
    _message_counts[username].append(now)

    if len(_message_counts[username]) > MSG_RATE_LIMIT:
        _log_threat(db, username, "MESSAGE_SPAM",
                    f"{len(_message_counts[username])} messages in 10s", "HIGH")
        return {"threat": "MESSAGE_SPAM", "severity": "HIGH",
                "detail": f"Rate limit exceeded: {len(_message_counts[username])} msgs/10s"}
    return None


def check_login_failure(db: Session, username: str, ip: str) -> dict | None:
    _login_failures[username] += 1
    _login_ips[username].add(ip)

    if _login_failures[username] >= LOGIN_FAIL_LIMIT:
        _log_threat(db, username, "BRUTE_FORCE",
                    f"{_login_failures[username]} failed attempts", "CRITICAL")
        return {"threat": "BRUTE_FORCE", "severity": "CRITICAL",
                "detail": f"{_login_failures[username]} failed login attempts"}

    if len(_login_ips[username]) >= MULTI_IP_LIMIT:
        _log_threat(db, username, "MULTI_IP_LOGIN",
                    f"Login from {len(_login_ips[username])} distinct IPs", "MEDIUM")
        return {"threat": "MULTI_IP_LOGIN", "severity": "MEDIUM",
                "detail": f"Logins from {len(_login_ips[username])} different IPs"}
    return None


def reset_login_failures(username: str):
    _login_failures[username] = 0
    _login_ips[username] = set()


def get_recent_threats(db: Session, limit: int = 20) -> list:
    threats = db.query(ThreatLog).order_by(ThreatLog.id.desc()).limit(limit).all()
    return [
        {
            "id": t.id,
            "actor": t.actor,
            "threat_type": t.threat_type,
            "detail": t.detail,
            "severity": t.severity,
            "timestamp": str(t.timestamp),
        }
        for t in threats
    ]

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import json
import os

from database import init_db, get_db, User
from auth import (
    hash_password, verify_password, create_token,
    make_device_fingerprint, verify_token_and_device, get_current_user
)
from log_chain import append_log, verify_chain
from threat_detection import (
    check_message_rate, check_login_failure,
    reset_login_failures, get_recent_threats
)

app = FastAPI(title="SecureLine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.on_event("startup")
def startup():
    init_db()


# ─── Pydantic schemas ────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str
    public_key: str          # X25519 public key hex (generated client-side)

class LoginRequest(BaseModel):
    username: str
    password: str

class RestMessageRequest(BaseModel):
    to: str
    encrypted_payload: str   # base64 AES-GCM ciphertext
    from_user: str
    token: str


# ─── Auth routes ─────────────────────────────────────────────────────────────

@app.post("/api/register")
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "Username already taken")
    user = User(
        username=req.username,
        hashed_password=hash_password(req.password),
        public_key=req.public_key,
        device_fingerprint=make_device_fingerprint(
            request.headers.get("user-agent", ""), request.client.host
        ),
    )
    db.add(user)
    db.commit()
    append_log(db, "REGISTER", req.username, f"New user registered")
    return {"status": "ok"}


@app.post("/api/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host
    user = db.query(User).filter(User.username == req.username).first()

    if not user or not verify_password(req.password, user.hashed_password):
        threat = check_login_failure(db, req.username, ip)
        append_log(db, "LOGIN_FAIL", req.username, f"Failed login from {ip}")
        detail = "Invalid credentials"
        if threat:
            detail += f" | THREAT: {threat['threat']} ({threat['severity']})"
        raise HTTPException(401, detail)

    reset_login_failures(req.username)
    fp = make_device_fingerprint(request.headers.get("user-agent", ""), ip)

    # Zero Trust: update fingerprint on each login
    user.device_fingerprint = fp
    db.commit()

    token = create_token(req.username, fp)
    append_log(db, "LOGIN", req.username, f"Successful login from {ip}")
    return {"token": token, "username": req.username, "public_key": user.public_key}


@app.get("/api/users")
def get_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.username != current_user.username).all()
    return [{"username": u.username, "public_key": u.public_key} for u in users]


# ─── REST fallback channel (anti-jamming simulation) ─────────────────────────

message_queue: dict[str, list] = {}   # username -> [messages]

@app.post("/api/message")
def rest_message(req: RestMessageRequest, request: Request, db: Session = Depends(get_db)):
    """Fallback channel when WebSocket is unavailable."""
    payload = verify_token_and_device(
        req.token,
        request.headers.get("user-agent", ""),
        request.client.host,
    )
    threat = check_message_rate(db, payload["sub"])
    if threat and threat["severity"] == "HIGH":
        raise HTTPException(429, f"Threat detected: {threat['detail']}")

    if req.to not in message_queue:
        message_queue[req.to] = []
    message_queue[req.to].append({
        "from": req.from_user,
        "encrypted_payload": req.encrypted_payload,
        "channel": "REST",
    })

    # Deliver via WS if recipient is connected
    if req.to in ws_manager.active:
        import asyncio
        asyncio.create_task(
            ws_manager.active[req.to].send_text(json.dumps({
                "type": "message",
                "from": req.from_user,
                "encrypted_payload": req.encrypted_payload,
                "channel": "REST→WS",
            }))
        )

    append_log(db, "REST_MESSAGE", req.from_user, f"REST fallback message to {req.to}")
    return {"status": "queued"}


@app.get("/api/poll")
def poll_messages(token: str, request: Request, db: Session = Depends(get_db)):
    """Client polls this when WebSocket is down."""
    payload = verify_token_and_device(token, request.headers.get("user-agent", ""), request.client.host)
    username = payload["sub"]
    msgs = message_queue.pop(username, [])
    return {"messages": msgs}


# ─── Audit log routes ─────────────────────────────────────────────────────────

@app.get("/api/logs")
def get_logs(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return verify_chain(db)


# ─── Threat routes ────────────────────────────────────────────────────────────

@app.get("/api/threats")
def get_threats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return get_recent_threats(db)


# ─── WebSocket hub ────────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: dict[str, WebSocket] = {}

    async def connect(self, username: str, ws: WebSocket):
        await ws.accept()
        self.active[username] = ws

    def disconnect(self, username: str):
        self.active.pop(username, None)

    async def send(self, username: str, data: dict):
        ws = self.active.get(username)
        if ws:
            await ws.send_text(json.dumps(data))

    async def broadcast_user_list(self):
        users = list(self.active.keys())
        for ws in self.active.values():
            await ws.send_text(json.dumps({"type": "user_list", "users": users}))


ws_manager = ConnectionManager()


@app.websocket("/ws/{token}")
async def websocket_endpoint(token: str, websocket: WebSocket, db: Session = Depends(get_db)):
    try:
        payload = verify_token_and_device(
            token,
            websocket.headers.get("user-agent", ""),
            websocket.client.host,
        )
    except HTTPException:
        await websocket.close(code=4001)
        return

    username = payload["sub"]
    await ws_manager.connect(username, websocket)
    append_log(db, "WS_CONNECT", username, "WebSocket connected")
    await ws_manager.broadcast_user_list()

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)

            if data.get("type") == "message":
                threat = check_message_rate(db, username)

                msg_payload = {
                    "type": "message",
                    "from": username,
                    "encrypted_payload": data["encrypted_payload"],
                    "channel": "WS",
                    "threat": threat,
                }

                await ws_manager.send(data["to"], msg_payload)
                # Echo back to sender with delivery confirmation
                await ws_manager.send(username, {**msg_payload, "type": "sent_confirm", "to": data["to"]})

                append_log(db, "MESSAGE_SENT", username, f"Encrypted message to {data['to']}")

                if threat:
                    await ws_manager.send(username, {"type": "threat_alert", "threat": threat})

    except WebSocketDisconnect:
        ws_manager.disconnect(username)
        append_log(db, "WS_DISCONNECT", username, "WebSocket disconnected")
        await ws_manager.broadcast_user_list()


# ─── Frontend routes ──────────────────────────────────────────────────────────

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/chat")
def serve_chat():
    return FileResponse(os.path.join(FRONTEND_DIR, "chat.html"))

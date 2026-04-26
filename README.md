# 🔐 SecureLine — Secure Defense Communication Platform

A real-time, tamper-proof, multi-channel communication system featuring end-to-end encryption, Zero Trust identity verification, AI threat detection, and immutable hash-chained logging.

> Built as a hackathon MVP. Think: **WhatsApp + Military-grade security + Threat detection.**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        BROWSER (2 tabs)                     │
│                                                             │
│   ┌─────────────────┐         ┌──────────────────┐          │
│   │   index.html    │         │   chat.html      │          │
│   │  Login/Register │         │  Chat UI +       │          │
│   │  Key Pair Gen   │         │  Audit Log Panel │          │
│   │  (WebCrypto)    │         │  Threat Panel    │          │
│   └────────┬────────┘         └────────┬─────────┘          │
│            │  HTTPS/REST               │  WebSocket / REST  │
└────────────┼───────────────────────────┼────────────────────┘
             │                           │
             ▼                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  FastAPI Backend (main.py)                  │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐    │
│  │  auth.py │  │log_chain │  │  threat_  │  │ crypto_  │    │
│  │  JWT +   │  │  .py     │  │detection  │  │ utils.py │    │
│  │  Device  │  │  SHA-256 │  │  .py      │  │ AES-GCM  │    │
│  │  Finger- │  │  Hash    │  │  Rule-    │  │ X25519   │    │
│  │  print   │  │  Chain   │  │  Based AI │  │          │    │
│  └──────────┘  └──────────┘  └───────────┘  └──────────┘    │
│                                                             │
│                    database.py (SQLite)                     │
│           users | audit_logs | threat_logs                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Real-time | WebSocket (native FastAPI) |
| Fallback Channel | REST API polling (anti-jamming simulation) |
| Authentication | JWT (python-jose), SHA-256 device fingerprinting |
| Encryption | ECDH P-256 key exchange + AES-256-GCM (WebCrypto API) |
| Password Hashing | sha256_crypt (passlib) |
| Audit Logging | SHA-256 hash-chaining (custom implementation) |
| Threat Detection | Rule-based anomaly detection (in-memory) |
| Database | SQLite via SQLAlchemy ORM |
| Frontend | Vanilla HTML/CSS/JS (no framework, zero build step) |

---

## Project Structure

```
secure_line/
├── backend/
│   ├── main.py              # FastAPI app, all routes, WebSocket hub
│   ├── auth.py              # JWT creation/verification, device fingerprinting
│   ├── crypto_utils.py      # Server-side AES-GCM + X25519 helpers
│   ├── log_chain.py         # SHA-256 hash-chained tamper-proof logger
│   ├── threat_detection.py  # Rule-based anomaly/threat detection
│   ├── database.py          # SQLAlchemy models: User, AuditLog, ThreatLog
│   └── requirements.txt
└── frontend/
    ├── index.html           # Login + Register + client-side key pair generation
    └── chat.html            # Full chat UI with encryption, panels, fallback
```

---

## Core Modules

### 1. Zero Trust Authentication (`auth.py`)
- Every login issues a **JWT** containing the username and a **device fingerprint**
- Device fingerprint = `SHA-256(User-Agent + IP)[:16]`
- Every WebSocket connection and REST fallback request re-verifies **both** the JWT signature and the device fingerprint
- If the fingerprint doesn't match (different device/IP), the request is rejected with `403 Zero Trust violation`

### 2. End-to-End Encryption (Frontend WebCrypto)
- On register, the browser generates an **ECDH P-256 key pair** using the native `WebCrypto` API
- The **public key** is stored on the server; the **private key never leaves the browser** (stored in `sessionStorage`)
- On each message, the sender derives a shared **AES-256-GCM** key via ECDH with the recipient's public key
- The server only ever sees the **base64 ciphertext** — it cannot decrypt any message

```
Sender                          Server                        Recipient
  │                               │                               │
  │── ECDH(myPriv, theirPub) ──►  │                               │
  │── AES-GCM encrypt(msg) ─────► │ ── relay ciphertext ────────► │
  │                               │                  ECDH(myPriv, theirPub)
  │                               │                  AES-GCM decrypt(msg)
```

### 3. Tamper-Proof Audit Logging (`log_chain.py`)
- Every critical event (login, message sent, connect/disconnect) is written as a **hash-chained log entry**
- Each entry contains: `event`, `actor`, `detail`, `timestamp`, `prev_hash`, `current_hash`
- `current_hash = SHA-256(event + actor + detail + timestamp + prev_hash)`
- The chain starts from a **genesis hash** of 64 zeros
- The `/api/logs` endpoint re-walks the entire chain and flags any entry where the hash doesn't match as `tampered: true`

### 4. Multi-Channel Fallback (`main.py`)
- Primary channel: **WebSocket** (`/ws/{token}`) — full-duplex real-time messaging
- Fallback channel: **REST API** (`POST /api/message` + `GET /api/poll`) — simulates anti-jamming / network disruption
- The frontend detects WebSocket disconnection and automatically switches to REST polling every 2 seconds
- The UI shows a live channel badge: `● WS Live` (green) or `● REST Fallback` (yellow)
- Demo button: **"⚡ Simulate Jamming"** forces the switch; **"🔄 Restore WebSocket"** reconnects

### 5. AI Threat Detection (`threat_detection.py`)
Rule-based anomaly detection with three threat types:

| Threat | Trigger | Severity |
|---|---|---|
| `MESSAGE_SPAM` | >10 messages in 10 seconds | HIGH |
| `BRUTE_FORCE` | ≥5 failed login attempts | CRITICAL |
| `MULTI_IP_LOGIN` | Login from ≥3 distinct IPs | MEDIUM |

- Threats are stored in the `threat_logs` table and visible in the **Threats panel** in the UI
- A red banner appears in the chat UI when a threat is detected in real time

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/register` | None | Register user + store public key |
| POST | `/api/login` | None | Login, returns JWT |
| GET | `/api/users` | JWT | List online users + public keys |
| POST | `/api/message` | JWT + Device | REST fallback message send |
| GET | `/api/poll` | JWT + Device | Poll queued REST messages |
| GET | `/api/logs` | JWT | Get full hash-chained audit log |
| GET | `/api/threats` | JWT | Get recent threat detections |
| WS | `/ws/{token}` | JWT + Device | WebSocket connection |

---

## Database Schema

```
users
├── id, username, hashed_password
├── public_key (ECDH P-256 hex)
├── device_fingerprint (SHA-256 of UA+IP)
└── created_at

audit_logs (hash-chained)
├── id, event, actor, detail, timestamp
├── prev_hash, current_hash
└── tampered (bool — set if chain broken)

threat_logs
├── id, actor, threat_type, detail
├── severity (LOW / MEDIUM / HIGH / CRITICAL)
└── timestamp
```

---

## Setup & Running

### Prerequisites
- Python 3.10+

### Install
```bash
cd backend
pip install -r requirements.txt
```

### Run
```bash
# Set secret key (recommended)
$env:SECRET_KEY = "your-strong-random-secret"   # PowerShell
export SECRET_KEY="your-strong-random-secret"   # bash

uvicorn main:app --host 0.0.0.0 --port 8888 --reload
```

### Open
```
http://localhost:8888        ← Login / Register
http://localhost:8888/chat   ← Chat (auto-redirect after login)
```

Open **two browser tabs** (or one normal + one incognito), register two users, and start chatting.

---

## Demo Script

| Step | Action | What it proves |
|---|---|---|
| 1 | Register `alice`, then `bob` | Key pair generated client-side, public key stored server-side |
| 2 | Login as both users | JWT issued with device fingerprint — Zero Trust auth |
| 3 | Send a message | Ciphertext visible below plaintext — server never sees plaintext |
| 4 | Watch Audit Log panel | Hash-chained entries updating live |
| 5 | Click **⚡ Simulate Jamming** | Channel badge switches to `REST Fallback` — messages still deliver |
| 6 | Click **🔄 Restore WebSocket** | Auto-reconnects back to `WS Live` |
| 7 | Send 11 messages rapidly | 🚨 `MESSAGE_SPAM` threat banner fires |
| 8 | Enter wrong password 5x | `BRUTE_FORCE` appears in Threats panel |

---

## Security Notes

- The `SECRET_KEY` must be set via environment variable in production — never hardcoded
- Private keys are stored in `sessionStorage` — cleared when the browser tab closes
- The device fingerprint is a lightweight Zero Trust check; for production, use a proper device attestation service
- `sha256_crypt` is used for password hashing — consider `argon2` for production workloads
- CORS is set to `*` for demo purposes — restrict to specific origins in production
- SQLite is used for simplicity — replace with PostgreSQL for production
#   s e c u r e 
 
 

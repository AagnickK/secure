# 🔐 SecureLine

**Secure Defense Communication Platform**

A real-time, tamper-proof, multi-channel communication system featuring end-to-end encryption, Zero Trust identity verification, AI threat detection, and immutable hash-chained logging.

> **Think:** WhatsApp + Military-grade security + Threat detection

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Overview

SecureLine is a hackathon MVP that demonstrates military-grade security principles in a modern communication platform. It combines:

- **End-to-End Encryption** using ECDH + AES-256-GCM
- **Zero Trust Architecture** with device fingerprinting and JWT validation
- **Tamper-Proof Audit Logging** using SHA-256 hash chains
- **Multi-Channel Resilience** with WebSocket primary + REST fallback
- **Real-Time Threat Detection** with rule-based anomaly detection

---

## 📋 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, FastAPI, Uvicorn |
| **Real-time Communication** | WebSocket (native FastAPI) |
| **Fallback Channel** | REST API polling |
| **Authentication** | JWT (python-jose), SHA-256 device fingerprinting |
| **Encryption** | ECDH P-256 key exchange + AES-256-GCM (WebCrypto API) |
| **Password Hashing** | sha256_crypt (passlib) |
| **Audit Logging** | SHA-256 hash-chaining |
| **Threat Detection** | Rule-based anomaly detection |
| **Database** | SQLite + SQLAlchemy ORM |
| **Frontend** | Vanilla HTML/CSS/JS (no framework, zero build step) |

---

## 🏗️ Architecture

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
│  │  print   │  │  Chain   │  │  Based    │  │          │    │
│  └──────────┘  └──────────┘  └───────────┘  └──────────┘    │
│                                                             │
│                    database.py (SQLite)                     │
│           users | audit_logs | threat_logs                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
secure_line/
├── backend/
│   ├── main.py              # FastAPI app, routes, WebSocket hub
│   ├── auth.py              # JWT + device fingerprinting
│   ├── crypto_utils.py      # AES-GCM + X25519 helpers
│   ├── log_chain.py         # SHA-256 hash-chained audit logging
│   ├── threat_detection.py  # Rule-based anomaly detection
│   ├── database.py          # SQLAlchemy ORM models
│   └── requirements.txt
└── frontend/
    ├── index.html           # Login/Register + key pair generation
    └── chat.html            # Chat UI + audit log + threat panel
```

---

## 🔑 Core Features

### 1. Zero Trust Authentication
- Every login issues a **JWT** with a **device fingerprint**
- Device fingerprint = `SHA-256(User-Agent + IP)[:16]`
- All WebSocket and REST requests re-verify both JWT and fingerprint
- Mismatched fingerprint → **403 Zero Trust violation**

### 2. End-to-End Encryption
- Browser generates **ECDH P-256 key pair** using WebCrypto API
- **Public key** stored on server; **private key stays in browser** (sessionStorage)
- Each message encrypted with **AES-256-GCM** derived from ECDH shared secret
- **Server only sees ciphertext** — cannot decrypt any message

```
Sender                    Server                    Recipient
  │                         │                           │
  │ ECDH(myPriv, theirPub)  │                           │
  │ AES-GCM encrypt(msg) ───► │ ──relay ciphertext──► │
  │                         │        ECDH(myPriv, theirPub)
  │                         │        AES-GCM decrypt(msg)
```

### 3. Tamper-Proof Audit Logging
- Every critical event logged with **SHA-256 hash chaining**
- Each entry: `event`, `actor`, `detail`, `timestamp`, `prev_hash`, `current_hash`
- Hash formula: `SHA-256(event + actor + detail + timestamp + prev_hash)`
- `/api/logs` endpoint re-walks chain and flags tampering

### 4. Multi-Channel Fallback
- **Primary:** WebSocket (`/ws/{token}`) — full-duplex real-time
- **Fallback:** REST polling (`POST /api/message`, `GET /api/poll`) — anti-jamming simulation
- Auto-detects WebSocket disconnection → switches to REST polling (2s interval)
- UI badge shows: `● WS Live` (green) or `● REST Fallback` (yellow)
- Demo buttons: **⚡ Simulate Jamming** | **🔄 Restore WebSocket**

### 5. AI Threat Detection
Rule-based anomaly detection with three threat levels:

| Threat | Trigger | Severity |
|---|---|---|
| `MESSAGE_SPAM` | >10 messages in 10 seconds | HIGH |
| `BRUTE_FORCE` | ≥5 failed login attempts | CRITICAL |
| `MULTI_IP_LOGIN` | Login from ≥3 distinct IPs | MEDIUM |

- Visible in **Threats panel** in real-time
- Red banner alerts when threat detected

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/secureline.git
   cd secureline/backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variable (recommended for security):**
   ```bash
   # macOS / Linux
   export SECRET_KEY="your-strong-random-secret-here"
   
   # Windows PowerShell
   $env:SECRET_KEY = "your-strong-random-secret-here"
   ```

4. **Start the server:**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8888 --reload
   ```

5. **Access the application:**
   - **Login/Register:** [http://localhost:8888](http://localhost:8888)
   - **Chat:** [http://localhost:8888/chat](http://localhost:8888/chat) (auto-redirect after login)

### Demo Setup

Open **two browser tabs** (or one normal + one incognito):
1. Register `alice` in Tab 1
2. Register `bob` in Tab 2
3. Login to both accounts
4. Start messaging and explore the features

---

## 📚 API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/register` | None | Register user + store public key |
| POST | `/api/login` | None | Login, returns JWT |
| GET | `/api/users` | JWT | List online users + public keys |
| POST | `/api/message` | JWT + Device | REST fallback message send |
| GET | `/api/poll` | JWT + Device | Poll queued REST messages |
| GET | `/api/logs` | JWT | Get hash-chained audit log |
| GET | `/api/threats` | JWT | Get recent threat detections |
| WS | `/ws/{token}` | JWT + Device | WebSocket connection |

---

## 💾 Database Schema

### Users Table
```
users
├── id (INTEGER, PK)
├── username (TEXT, UNIQUE)
├── hashed_password (TEXT)
├── public_key (TEXT) — ECDH P-256 hex
├── device_fingerprint (TEXT) — SHA-256(User-Agent + IP)
└── created_at (DATETIME)
```

### Audit Logs Table (Hash-Chained)
```
audit_logs
├── id (INTEGER, PK)
├── event (TEXT) — 'login', 'message_sent', 'connect', etc.
├── actor (TEXT) — username
├── detail (TEXT) — additional context
├── timestamp (DATETIME)
├── prev_hash (TEXT) — SHA-256 of previous entry
├── current_hash (TEXT) — SHA-256(event + actor + detail + timestamp + prev_hash)
└── tampered (BOOLEAN) — set if chain broken
```

### Threat Logs Table
```
threat_logs
├── id (INTEGER, PK)
├── actor (TEXT) — username
├── threat_type (TEXT) — 'MESSAGE_SPAM', 'BRUTE_FORCE', 'MULTI_IP_LOGIN'
├── detail (TEXT) — reason/context
├── severity (TEXT) — 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
└── timestamp (DATETIME)
```

---

## 🎮 Demo Walkthrough

| Step | Action | What It Proves |
|---|---|---|
| 1 | Register `alice`, then `bob` | Key pair generated client-side, public key stored server-side |
| 2 | Login as both users | JWT issued with device fingerprint (Zero Trust) |
| 3 | Send a message | Ciphertext visible below plaintext — server sees no plaintext |
| 4 | View Audit Log panel | Hash-chained entries updating in real-time |
| 5 | Click **⚡ Simulate Jamming** | Channel badge switches to `REST Fallback` — messages still deliver |
| 6 | Click **🔄 Restore WebSocket** | Auto-reconnects, badge returns to `WS Live` |
| 7 | Send 11 messages rapidly | 🚨 `MESSAGE_SPAM` threat banner fires in UI |
| 8 | Enter wrong password 5x | `BRUTE_FORCE` appears in Threats panel |

---

## 🔒 Security Considerations

### Production Checklist

- [ ] **SECRET_KEY** must be set via environment variable (never hardcoded)
- [ ] Private keys are stored in `sessionStorage` — cleared when tab closes
- [ ] Device fingerprint is lightweight; use proper device attestation in production
- [ ] Replace `sha256_crypt` with `argon2` for password hashing
- [ ] Restrict **CORS** to specific origins (currently `*` for demo)
- [ ] Replace SQLite with PostgreSQL for production
- [ ] Enable HTTPS/TLS in production
- [ ] Implement rate limiting on `/api/login` endpoint
- [ ] Use a proper threat detection ML model instead of rule-based system
- [ ] Implement database encryption at rest

### Security Notes

- **End-to-End Encryption:** Server-side encryption is purely for audit/log demos. In production, encrypt logs separately or use a key management service (AWS KMS, HashiCorp Vault).
- **Zero Trust:** Device fingerprinting is basic; add biometric/MFA for production.
- **Audit Logs:** SHA-256 chains provide integrity checking but not confidentiality. Consider encrypting logs at rest.

---

## 🧪 Testing

To test the system:

1. **E2E Encryption Test:**
   - Send a message and view the ciphertext in DevTools Network tab
   - Decrypt on recipient side only

2. **Audit Log Integrity:**
   - Navigate to `/api/logs` to view the hash chain
   - Try modifying the logs database and run `/api/logs` again to see tampering flag

3. **Threat Detection:**
   - Spam 10+ messages rapidly → observe `MESSAGE_SPAM` detection
   - Fail login 5x → observe `BRUTE_FORCE` detection

---

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📧 Contact & Support

For questions, issues, or suggestions:
- Open an [Issue](https://github.com/yourusername/secureline/issues)
- Start a [Discussion](https://github.com/yourusername/secureline/discussions)

---

## ⚖️ Disclaimer

This is a **hackathon MVP** designed for educational and demonstration purposes. While it implements industry-standard cryptographic techniques, it has not undergone a professional security audit. Do **not** use in production for sensitive communications without extensive testing and security review.

---

## 🎓 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [WebCrypto API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Hash-Chained Audit Logs](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)

---

**Made with ❤️ for secure, transparent communication**

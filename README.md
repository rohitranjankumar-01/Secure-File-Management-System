# 🔐 SecureFS — Secure File Management System
> B.Tech 2nd Year Operating Systems Security Project

## Quick Start (3 commands)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run
python backend/app.py

# 3. Open browser
# http://127.0.0.1:5000
```

## Tech Stack
| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+ + Flask |
| Password hashing | bcrypt (12 rounds) |
| Two-factor auth | pyotp (TOTP / Google Authenticator) |
| File encryption | cryptography — Fernet (AES-128-CBC + HMAC-SHA256) |
| Database | SQLite (built into Python) |
| Frontend | HTML5 + CSS3 + Vanilla JS |

## File Structure
```
securefs/
├── backend/
│   ├── app.py       ← Flask routes (run this)
│   ├── db.py        ← Database connection + schema
│   ├── auth.py      ← Register, login, 2FA
│   ├── files.py     ← Upload, download, share, delete
│   ├── crypto.py    ← AES-128 encrypt / decrypt
│   └── logger.py    ← Security event logging
├── frontend/
│   ├── index.html       ← Landing page
│   ├── register.html    ← Registration + 2FA QR setup
│   ├── login.html       ← Login + 2FA verification
│   ├── dashboard.html   ← Stats + recent files + security log
│   ├── upload.html      ← Drag & drop upload
│   ├── files.html       ← File manager + sharing
│   ├── share.html       ← Dedicated sharing UI
│   ├── css/style.css
│   └── js/main.js
├── encrypted_files/   ← AES-encrypted blobs stored here
├── database_files/    ← SQLite DB + Fernet key (auto-created)
└── requirements.txt
```

## Security Features
- **bcrypt** password hashing (cost factor 12)
- **TOTP 2FA** — Google Authenticator compatible
- **AES-128-CBC** file encryption via Fernet
- **HMAC-SHA256** integrity check on every file
- **Brute-force lockout** — 5 attempts → 5 min lock
- **Malware signature scanning** on every upload
- **UUID filenames** prevent path traversal
- **Parameterized SQL** prevents SQL injection
- **Discretionary Access Control** (owner + share model)
- **Full audit logging** of all security events

## GitHub Contribution Plan (15 commits)

| # | Module | File(s) |
|---|--------|---------|
| 1 | Project init | README, .gitignore, requirements.txt |
| 2 | Flask server | backend/app.py |
| 3 | Database schema | backend/db.py |
| 4 | Encryption | backend/crypto.py |
| 5 | Security logger | backend/logger.py |
| 6 | User registration | backend/auth.py (register_user) |
| 7 | Password hashing | backend/auth.py (bcrypt section) |
| 8 | Login + lockout | backend/auth.py (login_user, _record_fail) |
| 9 | Two-factor auth | backend/auth.py (verify_totp_code, make_qr_base64) |
| 10 | File upload | backend/files.py (upload_file) |
| 11 | File encryption pipeline | backend/files.py + crypto.py |
| 12 | File download | backend/files.py (download_file) |
| 13 | File sharing | backend/files.py (share_file, revoke_share) |
| 14 | Malware detection | backend/files.py (_scan function) |
| 15 | Frontend UI | frontend/ (all HTML, CSS, JS) |

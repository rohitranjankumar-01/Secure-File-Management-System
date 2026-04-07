# 🔐 SecureFS — Secure File Management System

SecureFS is a **secure web-based file management system** developed as part of a **Operating Systems security project**.  
The project demonstrates how modern systems protect sensitive data using **authentication, encryption, access control, and monitoring mechanisms**.

The platform allows users to **securely upload, store, manage, and share files** while protecting them from unauthorized access and common cybersecurity threats. The system implements multiple layers of security such as **password hashing, two-factor authentication, encrypted file storage, and security logging**, inspired by real-world cloud storage platforms.

The goal of this project is to apply **Operating Systems security concepts in a practical full-stack application**, helping students understand how secure storage systems are designed and implemented.

---

# 🚀 Quick Start (3 commands)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run
python backend/app.py

# 3. Open browser
# http://127.0.0.1:5000
```

---

# ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+ + Flask |
| Password hashing | bcrypt (12 rounds) |
| Two-factor auth | pyotp (TOTP / Google Authenticator) |
| File encryption | cryptography — Fernet (AES-128-CBC + HMAC-SHA256) |
| Database | SQLite (built into Python) |
| Frontend | HTML5 + CSS3 + Vanilla JS |

---

# 📁 File Structure

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
├── logs/
├── uploads/
├── .gitignore
├── .python-version
├── README.md
├── render.yaml
└── requirements.txt
```

---

# 🔒 Security Features

SecureFS integrates multiple security mechanisms commonly used in real-world secure storage systems.

- **bcrypt password hashing** (cost factor 12)  
- **TOTP 2FA** — Google Authenticator compatible  
- **AES-128-CBC file encryption via Fernet**  
- **HMAC-SHA256 integrity check on every file**  
- **Brute-force lockout** — 5 attempts → 5 min lock  
- **Malware signature scanning on every upload**  
- **UUID filenames prevent path traversal**  
- **Parameterized SQL prevents SQL injection**  
- **Discretionary Access Control (owner + share model)**  
- **Full audit logging of all security events**

These features ensure that the system provides **confidentiality, integrity, and controlled access to stored files**, which are core principles of **secure operating systems and cybersecurity practices**.

---

# 🎓 Academic Purpose

This project was developed to demonstrate how **Operating Systems security principles** can be implemented in a **real-world full-stack application**. It highlights concepts such as:

- Secure authentication mechanisms  
- Encrypted data storage  
- Access control models  
- Threat monitoring and logging  
- Secure file handling

The system serves as a **learning project for understanding secure system design and practical cybersecurity implementation**.

---

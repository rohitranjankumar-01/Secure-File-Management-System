"""
auth.py — Registration, login, brute-force protection, TOTP 2FA.
Imports: bcrypt, pyotp, qrcode, db (local), logger (local), standard library.
"""
import re, io, base64, datetime, uuid
import bcrypt
import pyotp
import qrcode

from db     import get_conn
from logger import log_event

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_ATTEMPTS    = 5
LOCKOUT_MINUTES = 5


# ── Helpers ───────────────────────────────────────────────────────────────────

def _valid_email(email: str) -> bool:
    return bool(re.match(r"^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$", email))


def _strong_password(pw: str):
    """Return (True, '') or (False, reason)."""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"\d", pw):
        return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", pw):
        return False, "Password must contain a special character."
    return True, ""


# ── Register ──────────────────────────────────────────────────────────────────

def register_user(username: str, email: str, password: str, ip: str = "") -> dict:
    username = username.strip().lower()
    email    = email.strip().lower()

    if len(username) < 3:
        return {"ok": False, "msg": "Username must be at least 3 characters."}
    if not _valid_email(email):
        return {"ok": False, "msg": "Invalid email address."}
    ok, reason = _strong_password(password)
    if not ok:
        return {"ok": False, "msg": reason}

    # Hash with bcrypt (12 rounds ≈ 250 ms — intentionally slow)
    pw_hash     = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    totp_secret = pyotp.random_base32()

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, totp_secret) VALUES (?,?,?,?)",
            (username, email, pw_hash, totp_secret)
        )
        conn.commit()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        uid = cur.fetchone()["id"]
        log_event(uid, "REGISTERED", f"email={email}", "INFO", ip)
        return {"ok": True, "msg": "Account created.", "username": username,
                "totp_secret": totp_secret}
    except Exception as e:
        if "UNIQUE" in str(e):
            return {"ok": False, "msg": "Username or email already taken."}
        return {"ok": False, "msg": f"Error: {e}"}
    finally:
        conn.close()


# ── Login ─────────────────────────────────────────────────────────────────────

def login_user(username: str, password: str, ip: str = "") -> dict:
    username = username.strip().lower()

    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return {"ok": False, "msg": "Invalid username or password."}

    # Brute-force check
    if user["locked_until"]:
        lock_dt = datetime.datetime.fromisoformat(user["locked_until"])
        if datetime.datetime.utcnow() < lock_dt:
            return {"ok": False, "msg": f"Account locked. Try after {user['locked_until']} UTC."}
        # Lock expired — reset
        conn = get_conn()
        conn.execute("UPDATE users SET login_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()

    # Verify password
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        _record_fail(user["id"], username, ip)
        return {"ok": False, "msg": "Invalid username or password."}

    # Success
    conn = get_conn()
    conn.execute("UPDATE users SET login_attempts=0, locked_until=NULL, last_login=datetime('now') WHERE id=?",
                 (user["id"],))
    conn.commit()
    conn.close()
    log_event(user["id"], "LOGIN_OK", "", "INFO", ip)

    return {
        "ok":           True,
        "msg":          "Password correct.",
        "user_id":      user["id"],
        "username":     user["username"],
        "totp_secret":  user["totp_secret"],
        "tfa_confirmed": user["tfa_confirmed"],
    }


def _record_fail(user_id: int, username: str, ip: str):
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT login_attempts FROM users WHERE id=?", (user_id,))
    row      = cur.fetchone()
    attempts = (row["login_attempts"] or 0) + 1
    locked   = None
    severity = "WARNING"
    if attempts >= MAX_ATTEMPTS:
        locked   = (datetime.datetime.utcnow() +
                    datetime.timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec="seconds")
        severity = "CRITICAL"
    conn.execute("UPDATE users SET login_attempts=?, locked_until=? WHERE id=?",
                 (attempts, locked, user_id))
    conn.commit()
    conn.close()
    log_event(user_id, "LOGIN_FAIL", f"attempt {attempts}/{MAX_ATTEMPTS}", severity, ip)


# ── Two-Factor Authentication ───────────────────────────────────────────────────────────



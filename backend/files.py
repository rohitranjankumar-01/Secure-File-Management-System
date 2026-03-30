"""
files.py — Upload, download, list, delete, share, revoke.
Imports: crypto (local), db (local), logger (local), standard library.
"""
import os, re, uuid, mimetypes, datetime

from db     import get_conn
from crypto import encrypt_bytes, decrypt_bytes
from logger import log_event

_ENC_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "encrypted_files")
)

ALLOWED_EXT = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif",
    "docx", "xlsx", "pptx", "csv", "zip", "mp4", "mp3"
}
MAX_SIZE = 50 * 1024 * 1024  # 50 MB

# Byte-level malware signatures (simple pattern matching)
_SIGNATURES = [
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}",   # EICAR test
    b"powershell -enc",
    b"cmd.exe /c",
    b"base64_decode(",
    b"/bin/sh -i",
    b"<script>eval(",
]
_BAD_EXT = re.compile(r"\.(php|exe|bat|sh|js)\.", re.IGNORECASE)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_name(name: str) -> str:
    name = os.path.basename(name)
    name = re.sub(r"[^\w.\-]", "_", name)
    return name


def _allowed(name: str) -> bool:
    parts = name.rsplit(".", 1)
    return len(parts) == 2 and parts[1].lower() in ALLOWED_EXT


def _mime(name: str) -> str:
    m, _ = mimetypes.guess_type(name)
    return m or "application/octet-stream"


def _human(n: int) -> str:
    for u in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def _scan(data: bytes, name: str):
    """Return (safe:bool, reason:str)."""
    if _BAD_EXT.search(name):
        return False, f"Suspicious double extension in '{name}'"
    
    # Get file extension
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    
    # Skip null-byte check for binary formats (images, zip, mp4, mp3)
    binary_exts = {"png", "jpg", "jpeg", "gif", "zip", "mp4", "mp3"}
    if ext not in binary_exts:
        if b"\x00" in data[:256]:
            return False, "Null-byte injection in file header"
    
    # Only scan text portion for malware signatures
    try:
        text_sample = data[:4096].decode("utf-8", errors="ignore")
        for sig in _SIGNATURES:
            if sig.decode("utf-8", errors="ignore").lower() in text_sample.lower():
                return False, "Malware pattern detected"
    except Exception:
        pass
    
    return True, "clean"


# ── Upload ────────────────────────────────────────────────────────────────────

def upload_file(user_id: int, filename: str, data: bytes, ip: str = "") -> dict:
    safe = _safe_name(filename)

    if not _allowed(safe):
        return {"ok": False, "msg": f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED_EXT))}"}

    if len(data) > MAX_SIZE:
        return {"ok": False, "msg": "File exceeds 50 MB limit."}

    safe_scan, reason = _scan(data, safe)
    if not safe_scan:
        log_event(user_id, "MALWARE_BLOCKED", reason, "CRITICAL", ip)
        return {"ok": False, "msg": f"File blocked: {reason}"}

    # Encrypt and save with a UUID filename
    enc_data    = encrypt_bytes(data)
    stored_name = uuid.uuid4().hex + "." + safe.rsplit(".", 1)[1].lower()
    os.makedirs(_ENC_DIR, exist_ok=True)
    with open(os.path.join(_ENC_DIR, stored_name), "wb") as f:
        f.write(enc_data)

    conn = get_conn()
    conn.execute(
        "INSERT INTO files (owner_id, original_name, stored_name, file_size, file_type) VALUES (?,?,?,?,?)",
        (user_id, safe, stored_name, len(data), _mime(safe))
    )
    conn.commit()
    conn.close()

    log_event(user_id, "FILE_UPLOAD", f"{safe} ({_human(len(data))})", "INFO", ip)
    return {"ok": True, "msg": f"'{safe}' uploaded and encrypted successfully."}


# ── Download ──────────────────────────────────────────────────────────────────

def download_file(user_id: int, file_id: int, ip: str = "") -> dict:
    if not _can_download(user_id, file_id):
        log_event(user_id, "UNAUTH_DOWNLOAD", f"file_id={file_id}", "WARNING", ip)
        return {"ok": False, "msg": "Access denied."}

    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id=? AND is_deleted=0", (file_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return {"ok": False, "msg": "File not found."}

    path = os.path.join(_ENC_DIR, row["stored_name"])
    if not os.path.exists(path):
        return {"ok": False, "msg": "File data missing on server."}

    with open(path, "rb") as f:
        enc = f.read()

    try:
        plain = decrypt_bytes(enc)
    except Exception:
        return {"ok": False, "msg": "Decryption failed — file may be corrupted."}

    conn = get_conn()
    conn.execute(
        "UPDATE files SET last_accessed=datetime('now'), downloads=downloads+1 WHERE id=?",
        (file_id,)
    )
    conn.commit()
    conn.close()

    log_event(user_id, "FILE_DOWNLOAD", f"file_id={file_id}", "INFO", ip)
    return {"ok": True, "data": plain,
            "filename": row["original_name"], "mime": row["file_type"]}


# ── Access helpers ────────────────────────────────────────────────────────────

def _can_access(user_id: int, file_id: int) -> bool:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT id FROM files WHERE id=? AND owner_id=? AND is_deleted=0",
                (file_id, user_id))
    if cur.fetchone():
        conn.close()
        return True
    cur.execute("""SELECT id FROM shares
                   WHERE file_id=? AND shared_with=?
                     AND (expires_at IS NULL OR expires_at > datetime('now'))""",
                (file_id, user_id))
    r = cur.fetchone()
    conn.close()
    return r is not None


def _can_download(user_id: int, file_id: int) -> bool:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT id FROM files WHERE id=? AND owner_id=? AND is_deleted=0",
                (file_id, user_id))
    if cur.fetchone():
        conn.close()
        return True
    cur.execute("""SELECT can_download FROM shares
                   WHERE file_id=? AND shared_with=?
                     AND (expires_at IS NULL OR expires_at > datetime('now'))""",
                (file_id, user_id))
    r = cur.fetchone()
    conn.close()
    return r is not None and r["can_download"] == 1


# ── List files ────────────────────────────────────────────────────────────────

def list_my_files(user_id: int) -> list:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(
        """SELECT id, original_name, file_size, file_type, is_encrypted,
                  upload_date, last_accessed, downloads
           FROM files WHERE owner_id=? AND is_deleted=0
           ORDER BY upload_date DESC""",
        (user_id,)
    )
    rows = cur.fetchall()
    conn.close()
    return [{
        "id": r["id"], "name": r["original_name"],
        "size": _human(r["file_size"]), "type": r["file_type"] or "",
        "encrypted": bool(r["is_encrypted"]),
        "uploaded": (r["upload_date"] or "")[:10],
        "last_accessed": (r["last_accessed"] or "")[:10],
        "downloads": r["downloads"],
    } for r in rows]


def list_shared_with_me(user_id: int) -> list:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(
        """SELECT f.id, f.original_name, f.file_size, f.file_type,
                  u.username AS owner, s.can_download, s.shared_at
           FROM shares s
           JOIN files f ON f.id = s.file_id
           JOIN users u ON u.id = s.owner_id
           WHERE s.shared_with=? AND f.is_deleted=0
             AND (s.expires_at IS NULL OR s.expires_at > datetime('now'))
           ORDER BY s.shared_at DESC""",
        (user_id,)
    )
    rows = cur.fetchall()
    conn.close()
    return [{
        "id": r["id"], "name": r["original_name"],
        "size": _human(r["file_size"]), "type": r["file_type"] or "",
        "owner": r["owner"], "can_download": bool(r["can_download"]),
        "shared_at": (r["shared_at"] or "")[:10],
    } for r in rows]


# ── Delete ────────────────────────────────────────────────────────────────────

def delete_file(user_id: int, file_id: int) -> dict:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT owner_id FROM files WHERE id=?", (file_id,))
    row = cur.fetchone()
    if not row or row["owner_id"] != user_id:
        conn.close()
        return {"ok": False, "msg": "Not your file."}
    conn.execute("UPDATE files SET is_deleted=1 WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    log_event(user_id, "FILE_DELETED", f"file_id={file_id}", "INFO")
    return {"ok": True, "msg": "File deleted."}


# ── Share / Revoke ────────────────────────────────────────────────────────────

def share_file(owner_id: int, file_id: int, target_username: str,
               can_download: bool = True, days: int = None) -> dict:
    conn = get_conn()
    cur  = conn.cursor()

    cur.execute("SELECT id FROM files WHERE id=? AND owner_id=? AND is_deleted=0",
                (file_id, owner_id))
    if not cur.fetchone():
        conn.close()
        return {"ok": False, "msg": "File not found or not yours."}

    cur.execute("SELECT id FROM users WHERE username=?", (target_username.strip().lower(),))
    target = cur.fetchone()
    if not target:
        conn.close()
        return {"ok": False, "msg": f"User '{target_username}' not found."}

    if target["id"] == owner_id:
        conn.close()
        return {"ok": False, "msg": "Cannot share with yourself."}

    expires = None
    if days:
        expires = (datetime.datetime.utcnow() +
                   datetime.timedelta(days=int(days))).isoformat(timespec="seconds")

    conn.execute(
        "INSERT INTO shares (file_id, owner_id, shared_with, can_download, expires_at) VALUES (?,?,?,?,?)",
        (file_id, owner_id, target["id"], int(can_download), expires)
    )
    conn.commit()
    conn.close()
    log_event(owner_id, "FILE_SHARED", f"file_id={file_id} -> {target_username}", "INFO")
    return {"ok": True, "msg": f"Shared with '{target_username}'."}


def revoke_share(owner_id: int, file_id: int, target_username: str) -> dict:
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (target_username.strip().lower(),))
    target = cur.fetchone()
    if not target:
        conn.close()
        return {"ok": False, "msg": "User not found."}
    conn.execute(
        "DELETE FROM shares WHERE file_id=? AND owner_id=? AND shared_with=?",
        (file_id, owner_id, target["id"])
    )
    conn.commit()
    conn.close()
    return {"ok": True, "msg": "Share revoked."}

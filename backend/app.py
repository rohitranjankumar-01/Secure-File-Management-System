"""
app.py — Flask application. Run this file to start the server.

Import map (flat, no sub-packages):
  db.py     → get_conn, init_db
  crypto.py → ensure_key
  auth.py   → register_user, login_user, verify_totp_code, confirm_2fa, make_qr_base64
  files.py  → upload_file, download_file, list_my_files, list_shared_with_me,
               delete_file, share_file, revoke_share
  logger.py → log_event
"""

import sys, os, io

# Make sure Python can find our sibling modules (db, auth, files, etc.)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, session, jsonify, send_file, send_from_directory

from db     import get_conn, init_db
from crypto import ensure_key
from logger import log_event
from auth   import (register_user, login_user,
                    verify_totp_code, confirm_2fa, make_qr_base64)
from files  import (upload_file, download_file,
                    list_my_files, list_shared_with_me,
                    delete_file, share_file, revoke_share)

# ── App setup ─────────────────────────────────────────────────────────────────

_FRONTEND = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

app = Flask(__name__,
            static_folder=os.path.join(_FRONTEND, "static"),
            static_url_path="/static")

app.secret_key          = os.environ.get("SECRET_KEY", "dev-secret-change-in-production-32bytes!")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # 50 MB


# ── Decorator ─────────────────────────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"ok": False, "msg": "Login required."}), 401
        return f(*args, **kwargs)
    return wrapper


def ip():
    return request.remote_addr or ""


# ── Frontend pages ────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return send_from_directory(_FRONTEND, "index.html")


@app.route("/<path:fname>")
def static_pages(fname):
    return send_from_directory(_FRONTEND, fname)


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    d = request.get_json(force=True)
    r = register_user(d.get("username", ""), d.get("email", ""),
                      d.get("password", ""), ip=ip())
    if r["ok"]:
        r["qr_code"]     = make_qr_base64(r["username"], r["totp_secret"])
        r["totp_secret"] = r["totp_secret"]
    return jsonify(r)


@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(force=True)
    r = login_user(d.get("username", ""), d.get("password", ""), ip=ip())
    if r["ok"]:
        # Store pending state — 2FA still required
        session["p_uid"]  = r["user_id"]
        session["p_user"] = r["username"]
        session["p_2fa"]  = True
        # Send QR only if 2FA not yet confirmed (first login)
        if not r["tfa_confirmed"]:
            r["qr_code"]     = make_qr_base64(r["username"], r["totp_secret"])
            r["totp_secret"] = r["totp_secret"]
        # Don't send sensitive fields to client
        for k in ("user_id", "totp_secret", "tfa_confirmed"):
            r.pop(k, None)
    return jsonify(r)


@app.route("/api/verify-2fa", methods=["POST"])
def api_verify_2fa():
    if "p_uid" not in session:
        return jsonify({"ok": False, "msg": "No pending login. Please log in first."})

    d    = request.get_json(force=True)
    code = d.get("code", "").strip()
    uid  = session["p_uid"]

    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT totp_secret, username FROM users WHERE id=?", (uid,))
    row = cur.fetchone()
    conn.close()

    if not row:
        session.clear()
        return jsonify({"ok": False, "msg": "User not found."})

    if not verify_totp_code(uid, row["totp_secret"], code):
        return jsonify({"ok": False, "msg": "Wrong code. Try again."})

    # Promote to full session
    session["user_id"]  = uid
    session["username"] = row["username"]
    session.pop("p_uid",  None)
    session.pop("p_user", None)
    session.pop("p_2fa",  None)

    confirm_2fa(uid)
    return jsonify({"ok": True, "msg": "Logged in.", "username": row["username"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    uid = session.get("user_id")
    if uid:
        log_event(uid, "LOGOUT", "", "INFO", ip())
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True,
                    "username": session["username"],
                    "user_id":  session["user_id"]})


# ── File routes ───────────────────────────────────────────────────────────────

@app.route("/api/files")
@login_required
def api_files():
    return jsonify({
        "ok":           True,
        "my_files":     list_my_files(session["user_id"]),
        "shared_files": list_shared_with_me(session["user_id"]),
    })


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "msg": "No file in request."})
    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "msg": "No file selected."})
    return jsonify(upload_file(session["user_id"], f.filename, f.read(), ip=ip()))


@app.route("/api/download/<int:fid>")
@login_required
def api_download(fid):
    r = download_file(session["user_id"], fid, ip=ip())
    if not r["ok"]:
        return jsonify(r), 403
    return send_file(io.BytesIO(r["data"]),
                     download_name=r["filename"],
                     as_attachment=True,
                     mimetype=r["mime"])


@app.route("/api/delete/<int:fid>", methods=["DELETE"])
@login_required
def api_delete(fid):
    return jsonify(delete_file(session["user_id"], fid))


@app.route("/api/share", methods=["POST"])
@login_required
def api_share():
    d = request.get_json(force=True)
    return jsonify(share_file(
        session["user_id"],
        d.get("file_id"),
        d.get("target_username", ""),
        d.get("can_download", True),
        d.get("days_valid"),
    ))


@app.route("/api/revoke-share", methods=["POST"])
@login_required
def api_revoke():
    d = request.get_json(force=True)
    return jsonify(revoke_share(session["user_id"], d.get("file_id"),
                                d.get("target_username", "")))


# ── Logs route ────────────────────────────────────────────────────────────────

@app.route("/api/logs")
@login_required
def api_logs():
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute(
        "SELECT action, detail, severity, ts FROM logs WHERE user_id=? ORDER BY ts DESC LIMIT 50",
        (session["user_id"],)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "logs": rows})


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ensure_key()
    init_db()
    print("\n" + "="*50)
    print("  SecureFS running at http://127.0.0.1:5000")
    print("="*50 + "\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)

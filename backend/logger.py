"""
logger.py — Security event logging.
Imports: only db (local) and standard library.
"""
from db import get_conn


def log_event(user_id, action: str, detail: str = "", severity: str = "INFO", ip: str = ""):
    """Insert one row into the logs table."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO logs (user_id, action, detail, severity, ip) VALUES (?,?,?,?,?)",
        (user_id, action, detail, severity, ip)
    )
    conn.commit()
    conn.close()

"""
db.py — Single database module. Every other file imports get_conn() from here.
"""
import sqlite3, os

_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "database_files", "app.db")
)


def get_conn():
    """Return a sqlite3 connection with row_factory set so columns work by name."""
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all tables. Safe to call multiple times."""
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            username       TEXT UNIQUE NOT NULL,
            email          TEXT UNIQUE NOT NULL,
            password_hash  TEXT NOT NULL,
            totp_secret    TEXT NOT NULL,
            tfa_confirmed  INTEGER DEFAULT 0,
            login_attempts INTEGER DEFAULT 0,
            locked_until   TEXT DEFAULT NULL,
            created_at     TEXT DEFAULT (datetime('now')),
            last_login     TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id      INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            stored_name   TEXT NOT NULL,
            file_size     INTEGER NOT NULL,
            file_type     TEXT NOT NULL,
            is_encrypted  INTEGER DEFAULT 1,
            upload_date   TEXT DEFAULT (datetime('now')),
            last_accessed TEXT DEFAULT NULL,
            downloads     INTEGER DEFAULT 0,
            is_deleted    INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS shares (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id      INTEGER NOT NULL REFERENCES files(id),
            owner_id     INTEGER NOT NULL REFERENCES users(id),
            shared_with  INTEGER NOT NULL REFERENCES users(id),
            can_download INTEGER DEFAULT 1,
            shared_at    TEXT DEFAULT (datetime('now')),
            expires_at   TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS logs (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER REFERENCES users(id),
            action   TEXT NOT NULL,
            detail   TEXT DEFAULT '',
            severity TEXT DEFAULT 'INFO',
            ip       TEXT DEFAULT '',
            ts       TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()
    print("[DB] Tables ready.")

import sqlite3
import uuid
import json
from datetime import datetime
from app.config import DB_PATH, logger

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    triggered_count INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    headers TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens (id)
                )
            """)
            conn.commit()
    except Exception as e:
        logger.error("Failed to initialize database", extra={"error": str(e)})

def create_token(name: str, description: str, severity: str) -> str:
    token_id = str(uuid.uuid4())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tokens (id, name, description, severity) VALUES (?, ?, ?, ?)",
            (token_id, name, description, severity)
        )
        conn.commit()
    return token_id

def get_tokens():
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tokens ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]

def get_token(token_id: str):
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tokens WHERE id = ?", (token_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def record_alert(token_id: str, ip_address: str, user_agent: str, headers: dict):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (token_id, ip_address, user_agent, headers) VALUES (?, ?, ?, ?)",
            (token_id, ip_address, user_agent, json.dumps(headers))
        )
        cursor.execute(
            "UPDATE tokens SET triggered_count = triggered_count + 1 WHERE id = ?",
            (token_id,)
        )
        conn.commit()

def get_alerts():
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT alerts.id, alerts.token_id, alerts.ip_address, alerts.user_agent, alerts.headers, alerts.timestamp,
                   tokens.name as token_name, tokens.severity as severity
            FROM alerts
            JOIN tokens ON alerts.token_id = tokens.id
            ORDER BY alerts.timestamp DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

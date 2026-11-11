"""SQLite storage with parameterized queries and duplicate protection."""

import sqlite3


SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT,
    line INTEGER,
    event_type TEXT,
    severity TEXT,
    ip TEXT,
    description TEXT UNIQUE
)
"""


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_description ON incidents(description)"
    )
    conn.commit()
    return conn


def insert_incident(conn, file_name, line_no, event_type, severity, ip, description):
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO incidents (file, line, event_type, severity, ip, description)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (file_name, line_no, event_type, severity, ip, description),
    )
    return cursor.rowcount > 0

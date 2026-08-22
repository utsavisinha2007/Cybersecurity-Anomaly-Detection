import sqlite3

DB_NAME = "cyber_incidents.db"


def init_db():
    """Create the SQLite database and required tables."""

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            risk_score REAL,
            priority TEXT,
            reasons TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            alert_type TEXT,
            severity TEXT,
            FOREIGN KEY (incident_id)
                REFERENCES incidents (incident_id)
        )
    """)

    conn.commit()
    conn.close()

    print("✅ [PHASE 9] Database initialized successfully.")


def save_incident(incident_id, risk_score, priority, reasons):
    """Save an incident and its Phase 8 explanation."""

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    reasons_str = " | ".join(reasons) if reasons else "Normal operational baseline"

    cursor.execute("""
        INSERT OR REPLACE INTO incidents
        (incident_id, risk_score, priority, reasons)
        VALUES (?, ?, ?, ?)
    """, (
        incident_id,
        risk_score,
        priority,
        reasons_str
    ))

    conn.commit()
    conn.close()

    print(f"✅ Incident {incident_id} saved successfully.")


def save_alert(incident_id, alert_type, severity):
    """Save an alert associated with an incident."""

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts
        (incident_id, alert_type, severity)
        VALUES (?, ?, ?)
    """, (
        incident_id,
        alert_type,
        severity
    ))

    conn.commit()
    conn.close()


def fetch_all_incidents():
    """Retrieve all stored incidents."""

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY timestamp DESC
    """)

    records = cursor.fetchall()

    conn.close()

    return records

import sqlite3
from datetime import datetime
from config import DATABASE_PATH


def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            source_ip TEXT,
            severity TEXT NOT NULL,
            details TEXT,
            resolved INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            raw_log TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def insert_alert(threat_type, source_ip, severity, details):
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO alerts (timestamp, threat_type, source_ip, severity, details) VALUES (?, ?, ?, ?, ?)",
        (timestamp, threat_type, source_ip, severity, details)
    )

    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id


def insert_log(source, raw_log):
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO logs (timestamp, source, raw_log) VALUES (?, ?, ?)",
        (timestamp, source, raw_log)
    )

    conn.commit()
    conn.close()


def get_alerts(severity=None, limit=100):
    conn = get_connection()
    cursor = conn.cursor()

    if severity:
        cursor.execute(
            "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
            (severity, limit)
        )
    else:
        cursor.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )

    results = cursor.fetchall()
    conn.close()
    return results


def resolve_alert(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()


def get_alert_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= date('now')")
    total_today = cursor.fetchone()[0]

    cursor.execute("""
        SELECT severity, COUNT(*) FROM alerts
        WHERE timestamp >= date('now')
        GROUP BY severity
    """)
    by_severity = dict(cursor.fetchall())

    cursor.execute("""
        SELECT threat_type, COUNT(*) FROM alerts
        WHERE timestamp >= date('now')
        GROUP BY threat_type
    """)
    by_type = dict(cursor.fetchall())

    cursor.execute("""
        SELECT source_ip, COUNT(*) as cnt FROM alerts
        WHERE timestamp >= date('now') AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY cnt DESC
        LIMIT 5
    """)
    top_ips = cursor.fetchall()

    conn.close()
    return {
        "total_today": total_today,
        "by_severity": by_severity,
        "by_type": by_type,
        "top_ips": top_ips
    }


def get_recent_logs(limit=5):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, source, raw_log FROM logs ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    results = cursor.fetchall()
    conn.close()
    return results


def get_all_alerts_for_report():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    results = cursor.fetchall()
    conn.close()
    return results
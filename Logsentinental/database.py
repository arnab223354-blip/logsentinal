"""
LogSentinel - SQLite Database Layer
Handles persistent storage, retrieval, and aggregation for events and security alerts.
Uses parameterized queries and handles connection contexts cleanly.
"""

import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

logger = logging.getLogger(__name__)

# Default predictable database location in workspace data directory
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "logsentinel.db"


class DatabaseError(Exception):
    """Custom exception raised when database operations fail."""
    pass


def get_db_path(db_path: Optional[str | Path] = None) -> Path:
    """Resolve database path and ensure parent directory exists."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def get_connection(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Open an SQLite connection with row factory and foreign key support."""
    path = get_db_path(db_path)
    try:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except sqlite3.Error as exc:
        logger.error(f"Failed to connect to database at {path}: {exc}")
        raise DatabaseError(f"Database connection error: {exc}") from exc


def init_db(db_path: Optional[str | Path] = None) -> None:
    """
    Initialize SQLite schema for events and alerts tables along with performance indexes.
    Safe to call multiple times (idempotent).
    """
    conn = get_connection(db_path)
    try:
        with conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    user TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    raw_line TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
                CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    user TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user);
            """)
    except sqlite3.Error as exc:
        logger.error(f"Failed to initialize database: {exc}")
        raise DatabaseError(f"Schema initialization error: {exc}") from exc
    finally:
        conn.close()


def save_events(events: List[Dict[str, Any]], db_path: Optional[str | Path] = None) -> int:
    """
    Batch insert parsed events into the events table using parameterized queries.
    Returns the number of events inserted.
    """
    if not events:
        return 0

    init_db(db_path)
    conn = get_connection(db_path)

    insert_sql = """
        INSERT INTO events (timestamp, ip, user, event_type, raw_line)
        VALUES (?, ?, ?, ?, ?)
    """
    rows = [
        (
            ev.get("timestamp", ""),
            ev.get("ip", ""),
            ev.get("user", ""),
            ev.get("event") or ev.get("event_type", ""),
            ev.get("raw_line", ""),
        )
        for ev in events
    ]

    try:
        with conn:
            cursor = conn.executemany(insert_sql, rows)
            return cursor.rowcount
    except sqlite3.Error as exc:
        logger.error(f"Failed to insert events: {exc}")
        raise DatabaseError(f"Error saving events: {exc}") from exc
    finally:
        conn.close()


def save_alerts(alerts: List[Dict[str, Any]], db_path: Optional[str | Path] = None) -> int:
    """
    Batch insert threat alerts into the alerts table using parameterized queries.
    Returns the number of alerts inserted.
    """
    if not alerts:
        return 0

    init_db(db_path)
    conn = get_connection(db_path)

    insert_sql = """
        INSERT INTO alerts (timestamp, rule_name, severity, ip, user, explanation)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    rows = [
        (
            al.get("timestamp", ""),
            al.get("rule_name", ""),
            al.get("severity", "MEDIUM"),
            al.get("ip", ""),
            al.get("user", ""),
            al.get("explanation", ""),
        )
        for al in alerts
    ]

    try:
        with conn:
            cursor = conn.executemany(insert_sql, rows)
            return cursor.rowcount
    except sqlite3.Error as exc:
        logger.error(f"Failed to insert alerts: {exc}")
        raise DatabaseError(f"Error saving alerts: {exc}") from exc
    finally:
        conn.close()


def load_events(
    db_path: Optional[str | Path] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None
) -> pd.DataFrame:
    """
    Load events from the database with optional filtering.
    Returns a pandas DataFrame.
    """
    init_db(db_path)
    conn = get_connection(db_path)

    query = "SELECT id, timestamp, ip, user, event_type, raw_line, created_at FROM events WHERE 1=1"
    params: List[Any] = []

    if event_type and event_type != "All":
        query += " AND event_type = ?"
        params.append(event_type)

    if search:
        search_pattern = f"%{search.strip()}%"
        query += " AND (ip LIKE ? OR user LIKE ? OR raw_line LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern])

    query += " ORDER BY timestamp DESC, id DESC"

    if limit is not None and limit > 0:
        query += " LIMIT ?"
        params.append(limit)

    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as exc:
        logger.error(f"Failed to query events: {exc}")
        raise DatabaseError(f"Error loading events: {exc}") from exc
    finally:
        conn.close()


def load_alerts(
    db_path: Optional[str | Path] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None
) -> pd.DataFrame:
    """
    Load alerts from the database with optional severity filtering.
    Returns a pandas DataFrame.
    """
    init_db(db_path)
    conn = get_connection(db_path)

    query = "SELECT id, timestamp, rule_name, severity, ip, user, explanation, created_at FROM alerts WHERE 1=1"
    params: List[Any] = []

    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)

    if search:
        search_pattern = f"%{search.strip()}%"
        query += " AND (ip LIKE ? OR user LIKE ? OR rule_name LIKE ? OR explanation LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    query += " ORDER BY timestamp DESC, id DESC"

    if limit is not None and limit > 0:
        query += " LIMIT ?"
        params.append(limit)

    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as exc:
        logger.error(f"Failed to query alerts: {exc}")
        raise DatabaseError(f"Error loading alerts: {exc}") from exc
    finally:
        conn.close()


def get_metrics(db_path: Optional[str | Path] = None) -> Dict[str, int]:
    """
    Calculate summary metrics directly from the database:
    - total_events
    - failed_logins
    - successful_logins
    - high_severity_alerts (HIGH or CRITICAL)
    - total_alerts
    - unique_ips
    - unique_users
    """
    init_db(db_path)
    conn = get_connection(db_path)

    metrics = {
        "total_events": 0,
        "failed_logins": 0,
        "successful_logins": 0,
        "high_severity_alerts": 0,
        "total_alerts": 0,
        "unique_ips": 0,
        "unique_users": 0,
    }

    try:
        cursor = conn.cursor()

        # Event counts
        cursor.execute("SELECT COUNT(*) FROM events")
        metrics["total_events"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE event_type = 'login_failed'")
        metrics["failed_logins"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE event_type = 'login_success'")
        metrics["successful_logins"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT ip) FROM events")
        metrics["unique_ips"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT user) FROM events")
        metrics["unique_users"] = cursor.fetchone()[0]

        # Alert counts
        cursor.execute("SELECT COUNT(*) FROM alerts")
        metrics["total_alerts"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL')")
        metrics["high_severity_alerts"] = cursor.fetchone()[0]

        return metrics
    except sqlite3.Error as exc:
        logger.error(f"Failed to calculate metrics: {exc}")
        raise DatabaseError(f"Error calculating metrics: {exc}") from exc
    finally:
        conn.close()


def clear_database(db_path: Optional[str | Path] = None) -> None:
    """
    Purge all records from both events and alerts tables.
    """
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM events;")
            conn.execute("DELETE FROM alerts;")
        # VACUUM cannot be run inside a transaction block in SQLite
        conn.isolation_level = None
        conn.execute("VACUUM;")
    except sqlite3.Error as exc:
        logger.error(f"Failed to clear database: {exc}")
        raise DatabaseError(f"Error clearing database: {exc}") from exc
    finally:
        conn.close()

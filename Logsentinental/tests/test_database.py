"""
Unit and integration tests for database.py (SQLite Storage Layer)
"""

from pathlib import Path
import pytest
from database import (
    DatabaseError,
    clear_database,
    get_metrics,
    init_db,
    load_alerts,
    load_events,
    save_alerts,
    save_events,
)


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    """Provide a fresh isolated SQLite database path for each test."""
    return tmp_path / "test_logsentinel.db"


def test_init_db(test_db_path: Path):
    """Verify tables and indexes are created without error."""
    init_db(test_db_path)
    assert test_db_path.exists()

    # Re-running init_db should be idempotent
    init_db(test_db_path)


def test_save_and_load_events(test_db_path: Path):
    """Verify events can be saved and retrieved as a DataFrame."""
    events = [
        {
            "timestamp": "2026-01-15T10:00:00Z",
            "ip": "198.51.100.23",
            "user": "admin",
            "event": "login_failed",
            "raw_line": "raw line 1",
        },
        {
            "timestamp": "2026-01-15T10:01:00Z",
            "ip": "192.0.2.10",
            "user": "alice",
            "event": "login_success",
            "raw_line": "raw line 2",
        },
    ]

    saved_count = save_events(events, db_path=test_db_path)
    assert saved_count == 2

    # Load all
    df_all = load_events(db_path=test_db_path)
    assert len(df_all) == 2
    assert "timestamp" in df_all.columns
    assert "ip" in df_all.columns

    # Filter by event_type
    df_failed = load_events(db_path=test_db_path, event_type="login_failed")
    assert len(df_failed) == 1
    assert df_failed.iloc[0]["user"] == "admin"

    # Search filter
    df_search = load_events(db_path=test_db_path, search="alice")
    assert len(df_search) == 1
    assert df_search.iloc[0]["ip"] == "192.0.2.10"


def test_save_and_load_alerts(test_db_path: Path):
    """Verify threat alerts can be saved and retrieved with severity filters."""
    alerts = [
        {
            "timestamp": "2026-01-15T10:05:00Z",
            "rule_name": "Repeated Failed Logins",
            "severity": "HIGH",
            "ip": "198.51.100.23",
            "user": "admin",
            "explanation": "High severity brute force heuristic alert",
        },
        {
            "timestamp": "2026-01-15T10:10:00Z",
            "rule_name": "Successful Login After Repeated Failures",
            "severity": "CRITICAL",
            "ip": "192.0.2.45",
            "user": "alice",
            "explanation": "Critical severity account takeover heuristic alert",
        },
    ]

    saved_count = save_alerts(alerts, db_path=test_db_path)
    assert saved_count == 2

    df_alerts = load_alerts(db_path=test_db_path)
    assert len(df_alerts) == 2

    # Filter by severity
    df_critical = load_alerts(db_path=test_db_path, severity="CRITICAL")
    assert len(df_critical) == 1
    assert df_critical.iloc[0]["user"] == "alice"


def test_get_metrics(test_db_path: Path):
    """Verify aggregated dashboard metrics from the database."""
    events = [
        {"timestamp": "2026-01-15T10:00:00Z", "ip": "192.0.2.1", "user": "user1", "event": "login_failed", "raw_line": ""},
        {"timestamp": "2026-01-15T10:01:00Z", "ip": "192.0.2.1", "user": "user1", "event": "login_failed", "raw_line": ""},
        {"timestamp": "2026-01-15T10:02:00Z", "ip": "192.0.2.2", "user": "user2", "event": "login_success", "raw_line": ""},
    ]
    alerts = [
        {
            "timestamp": "2026-01-15T10:01:00Z",
            "rule_name": "Test Alert",
            "severity": "HIGH",
            "ip": "192.0.2.1",
            "user": "user1",
            "explanation": "Explanation",
        }
    ]

    save_events(events, db_path=test_db_path)
    save_alerts(alerts, db_path=test_db_path)

    metrics = get_metrics(db_path=test_db_path)
    assert metrics["total_events"] == 3
    assert metrics["failed_logins"] == 2
    assert metrics["successful_logins"] == 1
    assert metrics["high_severity_alerts"] == 1
    assert metrics["total_alerts"] == 1
    assert metrics["unique_ips"] == 2
    assert metrics["unique_users"] == 2


def test_clear_database(test_db_path: Path):
    """Verify clearing the database empties both events and alerts tables."""
    events = [{"timestamp": "2026-01-15T10:00:00Z", "ip": "192.0.2.1", "user": "u", "event": "login_success", "raw_line": ""}]
    alerts = [{"timestamp": "2026-01-15T10:00:00Z", "rule_name": "r", "severity": "LOW", "ip": "192.0.2.1", "user": "u", "explanation": "e"}]

    save_events(events, db_path=test_db_path)
    save_alerts(alerts, db_path=test_db_path)

    # Confirm data exists
    assert get_metrics(db_path=test_db_path)["total_events"] == 1

    # Clear
    clear_database(db_path=test_db_path)

    # Confirm tables are cleared
    metrics_after = get_metrics(db_path=test_db_path)
    assert metrics_after["total_events"] == 0
    assert metrics_after["total_alerts"] == 0


def test_database_persistence_across_connections(test_db_path: Path):
    """Verify SQLite persistence across distinct connections and calls."""
    events = [{"timestamp": "2026-01-15T10:00:00Z", "ip": "192.0.2.1", "user": "persist_user", "event": "login_success", "raw_line": ""}]
    save_events(events, db_path=test_db_path)

    # Load in a completely new invocation
    df = load_events(db_path=test_db_path)
    assert len(df) == 1
    assert df.iloc[0]["user"] == "persist_user"


def test_database_empty_saves(test_db_path: Path):
    """Verify empty list saves return 0 without errors."""
    assert save_events([], db_path=test_db_path) == 0
    assert save_alerts([], db_path=test_db_path) == 0

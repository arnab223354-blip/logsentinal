"""
Unit and integration tests for detection.py (Threat Detection Engine)
"""

from datetime import datetime, timedelta, timezone
import pytest
from detection import (
    DetectionConfig,
    detect_repeated_failed_logins,
    detect_successful_login_after_failures,
    detect_threats,
)


def make_event(
    dt: datetime,
    event: str = "login_failed",
    ip: str = "198.51.100.23",
    user: str = "admin",
    line_number: int = 1
) -> dict:
    """Helper to generate well-formed event dictionaries with valid timestamps."""
    return {
        "line_number": line_number,
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timestamp_dt": dt,
        "ip": ip,
        "user": user,
        "event": event,
        "raw_line": f"{dt.strftime('%Y-%m-%dT%H:%M:%SZ')} ip={ip} user={user} event={event}",
    }


def test_repeated_failed_logins_below_threshold():
    """Verify that fewer failures than threshold does not trigger Rule 1."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    # 4 failures within 2 minutes (threshold = 5)
    events = [
        make_event(base_time + timedelta(seconds=i * 30), event="login_failed", ip="198.51.100.23")
        for i in range(4)
    ]

    alerts = detect_repeated_failed_logins(events, threshold=5, window_minutes=5)
    assert len(alerts) == 0


def test_repeated_failed_logins_exact_threshold():
    """Verify exactly 5 failures within 5 minutes triggers Rule 1."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(base_time + timedelta(minutes=i), event="login_failed", ip="198.51.100.23")
        for i in range(5)
    ]

    alerts = detect_repeated_failed_logins(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Repeated Failed Logins"
    assert alerts[0]["ip"] == "198.51.100.23"
    assert alerts[0]["severity"] == "HIGH"
    assert "5 failed login attempts" in alerts[0]["explanation"]


def test_repeated_failed_logins_deduplication():
    """Verify that 8 failures in rapid succession triggers only 1 alert, not duplicate alerts."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    # 8 failures spaced 15 seconds apart (total duration < 2 minutes)
    events = [
        make_event(base_time + timedelta(seconds=i * 15), event="login_failed", ip="198.51.100.23")
        for i in range(8)
    ]

    alerts = detect_repeated_failed_logins(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1


def test_repeated_failed_logins_outside_window():
    """Verify that failures spread out beyond window_minutes do not trigger an alert."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    # 5 failures spaced 6 minutes apart (total 24 minutes, window = 5)
    events = [
        make_event(base_time + timedelta(minutes=i * 6), event="login_failed", ip="198.51.100.23")
        for i in range(5)
    ]

    alerts = detect_repeated_failed_logins(events, threshold=5, window_minutes=5)
    assert len(alerts) == 0


def test_repeated_failed_logins_multiple_ips():
    """Verify detection discriminates between different IPs."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    # Attacking IP: 5 failures
    for i in range(5):
        events.append(make_event(base_time + timedelta(seconds=i * 20), ip="198.51.100.23"))
    # Benign IP: 2 failures
    for i in range(2):
        events.append(make_event(base_time + timedelta(seconds=i * 20), ip="192.0.2.10"))

    alerts = detect_repeated_failed_logins(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "198.51.100.23"


def test_successful_login_after_failures_triggers():
    """Verify 3 failures followed by success within 10 minutes triggers Rule 2."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(base_time, event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=1), event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=2), event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=3), event="login_success", ip="192.0.2.45", user="alice"),
    ]

    alerts = detect_successful_login_after_failures(events, failure_threshold=3, window_minutes=10)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Successful Login After Repeated Failures"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["user"] == "alice"
    assert alerts[0]["ip"] == "192.0.2.45"


def test_successful_login_after_failures_below_threshold():
    """Verify 2 failures followed by success does not trigger (threshold = 3)."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(base_time, event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=1), event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=2), event="login_success", ip="192.0.2.45", user="alice"),
    ]

    alerts = detect_successful_login_after_failures(events, failure_threshold=3, window_minutes=10)
    assert len(alerts) == 0


def test_successful_login_normal_login():
    """Verify normal login without preceding failures does not trigger."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(base_time, event="login_success", ip="192.0.2.45", user="alice"),
    ]

    alerts = detect_successful_login_after_failures(events, failure_threshold=3, window_minutes=10)
    assert len(alerts) == 0


def test_successful_login_different_users_not_triggered():
    """Verify failures for user1 do not count towards success for user2 on same IP."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(base_time, event="login_failed", ip="192.0.2.45", user="user1"),
        make_event(base_time + timedelta(minutes=1), event="login_failed", ip="192.0.2.45", user="user1"),
        make_event(base_time + timedelta(minutes=2), event="login_failed", ip="192.0.2.45", user="user1"),
        make_event(base_time + timedelta(minutes=3), event="login_success", ip="192.0.2.45", user="user2"),
    ]

    alerts = detect_successful_login_after_failures(events, failure_threshold=3, window_minutes=10)
    assert len(alerts) == 0


def test_successful_login_failures_outside_window():
    """Verify failures older than window_minutes are not counted towards success."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    # Failures occurred at 10:00, 10:01, 10:02; success at 10:25 (23 min later, window = 10)
    events = [
        make_event(base_time, event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=1), event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=2), event="login_failed", ip="192.0.2.45", user="alice"),
        make_event(base_time + timedelta(minutes=25), event="login_success", ip="192.0.2.45", user="alice"),
    ]

    alerts = detect_successful_login_after_failures(events, failure_threshold=3, window_minutes=10)
    assert len(alerts) == 0


def test_detect_threats_custom_config():
    """Verify full detect_threats with custom configuration."""
    base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(base_time + timedelta(seconds=10), event="login_failed", ip="198.51.100.1", user="bob"),
        make_event(base_time + timedelta(seconds=20), event="login_failed", ip="198.51.100.1", user="bob"),
    ]

    # With default threshold=5, no alerts
    assert len(detect_threats(events)) == 0

    # With custom config threshold=2, alerts trigger
    custom_cfg = DetectionConfig(failed_login_threshold=2, failed_login_window_minutes=2)
    alerts = detect_threats(events, config=custom_cfg)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Repeated Failed Logins"

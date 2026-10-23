"""
Unit and integration tests for log_parser.py
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from log_parser import (
    parse_iso_timestamp,
    validate_ip_address,
    parse_log_line,
    parse_log_content,
    parse_log_file,
    ALLOWED_EVENTS,
)


def test_parse_iso_timestamp_valid():
    """Verify ISO 8601 timestamps are parsed correctly to UTC datetime."""
    dt1 = parse_iso_timestamp("2026-01-15T10:00:00Z")
    assert dt1 == datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

    dt2 = parse_iso_timestamp("2026-01-15T12:00:00+02:00")
    assert dt2 == datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

    # Lowercase z
    dt3 = parse_iso_timestamp("2026-01-15T10:00:00z")
    assert dt3 == datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def test_parse_iso_timestamp_invalid():
    """Verify malformed timestamps raise ValueError."""
    with pytest.raises(Exception):
        parse_iso_timestamp("invalid-date")

    with pytest.raises(Exception):
        # 60 is an invalid minute
        parse_iso_timestamp("2026-01-15T10:60:00Z")

    with pytest.raises(Exception):
        # Month 13 is invalid
        parse_iso_timestamp("2026-13-01T10:00:00Z")


def test_validate_ip_address():
    """Verify IPv4 and IPv6 address validation."""
    assert validate_ip_address("192.0.2.1") == "192.0.2.1"
    assert validate_ip_address("198.51.100.23") == "198.51.100.23"
    assert validate_ip_address("2001:db8::1") == "2001:db8::1"

    with pytest.raises(ValueError):
        validate_ip_address("999.999.999.999")

    with pytest.raises(ValueError):
        validate_ip_address("not_an_ip")

    with pytest.raises(ValueError):
        validate_ip_address("192.168.1.500")


def test_parse_log_line_valid_events():
    """Verify parsing of all allowed event types and key-value formats."""
    for event_type in ALLOWED_EVENTS:
        line = f"2026-01-15T10:00:00Z ip=198.51.100.23 user=admin event={event_type}"
        event, err = parse_log_line(line, line_number=42)
        assert err is None
        assert event is not None
        assert event["line_number"] == 42
        assert event["ip"] == "198.51.100.23"
        assert event["user"] == "admin"
        assert event["event"] == event_type
        assert event["timestamp"] == "2026-01-15T10:00:00Z"


def test_parse_log_line_quoted_and_unordered():
    """Verify parser handles quoted values and alternative key orders."""
    line = '2026-01-15T10:00:00Z event=login_success user="service admin" ip=192.0.2.55'
    event, err = parse_log_line(line, line_number=1)
    assert err is None
    assert event is not None
    assert event["user"] == "service admin"
    assert event["event"] == "login_success"
    assert event["ip"] == "192.0.2.55"


def test_parse_log_line_skip_comments_and_blanks():
    """Verify blank lines and comment lines return (None, None)."""
    assert parse_log_line("") == (None, None)
    assert parse_log_line("   \t  ") == (None, None)
    assert parse_log_line("# This is a comment") == (None, None)
    assert parse_log_line("// C-style comment") == (None, None)
    assert parse_log_line("; INI-style comment") == (None, None)


def test_parse_log_line_malformed_timestamp():
    """Verify malformed timestamp produces an error dict without raising an exception."""
    line = "2026-01-15T10:00:60Z ip=198.51.100.23 user=admin event=login_failed"
    event, err = parse_log_line(line, line_number=10)
    assert event is None
    assert err is not None
    assert err["line_number"] == 10
    assert "Invalid ISO 8601 timestamp" in err["error"]


def test_parse_log_line_invalid_ip():
    """Verify invalid IP produces an error dict without raising an exception."""
    line = "2026-01-15T10:00:00Z ip=300.51.100.23 user=admin event=login_failed"
    event, err = parse_log_line(line, line_number=11)
    assert event is None
    assert err is not None
    assert "Invalid IP address" in err["error"]


def test_parse_log_line_unsupported_event():
    """Verify unsupported event type produces an error dict."""
    line = "2026-01-15T10:00:00Z ip=198.51.100.23 user=admin event=password_reset_request"
    event, err = parse_log_line(line, line_number=12)
    assert event is None
    assert err is not None
    assert "Unsupported event type" in err["error"]


def test_parse_log_line_missing_fields():
    """Verify missing required fields (e.g. no user) produces an error."""
    line = "2026-01-15T10:00:00Z ip=198.51.100.23 event=login_failed"
    event, err = parse_log_line(line, line_number=13)
    assert event is None
    assert err is not None
    assert "Missing required fields" in err["error"]


def test_parse_log_content_bulk():
    """Verify bulk parsing with mixed valid, comment, and invalid lines."""
    content = """# Header comment
2026-01-15T10:00:00Z ip=198.51.100.23 user=admin event=login_failed

2026-01-15T10:01:00Z ip=198.51.100.23 user=admin event=login_success
BAD_LINE_NO_TIMESTAMP
2026-01-15T10:02:00Z ip=198.51.100.23 user=admin event=logout
"""
    events, errors = parse_log_content(content)
    assert len(events) == 3
    assert len(errors) == 1
    assert errors[0]["line_number"] == 5


def test_parse_log_file(tmp_path: Path):
    """Verify reading and parsing from a temporary file."""
    sample_file = tmp_path / "test.log"
    sample_file.write_text(
        "2026-01-15T10:00:00Z ip=192.0.2.1 user=test_user event=login_success\n",
        encoding="utf-8"
    )

    events, errors = parse_log_file(sample_file)
    assert len(events) == 1
    assert len(errors) == 0
    assert events[0]["user"] == "test_user"


def test_parse_log_file_not_found():
    """Verify FileNotFoundError is raised when file does not exist."""
    with pytest.raises(FileNotFoundError):
        parse_log_file("non_existent_file_xyz.log")

"""
LogSentinel - Log Parser Module
Parses and validates cybersecurity authentication logs in standardized key-value format.
Supported format:
  2026-01-15T10:00:00Z ip=198.51.100.23 user=admin event=login_failed
"""

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Supported event types according to cybersecurity specification
ALLOWED_EVENTS: Set[str] = {
    "login_failed",
    "login_success",
    "logout",
    "account_locked",
}

# Regex to capture key=value pairs, supporting optional quoted values (e.g. user="john doe")
KEY_VALUE_REGEX = re.compile(r'([a-zA-Z_]+)=(?:"([^"]*)"|(\S+))')


def parse_iso_timestamp(ts_str: str) -> datetime:
    """
    Parse an ISO 8601 timestamp string into a timezone-aware UTC datetime.
    Raises ValueError if format is invalid.
    """
    # Replace trailing 'Z' with '+00:00' for broad compatibility
    normalized_ts = ts_str.strip()
    if normalized_ts.endswith("Z") or normalized_ts.endswith("z"):
        normalized_ts = normalized_ts[:-1] + "+00:00"

    dt = datetime.fromisoformat(normalized_ts)
    if dt.tzinfo is None:
        # Default to UTC if no timezone offset was specified
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Convert explicitly to UTC
        dt = dt.astimezone(timezone.utc)
    return dt


def validate_ip_address(ip_str: str) -> str:
    """
    Validate that the given string is a valid IPv4 or IPv6 address.
    Returns normalized IP string. Raises ValueError if invalid.
    """
    clean_ip = ip_str.strip()
    ip_obj = ipaddress.ip_address(clean_ip)
    return str(ip_obj)


def parse_log_line(line: str, line_number: int = 1) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Parse a single log line.

    Returns:
        (event_dict, None) if parsing succeeded.
        (None, error_dict) if parsing failed or malformed line encountered.
        (None, None) if line is blank or a comment.
    """
    stripped = line.strip()

    # Skip blank lines
    if not stripped:
        return None, None

    # Skip comments (#, //, ;)
    if stripped.startswith(("#", "//", ";")):
        return None, None

    tokens = stripped.split()
    if not tokens:
        return None, None

    # First token must be the ISO 8601 timestamp
    ts_token = tokens[0]
    try:
        dt = parse_iso_timestamp(ts_token)
    except Exception as exc:
        return None, {
            "line_number": line_number,
            "raw_line": stripped,
            "error": f"Invalid ISO 8601 timestamp '{ts_token}': {exc}",
        }

    # Extract key=value attributes from the rest of the line
    raw_attributes = stripped[len(ts_token):].strip()
    matches = KEY_VALUE_REGEX.findall(raw_attributes)
    fields: Dict[str, str] = {}
    for key, quoted_val, unquoted_val in matches:
        val = quoted_val if quoted_val != "" else unquoted_val
        fields[key.lower()] = val

    # Field aliases mapping
    ip_val = fields.get("ip") or fields.get("ip_address")
    user_val = fields.get("user") or fields.get("username")
    event_val = fields.get("event") or fields.get("event_type")

    missing = []
    if not ip_val:
        missing.append("ip")
    if not user_val:
        missing.append("user")
    if not event_val:
        missing.append("event")

    if missing:
        return None, {
            "line_number": line_number,
            "raw_line": stripped,
            "error": f"Missing required fields: {', '.join(missing)}",
        }

    # Validate IP address
    try:
        normalized_ip = validate_ip_address(ip_val)
    except ValueError as exc:
        return None, {
            "line_number": line_number,
            "raw_line": stripped,
            "error": f"Invalid IP address '{ip_val}': {exc}",
        }

    # Validate event type
    normalized_event = event_val.lower().strip()
    if normalized_event not in ALLOWED_EVENTS:
        return None, {
            "line_number": line_number,
            "raw_line": stripped,
            "error": (
                f"Unsupported event type '{event_val}'. "
                f"Allowed events: {', '.join(sorted(ALLOWED_EVENTS))}"
            ),
        }

    # Normalized ISO 8601 string representation in UTC format
    utc_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    event_data = {
        "line_number": line_number,
        "timestamp": utc_iso,
        "timestamp_dt": dt,
        "ip": normalized_ip,
        "user": user_val.strip(),
        "event": normalized_event,
        "raw_line": stripped,
    }

    return event_data, None


def parse_log_lines(lines: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse a list of log line strings.
    Returns:
        tuple (events, errors)
    """
    events: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        event, err = parse_log_line(line, line_number=idx)
        if event is not None:
            events.append(event)
        elif err is not None:
            errors.append(err)

    return events, errors


def parse_log_content(content: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse the full text content of a log file.
    Returns:
        tuple (events, errors)
    """
    lines = content.splitlines()
    return parse_log_lines(lines)


def parse_log_file(file_path: str | Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Read and parse a .log or .txt file from disk.
    Handles decoding gracefully without crashing.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    # Read with utf-8 and fallback replacement for corrupted characters
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    return parse_log_content(content)

"""
LogSentinel - Threat Detection Engine
Implements heuristic-based cybersecurity threat detection rules:
1. Repeated Failed Logins (Brute Force heuristic)
2. Successful Login After Repeated Failures (Suspicious Success heuristic)
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set


@dataclass
class DetectionConfig:
    """Configurable thresholds for heuristic detection rules."""
    failed_login_threshold: int = 5
    failed_login_window_minutes: int = 5
    failed_login_severity: str = "HIGH"

    success_after_failures_threshold: int = 3
    success_after_failures_window_minutes: int = 10
    success_after_failures_severity: str = "CRITICAL"


def _format_duration(td: timedelta) -> str:
    """Format a timedelta into a concise, human-readable string."""
    total_seconds = int(td.total_seconds())
    if total_seconds < 60:
        return f"{total_seconds} seconds"
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    if seconds == 0:
        return f"{minutes} min"
    return f"{minutes}m {seconds}s"


def detect_repeated_failed_logins(
    events: List[Dict[str, Any]],
    threshold: int = 5,
    window_minutes: int = 5,
    severity: str = "HIGH"
) -> List[Dict[str, Any]]:
    """
    Rule 1: Detect repeated failed login attempts from a single IP within a sliding time window.

    Educational Heuristic:
    Detects potential brute force or automated credential stuffing activity.
    Does not definitively prove malicious intent (may be a misconfigured service or batch job).
    """
    alerts: List[Dict[str, Any]] = []
    window_delta = timedelta(minutes=window_minutes)

    # Filter for failed login events and group by IP
    failed_events_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if ev.get("event") == "login_failed":
            ip = ev.get("ip", "")
            failed_events_by_ip.setdefault(ip, []).append(ev)

    for ip, ip_events in failed_events_by_ip.items():
        # Sort chronologically by timestamp_dt
        ip_events.sort(key=lambda x: x["timestamp_dt"])

        # Track the last alert timestamp for this IP to prevent duplicate alerts during the same burst
        last_alert_time: Optional[datetime] = None

        for curr_idx, current_ev in enumerate(ip_events):
            curr_time: datetime = current_ev["timestamp_dt"]

            # If an alert was already triggered recently within this window, suppress duplicates
            if last_alert_time is not None and (curr_time - last_alert_time) < window_delta:
                continue

            # Sliding window lookback: find all failed events in [curr_time - window_delta, curr_time]
            window_start_time = curr_time - window_delta
            window_events = [
                ev for ev in ip_events[:curr_idx + 1]
                if ev["timestamp_dt"] >= window_start_time
            ]

            if len(window_events) >= threshold:
                duration = curr_time - window_events[0]["timestamp_dt"]
                duration_str = _format_duration(duration)
                targeted_users = sorted(list({ev.get("user", "unknown") for ev in window_events}))

                if len(targeted_users) == 1:
                    user_str = targeted_users[0]
                else:
                    user_str = f"multiple ({', '.join(targeted_users[:3])}{'...' if len(targeted_users) > 3 else ''})"

                explanation = (
                    f"Educational Heuristic: Detected {len(window_events)} failed login attempts "
                    f"from IP {ip} within {duration_str} (threshold: >={threshold} failures within {window_minutes} min). "
                    f"Target user(s): {', '.join(targeted_users)}. "
                    f"This pattern represents a potential brute-force or credential guessing heuristic."
                )

                alert = {
                    "timestamp": current_ev["timestamp"],
                    "rule_name": "Repeated Failed Logins",
                    "severity": severity,
                    "ip": ip,
                    "user": user_str,
                    "explanation": explanation,
                    "details": {
                        "count": len(window_events),
                        "window_minutes": window_minutes,
                        "duration_seconds": int(duration.total_seconds()),
                        "targeted_users": targeted_users,
                    },
                }
                alerts.append(alert)
                last_alert_time = curr_time

    return alerts


def detect_successful_login_after_failures(
    events: List[Dict[str, Any]],
    failure_threshold: int = 3,
    window_minutes: int = 10,
    severity: str = "CRITICAL"
) -> List[Dict[str, Any]]:
    """
    Rule 2: Detect a successful login after at least `failure_threshold` recent failures
    for the same username and IP within `window_minutes`.

    Educational Heuristic:
    Detects potential credential compromise or successful account takeover following guessing.
    Could also represent a user who genuinely forgot their password and recalled it.
    """
    alerts: List[Dict[str, Any]] = []
    window_delta = timedelta(minutes=window_minutes)

    # Group all authentication events by (username, IP)
    events_by_user_ip: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for ev in events:
        key = (ev.get("user", ""), ev.get("ip", ""))
        events_by_user_ip.setdefault(key, []).append(ev)

    for (user, ip), user_ip_events in events_by_user_ip.items():
        # Sort chronologically
        user_ip_events.sort(key=lambda x: x["timestamp_dt"])

        # Track alerted success timestamps to prevent duplicate alerts for the same event
        alerted_timestamps: Set[datetime] = set()

        for curr_idx, ev in enumerate(user_ip_events):
            if ev.get("event") == "login_success":
                success_time: datetime = ev["timestamp_dt"]
                if success_time in alerted_timestamps:
                    continue

                window_start = success_time - window_delta

                # Look back at failed logins strictly before the success event within the window
                failures = [
                    prev_ev for prev_ev in user_ip_events[:curr_idx]
                    if prev_ev.get("event") == "login_failed"
                    and prev_ev["timestamp_dt"] >= window_start
                ]

                if len(failures) >= failure_threshold:
                    earliest_failure_time = failures[0]["timestamp_dt"]
                    span_str = _format_duration(success_time - earliest_failure_time)

                    explanation = (
                        f"Educational Heuristic: Successful login for user '{user}' from IP {ip} "
                        f"following {len(failures)} recent failed attempts within {span_str} "
                        f"(threshold: >={failure_threshold} failures within {window_minutes} min). "
                        f"This pattern represents a potential credential compromise heuristic "
                        f"(e.g., successful brute force or account takeover), though it may also indicate "
                        f"a legitimate user who recalled a forgotten password."
                    )

                    alert = {
                        "timestamp": ev["timestamp"],
                        "rule_name": "Successful Login After Repeated Failures",
                        "severity": severity,
                        "ip": ip,
                        "user": user,
                        "explanation": explanation,
                        "details": {
                            "failure_count": len(failures),
                            "window_minutes": window_minutes,
                            "time_to_success_seconds": int((success_time - earliest_failure_time).total_seconds()),
                        },
                    }
                    alerts.append(alert)
                    alerted_timestamps.add(success_time)

    return alerts


def detect_threats(
    events: List[Dict[str, Any]],
    config: Optional[DetectionConfig] = None
) -> List[Dict[str, Any]]:
    """
    Run all configured threat detection rules on the provided events list.
    Deduplicates and returns alerts sorted chronologically by timestamp.
    """
    if config is None:
        config = DetectionConfig()

    all_alerts: List[Dict[str, Any]] = []

    # Rule 1: Repeated failed logins
    r1_alerts = detect_repeated_failed_logins(
        events,
        threshold=config.failed_login_threshold,
        window_minutes=config.failed_login_window_minutes,
        severity=config.failed_login_severity
    )
    all_alerts.extend(r1_alerts)

    # Rule 2: Successful login after failures
    r2_alerts = detect_successful_login_after_failures(
        events,
        failure_threshold=config.success_after_failures_threshold,
        window_minutes=config.success_after_failures_window_minutes,
        severity=config.success_after_failures_severity
    )
    all_alerts.extend(r2_alerts)

    # Sort alerts chronologically
    all_alerts.sort(key=lambda x: x.get("timestamp", ""))

    return all_alerts

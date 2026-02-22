"""
reefwatch.config
~~~~~~~~~~~~~~~~
Configuration loading and validation utilities.
"""

from pathlib import Path

import yaml

from reefwatch._common import logger

_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load_config(path: str) -> dict:
    p = Path(path).expanduser()
    if not p.exists():
        logger.warning(f"Config not found at {p}, using defaults")
        return {}
    with open(p) as f:
        return yaml.safe_load(f) or {}


def validate_config(config: dict) -> list[str]:
    """Validate config and return list of warning messages."""
    warnings: list[str] = []

    # Validate intervals (must be positive)
    for section, key in [
        (("collectors", "logs"), "interval_seconds"),
        (("collectors", "processes"), "interval_seconds"),
        (("collectors", "network"), "interval_seconds"),
    ]:
        val = config
        for k in section:
            val = val.get(k, {}) if isinstance(val, dict) else {}
        interval = val.get(key) if isinstance(val, dict) else None
        if interval is not None and (not isinstance(interval, (int, float)) or interval <= 0):
            warnings.append(
                f"{'.'.join(section)}.{key} must be positive, got {interval}"
            )

    # Validate min_severity
    min_sev = config.get("alerting", {}).get("min_severity")
    if min_sev is not None and min_sev not in _VALID_SEVERITIES:
        warnings.append(
            f"alerting.min_severity '{min_sev}' is not valid "
            f"(expected one of {_VALID_SEVERITIES})"
        )

    # Validate suspicious ports (0-65535)
    ports = config.get("collectors", {}).get("network", {}).get("suspicious_ports", [])
    for port in ports:
        if not isinstance(port, int) or port < 0 or port > 65535:
            warnings.append(f"Invalid suspicious port: {port} (must be 0-65535)")

    # Validate dedup_window (non-negative)
    dedup = config.get("alerting", {}).get("dedup_window_seconds")
    if dedup is not None and (not isinstance(dedup, (int, float)) or dedup < 0):
        warnings.append(
            f"alerting.dedup_window_seconds must be non-negative, got {dedup}"
        )

    # Validate batch_window (positive)
    batch_w = config.get("alerting", {}).get("batch_window_seconds")
    if batch_w is not None and (not isinstance(batch_w, (int, float)) or batch_w <= 0):
        warnings.append(
            f"alerting.batch_window_seconds must be positive, got {batch_w}"
        )

    # Validate retry_attempts (positive int)
    retry = config.get("webhook", {}).get("retry_attempts")
    if retry is not None and (not isinstance(retry, int) or retry < 1):
        warnings.append(
            f"webhook.retry_attempts must be a positive integer, got {retry}"
        )

    return warnings

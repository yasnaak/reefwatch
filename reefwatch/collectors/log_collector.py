"""
reefwatch.collectors.log_collector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tails system log files for new entries.
"""

import json
import subprocess
from datetime import datetime, timezone

from reefwatch._common import SYSTEM, expand, get_os_key, logger


class LogCollector:
    """Tails system log files for new entries."""

    def __init__(self, config: dict):
        self.enabled = config.get("collectors", {}).get("logs", {}).get("enabled", True)
        self.interval = (
            config.get("collectors", {}).get("logs", {}).get("interval_seconds", 10)
        )
        os_key = get_os_key()
        sources_cfg = config.get("collectors", {}).get("logs", {}).get("sources", {})
        self.sources = [
            expand(s) for s in sources_cfg.get(os_key, []) if expand(s).exists()
        ]
        self._file_positions: dict[str, int] = {}
        self.use_journald = (
            config.get("collectors", {}).get("logs", {}).get("use_journald", True)
            and SYSTEM == "Linux"
        )
        self._last_journald_ts: str | None = None

        # Initialize positions to end of file (only read new lines)
        for src in self.sources:
            try:
                self._file_positions[str(src)] = src.stat().st_size
            except Exception as e:
                logger.debug(f"Cannot get size of {src}, starting from 0: {e}")
                self._file_positions[str(src)] = 0

        logger.info(
            f"LogCollector initialized: {len(self.sources)} sources"
            + (" +journald" if self.use_journald else "")
        )

    def collect(self) -> list[dict]:
        """Returns list of new log entries as dicts."""
        entries = []

        # Collect from journald on Linux
        if self.use_journald:
            entries.extend(self._collect_journald())

        for src in self.sources:
            try:
                src_str = str(src)
                current_size = src.stat().st_size
                last_pos = self._file_positions.get(src_str, 0)

                # Handle log rotation
                if current_size < last_pos:
                    last_pos = 0

                if current_size > last_pos:
                    with open(src, "r", errors="replace") as f:
                        f.seek(last_pos)
                        new_lines = f.readlines()
                        self._file_positions[src_str] = f.tell()

                    for line in new_lines:
                        line = line.strip()
                        if line:
                            entries.append(
                                {
                                    "source": src.name,
                                    "source_path": src_str,
                                    "line": line,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }
                            )
            except PermissionError:
                logger.debug(f"No permission to read {src}")
            except Exception as e:
                logger.debug(f"Error reading {src}: {e}")

        return entries

    def _collect_journald(self) -> list[dict]:
        """Collect new entries from systemd journal."""
        entries = []
        try:
            cmd = ["journalctl", "--output=json", "--no-pager"]
            if self._last_journald_ts:
                cmd += ["--since", self._last_journald_ts]
            else:
                # First run: only get entries from now
                cmd += ["--since", "now"]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.debug(f"journalctl returned {result.returncode}")
                return entries

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    entries.append(
                        {
                            "source": "journald",
                            "source_path": "journald",
                            "line": record.get("MESSAGE", ""),
                            "unit": record.get("_SYSTEMD_UNIT", ""),
                            "priority": record.get("PRIORITY", ""),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                except json.JSONDecodeError:
                    continue

            # Update timestamp for next collection
            self._last_journald_ts = datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except FileNotFoundError:
            logger.debug("journalctl not found, disabling journald collection")
            self.use_journald = False
        except subprocess.TimeoutExpired:
            logger.warning("journalctl timed out")
        except Exception as e:
            logger.debug(f"journald collection error: {e}")

        return entries

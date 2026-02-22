"""
reefwatch.collectors.process_monitor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Monitors running processes for suspicious activity.
"""

import threading
import time
from datetime import datetime, timezone

import psutil

from reefwatch._common import logger


class ProcessMonitor:
    """Monitors running processes for suspicious activity."""

    def __init__(self, config: dict):
        proc_cfg = config.get("collectors", {}).get("processes", {})
        self.enabled = proc_cfg.get("enabled", True)
        self.interval = proc_cfg.get("interval_seconds", 30)
        self.suspicious_patterns = proc_cfg.get("suspicious_patterns", [])
        self.cpu_threshold = proc_cfg.get("cpu_threshold_percent", 90)
        self.cpu_sustained = proc_cfg.get("cpu_sustained_seconds", 120)
        self._high_cpu_pids: dict[int, float] = {}  # pid -> first_seen_high
        self._cpu_lock = threading.Lock()
        logger.info(
            f"ProcessMonitor initialized: {len(self.suspicious_patterns)} patterns"
        )

    def check(self) -> list[dict]:
        alerts = []
        now = time.time()
        seen_pids = set()

        for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info["name"] or ""
                cmdline = " ".join(info["cmdline"] or [])
                cpu = info["cpu_percent"] or 0
                seen_pids.add(pid)

                # Check suspicious patterns
                for pattern in self.suspicious_patterns:
                    if pattern.lower() in cmdline.lower() or pattern.lower() in name.lower():
                        alerts.append(
                            {
                                "type": "Suspicious process detected",
                                "severity": "HIGH",
                                "source": "process_monitor",
                                "detail": f"PID {pid}: {cmdline[:200]}",
                                "rule": f"custom/suspicious_process/{pattern}",
                                "time": datetime.now(timezone.utc).isoformat(),
                            }
                        )

                # Check sustained high CPU
                if cpu > self.cpu_threshold:
                    if pid not in self._high_cpu_pids:
                        self._high_cpu_pids[pid] = now
                    elif now - self._high_cpu_pids[pid] > self.cpu_sustained:
                        alerts.append(
                            {
                                "type": "Sustained high CPU usage",
                                "severity": "MEDIUM",
                                "source": "process_monitor",
                                "detail": (
                                    f"PID {pid} ({name}): {cpu}% CPU "
                                    f"for {int(now - self._high_cpu_pids[pid])}s"
                                ),
                                "rule": "custom/high_cpu",
                                "time": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                else:
                    self._high_cpu_pids.pop(pid, None)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Cleanup dead PIDs
        with self._cpu_lock:
            self._high_cpu_pids = {
                k: v for k, v in self._high_cpu_pids.items() if k in seen_pids
            }
        return alerts

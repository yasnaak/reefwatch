"""
reefwatch.alert_manager
~~~~~~~~~~~~~~~~~~~~~~~
Deduplicates, batches, and delivers alerts to OpenClaw webhook.
"""

import json
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from reefwatch._common import expand, logger


class AlertManager:
    """Deduplicates, batches, and delivers alerts to OpenClaw webhook."""

    def __init__(self, config: dict, webhook_url: str, webhook_token: str):
        self.alerting_config = config.get("alerting", {})
        self.webhook_config = config.get("webhook", {})
        self.webhook_url = webhook_url
        self.webhook_token = webhook_token
        self._validate_webhook_url()
        self.dedup_window = self.alerting_config.get("dedup_window_seconds", 300)
        self.min_severity = self.alerting_config.get("min_severity", "MEDIUM")
        self.batch_alerts_flag = self.alerting_config.get("batch_alerts", True)
        self.batch_window = self.alerting_config.get("batch_window_seconds", 30)

        self._recent: dict[str, float] = {}  # rule_id -> last_alert_timestamp
        self._batch: list[dict] = []
        self._batch_lock = threading.Lock()
        self._batch_timer: threading.Timer | None = None
        self._history_count: int = 0

        self.history_file = expand(
            config.get("general", {}).get(
                "alerts_history",
                "~/.openclaw/workspace/skills/reefwatch/scripts/alerts_history.json",
            )
        )
        self.max_history = config.get("general", {}).get("max_alerts_history", 500)

        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self._min_sev_idx = (
            severity_order.index(self.min_severity)
            if self.min_severity in severity_order
            else 1
        )
        self._severity_order = severity_order

    def submit(self, alert: dict):
        """Submit an alert for processing. May be deduped or batched."""
        sev = alert.get("severity", "MEDIUM")
        try:
            sev_idx = self._severity_order.index(sev)
        except ValueError:
            logger.warning(f"Unknown severity '{sev}' in alert, treating as MEDIUM")
            sev_idx = self._severity_order.index("MEDIUM")
        if sev_idx < self._min_sev_idx:
            logger.debug(f"Alert below min severity ({sev}): {alert.get('type')}")
            return

        rule_id = alert.get("rule", "unknown")
        now = time.time()
        if rule_id in self._recent:
            if now - self._recent[rule_id] < self.dedup_window:
                logger.debug(f"Dedup: skipping repeat alert for {rule_id}")
                return
        self._recent[rule_id] = now

        # Clean old dedup entries
        cutoff = now - self.dedup_window
        self._recent = {k: v for k, v in self._recent.items() if v > cutoff}

        self._save_to_history(alert)

        if self.batch_alerts_flag:
            self._add_to_batch(alert)
        else:
            self._send([alert])

    def _add_to_batch(self, alert: dict):
        with self._batch_lock:
            self._batch.append(alert)
            if self._batch_timer is None:
                self._batch_timer = threading.Timer(
                    self.batch_window, self._flush_batch
                )
                self._batch_timer.daemon = True
                self._batch_timer.start()

    def _flush_batch(self):
        with self._batch_lock:
            batch = self._batch[:]
            self._batch.clear()
            self._batch_timer = None
        if batch:
            self._send(batch)

    def _send(self, alerts: list[dict]):
        """Send alert(s) to OpenClaw via webhook."""
        if not self.webhook_url:
            logger.warning("No webhook URL configured, printing alert to log only")
            for a in alerts:
                logger.warning(f"ALERT: {json.dumps(a)}")
            return

        lines = ["🔴 REEFWATCH ALERT", "━" * 24]
        for a in alerts:
            lines.append(f"Type: {a.get('type', 'Unknown')}")
            lines.append(f"Severity: {a.get('severity', 'MEDIUM')}")
            lines.append(f"Source: {a.get('source', 'N/A')}")
            lines.append(f"Detail: {a.get('detail', 'N/A')}")
            lines.append(f"Rule: {a.get('rule', 'N/A')}")
            lines.append(f"Time: {a.get('time', datetime.now(timezone.utc).isoformat())}")
            if len(alerts) > 1:
                lines.append("─" * 24)
        lines.append("━" * 24)

        message = "\n".join(lines)

        headers = {"Content-Type": "application/json"}
        if self.webhook_token:
            headers["Authorization"] = f"Bearer {self.webhook_token}"

        retry = self._config_retry()
        for attempt in range(retry["attempts"]):
            try:
                resp = requests.post(
                    self.webhook_url,
                    json={"text": message, "mode": "now"},
                    headers=headers,
                    timeout=10,
                )
                if resp.ok:
                    logger.info(f"Alert delivered ({len(alerts)} alerts)")
                    return
                logger.warning(f"Webhook returned {resp.status_code}: {resp.text}")
            except Exception as e:
                logger.warning(f"Webhook attempt {attempt+1} failed: {e}")
            time.sleep(retry["delay"])

        logger.error("Failed to deliver alert after retries")

    def shutdown(self):
        """Cancel pending timer and flush remaining alerts before exit."""
        with self._batch_lock:
            if self._batch_timer is not None:
                self._batch_timer.cancel()
                self._batch_timer = None
            batch = self._batch[:]
            self._batch.clear()
        if batch:
            self._send(batch)

    def _validate_webhook_url(self):
        """Basic SSRF prevention: warn if webhook points outside localhost."""
        if not self.webhook_url:
            return
        parsed = urlparse(self.webhook_url)
        if parsed.scheme not in ("http", "https"):
            logger.error(
                f"Webhook URL has unsupported scheme '{parsed.scheme}', disabling webhook"
            )
            self.webhook_url = ""
            return
        localhost_hosts = {"127.0.0.1", "localhost", "::1"}
        allow_external = self.webhook_config.get("allow_external", False)
        if parsed.hostname not in localhost_hosts and not allow_external:
            logger.warning(
                f"Webhook URL host '{parsed.hostname}' is not localhost. "
                f"Set webhook.allow_external: true in config to suppress this warning."
            )

    def _config_retry(self):
        return {
            "attempts": self.webhook_config.get("retry_attempts", 3),
            "delay": self.webhook_config.get("retry_delay_seconds", 5),
        }

    def _save_to_history(self, alert: dict):
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, "a") as f:
                f.write(json.dumps(alert, default=str) + "\n")
            self._history_count += 1
            if self._history_count % 50 == 0:
                self._rotate_history()
        except Exception as e:
            logger.warning(f"Failed to save alert history: {e}")

    def _rotate_history(self):
        """Keep only the last max_history alerts in the JSONL file."""
        try:
            lines = self.history_file.read_text().strip().split("\n")
            if len(lines) > self.max_history:
                with open(self.history_file, "w") as f:
                    f.write("\n".join(lines[-self.max_history :]) + "\n")
        except Exception as e:
            logger.debug(f"History rotation failed: {e}")

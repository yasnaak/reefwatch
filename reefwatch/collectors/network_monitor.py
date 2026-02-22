"""
reefwatch.collectors.network_monitor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Monitors network connections for suspicious activity.
"""

import ipaddress
import socket
from datetime import datetime, timezone
from pathlib import Path

import psutil

from reefwatch._common import logger


class NetworkMonitor:
    """Monitors network connections for suspicious activity."""

    def __init__(self, config: dict):
        net_cfg = config.get("collectors", {}).get("network", {})
        self.enabled = net_cfg.get("enabled", True)
        self.interval = net_cfg.get("interval_seconds", 60)
        self.suspicious_ports = set(net_cfg.get("suspicious_ports", []))
        self.rate_threshold = net_cfg.get("connection_rate_threshold", 50)
        self._prev_connections: set[tuple] = set()
        self._ioc_ips: set[str] = set()
        self._ioc_domains: set[str] = set()

        # Load IOC blocklist
        ioc_path = net_cfg.get("ioc_blocklist", "")
        if ioc_path:
            self._load_iocs(ioc_path)

        logger.info(
            f"NetworkMonitor initialized: {len(self.suspicious_ports)} ports, "
            f"{len(self._ioc_ips)} IOC IPs"
        )

    def _load_iocs(self, path: str):
        p = Path(path)
        if not p.is_absolute():
            p = Path(__file__).parent / p
        if not p.exists():
            logger.warning(f"IOC blocklist not found: {p}")
            return
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(line)
                    self._ioc_ips.add(line)
                except ValueError:
                    # Not a valid IP — treat as domain
                    self._ioc_domains.add(line.lower())
                    # Pre-resolve domain to IPs for efficient matching
                    try:
                        for info in socket.getaddrinfo(line, None):
                            self._ioc_ips.add(info[4][0])
                    except socket.gaierror:
                        logger.debug(f"Cannot resolve IOC domain: {line}")
        logger.info(
            f"IOCs loaded: {len(self._ioc_ips)} IPs, "
            f"{len(self._ioc_domains)} domains"
        )

    def check(self) -> list[dict]:
        alerts = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("No permission for net_connections, trying inet4 only")
            try:
                connections = psutil.net_connections(kind="inet4")
            except Exception as e:
                logger.warning(f"Cannot access network connections: {e}")
                return alerts

        current_conns = set()
        for conn in connections:
            if conn.status == "ESTABLISHED" and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                current_conns.add((remote_ip, remote_port))

                # Check suspicious ports
                if remote_port in self.suspicious_ports:
                    alerts.append(
                        {
                            "type": "Connection to suspicious port",
                            "severity": "HIGH",
                            "source": "network_monitor",
                            "detail": (
                                f"Connection to {remote_ip}:{remote_port} "
                                f"(PID: {conn.pid})"
                            ),
                            "rule": f"custom/suspicious_port/{remote_port}",
                            "time": datetime.now(timezone.utc).isoformat(),
                        }
                    )

                # Check IOC blocklist
                if remote_ip in self._ioc_ips:
                    alerts.append(
                        {
                            "type": "Connection to known malicious IP",
                            "severity": "CRITICAL",
                            "source": "network_monitor",
                            "detail": (
                                f"Connection to IOC {remote_ip}:{remote_port} "
                                f"(PID: {conn.pid})"
                            ),
                            "rule": "custom/ioc_blocklist",
                            "time": datetime.now(timezone.utc).isoformat(),
                        }
                    )

        # Check connection rate (new connections since last check)
        new_conns = current_conns - self._prev_connections
        if len(new_conns) > self.rate_threshold:
            alerts.append(
                {
                    "type": "High connection rate",
                    "severity": "MEDIUM",
                    "source": "network_monitor",
                    "detail": f"{len(new_conns)} new connections since last check",
                    "rule": "custom/connection_rate",
                    "time": datetime.now(timezone.utc).isoformat(),
                }
            )

        self._prev_connections = current_conns
        return alerts

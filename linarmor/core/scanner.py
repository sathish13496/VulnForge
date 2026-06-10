"""
LinArmor Nmap Scanner Wrapper

Provides a clean interface around python-nmap for host discovery,
port scanning, service version detection, and OS fingerprinting.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

import nmap

from linarmor.core.target import Service, Target

logger = logging.getLogger("linarmor.scanner")


class NmapScanner:
    """
    Wrapper around python-nmap for network reconnaissance and enumeration.

    Usage:
        scanner = NmapScanner(log_callback=print)
        target = Target(ip="192.168.1.100")
        target = scanner.discover_host(target)
        target = scanner.scan_ports(target)
    """

    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None):
        """
        Initialize the Nmap scanner.

        Args:
            log_callback: Optional function(level, message) for real-time log output.
                         Levels: "info", "warn", "error", "success"
        """
        self._nm = nmap.PortScanner()
        self._log = log_callback or self._default_log

    def _default_log(self, level: str, message: str) -> None:
        """Default log handler that uses Python logging."""
        log_fn = getattr(logger, level if level != "success" else "info")
        log_fn(message)

    def _emit(self, level: str, message: str) -> None:
        """Emit a log message via the callback."""
        self._log(level, message)

    # ──────────────────────────────────────────────
    # Phase 1: Host Discovery (Reconnaissance)
    # ──────────────────────────────────────────────

    def discover_host(self, target: Target) -> Target:
        """
        Check if the target host is alive and gather basic info.

        Runs: nmap -sn <target>
        """
        self._emit("info", f"Phase 1: Reconnaissance — Starting host discovery for {target.ip}")

        try:
            self._nm.scan(hosts=target.ip, arguments="-sn")

            if target.ip in self._nm.all_hosts():
                host_info = self._nm[target.ip]
                target.is_alive = True

                # Extract hostname
                if "hostnames" in host_info and host_info["hostnames"]:
                    for h in host_info["hostnames"]:
                        if h.get("name"):
                            target.hostname = h["name"]
                            break

                # Extract state/latency
                if "status" in host_info:
                    target.latency = float(host_info["status"].get("reason_ttl", 0))

                self._emit("success", f"Host is up (latency: {target.latency}s) — {target.hostname or target.ip}")
            else:
                target.is_alive = False
                self._emit("error", f"Host {target.ip} appears to be down or unreachable")

        except nmap.PortScannerError as e:
            self._emit("error", f"Nmap error during host discovery: {e}")
            target.is_alive = False
        except Exception as e:
            self._emit("error", f"Unexpected error during host discovery: {e}")
            target.is_alive = False

        return target

    # ──────────────────────────────────────────────
    # Phase 2: Port Scanning & Service Enumeration
    # ──────────────────────────────────────────────

    def scan_ports(self, target: Target, scan_type: str = "full") -> Target:
        """
        Scan ports on the target and detect running services.

        Args:
            target: Target with IP to scan
            scan_type: "full" (all ports) or "quick" (top 1000)
        """
        if not target.is_alive:
            self._emit("warn", "Skipping port scan — host is not alive")
            return target

        if scan_type == "quick":
            args = "-sS -sV --top-ports 1000 --open"
            self._emit("info", "Phase 2: Enumeration — Running Nmap SYN scan on top 1000 ports")
        else:
            port_range = target.port_range or "1-65535"
            args = f"-sS -sV -O -p {port_range} --open"
            self._emit("info", f"Phase 2: Enumeration — Running Nmap SYN scan on ports {port_range}")

        try:
            self._nm.scan(hosts=target.ip, arguments=args)

            if target.ip not in self._nm.all_hosts():
                self._emit("warn", "No scan results returned for target")
                return target

            host_data = self._nm[target.ip]

            # Extract OS information
            if "osmatch" in host_data:
                os_matches = host_data["osmatch"]
                if os_matches:
                    best_match = os_matches[0]
                    target.os_name = best_match.get("name", "")
                    target.os_family = best_match.get("osclass", [{}])[0].get("osfamily", "") \
                        if best_match.get("osclass") else ""

                    # Try to extract kernel version from OS name
                    os_name_lower = target.os_name.lower()
                    if "linux" in os_name_lower:
                        target.os_family = "Linux"

                    self._emit("info", f"OS detected: {target.os_name}")

            # Extract services for each protocol (tcp/udp)
            for proto in host_data.all_protocols():
                ports = sorted(host_data[proto].keys())
                for port in ports:
                    port_info = host_data[proto][port]

                    service = Service(
                        port=port,
                        protocol=proto,
                        state=port_info.get("state", "unknown"),
                        service_name=port_info.get("name", ""),
                        product=port_info.get("product", ""),
                        version=port_info.get("version", ""),
                        extra_info=port_info.get("extrainfo", ""),
                        cpe=port_info.get("cpe", ""),
                    )

                    target.services.append(service)
                    target.open_ports.append(port)

            port_count = len(target.open_ports)
            port_list = ", ".join(str(p) for p in target.open_ports[:15])
            suffix = "..." if port_count > 15 else ""
            self._emit("success", f"{port_count} open ports discovered: {port_list}{suffix}")

        except nmap.PortScannerError as e:
            self._emit("error", f"Nmap error during port scan: {e}")
        except Exception as e:
            self._emit("error", f"Unexpected error during port scan: {e}")

        return target

    # ──────────────────────────────────────────────
    # Banner Grabbing
    # ──────────────────────────────────────────────

    def grab_banners(self, target: Target) -> Target:
        """
        Grab service banners for more detailed version information.
        Runs the Nmap banner script against open ports.
        """
        if not target.open_ports:
            return target

        self._emit("info", "Grabbing service banners for detailed fingerprinting...")

        ports_str = ",".join(str(p) for p in target.open_ports[:50])  # Limit to 50 ports
        args = f"-sV --script=banner -p {ports_str}"

        try:
            self._nm.scan(hosts=target.ip, arguments=args)

            if target.ip in self._nm.all_hosts():
                host_data = self._nm[target.ip]
                for proto in host_data.all_protocols():
                    for port in host_data[proto]:
                        port_info = host_data[proto][port]
                        # Update existing service with banner info
                        service = target.get_service_by_port(port)
                        if service:
                            # Check for banner in script output
                            scripts = port_info.get("script", {})
                            if "banner" in scripts:
                                service.banner = scripts["banner"]

                            # Update version if we got better info
                            if port_info.get("version") and not service.version:
                                service.version = port_info["version"]
                            if port_info.get("product") and not service.product:
                                service.product = port_info["product"]
                            if port_info.get("cpe") and not service.cpe:
                                service.cpe = port_info["cpe"]

            self._emit("success", "Banner grabbing completed")

        except Exception as e:
            self._emit("warn", f"Banner grabbing partially failed: {e}")

        return target

    # ──────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────

    @staticmethod
    def is_nmap_installed() -> bool:
        """Check if nmap is installed on the system."""
        try:
            scanner = nmap.PortScanner()
            scanner.nmap_version()
            return True
        except nmap.PortScannerError:
            return False

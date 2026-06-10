"""
Docker Misconfigurations Module

Checks for exposed Docker API, daemon socket, and
container security issues accessible over the network.
"""

from __future__ import annotations

import json
import socket
from typing import Optional

from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class DockerModule(BaseModule):
    name = "Docker Misconfigurations"
    description = "Privileged containers, socket exposure"
    module_id = "docker"
    requires_auth = False

    # Docker API default ports
    DOCKER_PORTS = [2375, 2376, 4243]

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        self._emit("info", "Checking for exposed Docker API endpoints...")

        # 1. Check for Docker API on common ports
        for port in self.DOCKER_PORTS:
            if port in target.open_ports:
                finding = self._check_docker_api(target.ip, port)
                if finding:
                    findings.append(finding)

        # 2. Check for Docker service detected via Nmap
        for service in target.services:
            if "docker" in service.service_name.lower() or "docker" in service.product.lower():
                if service.port not in self.DOCKER_PORTS:
                    finding = self._check_docker_api(target.ip, service.port)
                    if finding:
                        findings.append(finding)

        return findings

    def _check_docker_api(self, ip: str, port: int) -> Optional[Finding]:
        """Check if Docker API is accessible without authentication."""
        try:
            import requests
            scheme = "https" if port == 2376 else "http"
            url = f"{scheme}://{ip}:{port}/version"

            response = requests.get(url, timeout=5, verify=False)

            if response.status_code == 200:
                try:
                    version_info = response.json()
                    docker_version = version_info.get("Version", "unknown")
                    api_version = version_info.get("ApiVersion", "unknown")
                except json.JSONDecodeError:
                    docker_version = "unknown"
                    api_version = "unknown"

                # Try to list containers
                containers_url = f"{scheme}://{ip}:{port}/containers/json?all=1"
                containers_resp = requests.get(containers_url, timeout=5, verify=False)
                container_count = 0
                privileged_containers = []

                if containers_resp.status_code == 200:
                    try:
                        containers = containers_resp.json()
                        container_count = len(containers)

                        # Check for privileged containers
                        for container in containers:
                            container_id = container.get("Id", "")[:12]
                            names = container.get("Names", [])
                            name = names[0] if names else container_id

                            # Inspect each container for privileged mode
                            inspect_url = f"{scheme}://{ip}:{port}/containers/{container_id}/json"
                            try:
                                inspect_resp = requests.get(inspect_url, timeout=5, verify=False)
                                if inspect_resp.status_code == 200:
                                    inspect_data = inspect_resp.json()
                                    host_config = inspect_data.get("HostConfig", {})
                                    if host_config.get("Privileged"):
                                        privileged_containers.append(name)
                            except Exception:
                                pass

                    except json.JSONDecodeError:
                        pass

                # Main finding: Docker API exposed
                return Finding(
                    title=f"Docker API Exposed Without Authentication on Port {port}",
                    description=(
                        f"The Docker daemon API is accessible without any authentication "
                        f"on port {port}. Docker version: {docker_version}, "
                        f"API version: {api_version}. "
                        f"Found {container_count} containers. "
                        f"This allows complete host takeover by creating a privileged "
                        f"container with host filesystem mounted."
                        + (f"\n\nPrivileged containers found: {', '.join(privileged_containers)}"
                           if privileged_containers else "")
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=10.0,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=(
                        f"Docker API responded on {scheme}://{ip}:{port}. "
                        f"Version: {docker_version}, Containers: {container_count}"
                    ),
                    remediation=(
                        "1. Never expose the Docker API to the network.\n"
                        "2. Remove -H tcp://0.0.0.0:2375 from Docker daemon flags.\n"
                        "3. If remote API access is needed, use TLS client certificates.\n"
                        "4. Use Docker socket proxy with limited API access."
                    ),
                )

        except ImportError:
            # Fall back to raw socket check
            return self._check_docker_api_socket(ip, port)
        except Exception as e:
            self._emit("warn", f"Docker API check on port {port} failed: {e}")

        return None

    def _check_docker_api_socket(self, ip: str, port: int) -> Optional[Finding]:
        """Fallback Docker API check using raw socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

            # Send HTTP GET for /version
            request = (
                f"GET /version HTTP/1.1\r\n"
                f"Host: {ip}:{port}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if "ApiVersion" in response or "docker" in response.lower():
                return Finding(
                    title=f"Docker API Exposed on Port {port}",
                    description=(
                        f"The Docker daemon API appears to be accessible on port {port} "
                        f"without authentication. This is a critical security issue."
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=10.0,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Docker API responded on port {port}",
                    remediation="Do not expose Docker API to the network. Use TLS certificates.",
                )
        except Exception:
            pass

        return None

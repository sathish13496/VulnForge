"""
Sensitive File Exposure Module

Checks for exposed sensitive files via HTTP services by probing
common paths for configuration files, backups, and credentials.
"""

from __future__ import annotations

import socket
from typing import Optional

from vulnforge.core.target import Finding, Severity, FindingStatus, Target
from vulnforge.modules.base_module import BaseModule


class SensitiveFilesModule(BaseModule):
    name = "Sensitive File Exposure"
    description = "Exposed configs, keys, backup files"
    module_id = "sensitive_files"
    requires_auth = False

    # Common paths to check on web servers
    SENSITIVE_PATHS = [
        # Version control
        ("/.git/HEAD", "Git Repository Exposed", Severity.CRITICAL, 9.1,
         "The .git directory is accessible, exposing full source code and commit history."),
        ("/.svn/entries", "SVN Repository Exposed", Severity.HIGH, 7.5,
         "The .svn directory is accessible, exposing source code."),

        # Configuration files
        ("/.env", "Environment File (.env) Exposed", Severity.CRITICAL, 9.1,
         "The .env file is accessible, likely containing API keys, database credentials, and secrets."),
        ("/config.php", "PHP Configuration File Exposed", Severity.HIGH, 7.5,
         "A PHP configuration file is accessible, potentially containing database credentials."),
        ("/wp-config.php", "WordPress Configuration Exposed", Severity.CRITICAL, 9.1,
         "WordPress configuration file with database credentials is accessible."),
        ("/web.config", "IIS/ASP.NET Configuration Exposed", Severity.HIGH, 7.5,
         "ASP.NET configuration file is accessible."),

        # Backup files
        ("/backup.sql", "Database Backup File Exposed", Severity.CRITICAL, 9.1,
         "A SQL backup file is accessible, potentially containing all database data."),
        ("/backup.tar.gz", "Backup Archive Exposed", Severity.HIGH, 7.5,
         "A backup archive is accessible."),
        ("/dump.sql", "Database Dump Exposed", Severity.CRITICAL, 9.1,
         "A database dump file is accessible."),

        # Server info
        ("/server-status", "Apache Server Status Exposed", Severity.MEDIUM, 5.3,
         "Apache server-status page is accessible, revealing active connections and server info."),
        ("/server-info", "Apache Server Info Exposed", Severity.MEDIUM, 5.3,
         "Apache server-info page is accessible, revealing server configuration."),
        ("/phpinfo.php", "PHP Info Page Exposed", Severity.MEDIUM, 5.3,
         "phpinfo() is accessible, revealing PHP configuration, paths, and loaded modules."),
        ("/info.php", "PHP Info Page Exposed", Severity.MEDIUM, 5.3,
         "phpinfo() is accessible."),

        # Admin panels
        ("/admin/", "Admin Panel Accessible", Severity.MEDIUM, 5.0,
         "An admin panel is accessible. Check if authentication is properly enforced."),
        ("/phpmyadmin/", "phpMyAdmin Accessible", Severity.HIGH, 7.5,
         "phpMyAdmin is accessible from the network, allowing database management."),
        ("/adminer.php", "Adminer Database Tool Exposed", Severity.HIGH, 7.5,
         "Adminer database management tool is accessible."),

        # Keys and certificates
        ("/id_rsa", "SSH Private Key Exposed", Severity.CRITICAL, 9.8,
         "An SSH private key is accessible via the web server."),
        ("/.ssh/authorized_keys", "SSH Authorized Keys Exposed", Severity.HIGH, 7.5,
         "SSH authorized_keys file is accessible."),

        # Debug/development
        ("/debug", "Debug Endpoint Exposed", Severity.MEDIUM, 5.3,
         "A debug endpoint is accessible."),
        ("/console", "Debug Console Exposed", Severity.CRITICAL, 9.1,
         "An interactive debug console (e.g., Werkzeug) is accessible."),
        ("/actuator", "Spring Boot Actuator Exposed", Severity.HIGH, 7.5,
         "Spring Boot Actuator endpoints are accessible, exposing internal application state."),
        ("/actuator/env", "Spring Boot Environment Exposed", Severity.CRITICAL, 9.1,
         "Spring Boot environment variables are accessible, potentially containing secrets."),
    ]

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        # Find HTTP services
        http_ports = []
        for service in target.services:
            if service.service_name in ("http", "https", "http-proxy"):
                http_ports.append((service.port, "https" if "ssl" in service.service_name or
                                   service.port == 443 else "http"))

        # Also check common HTTP ports even if not identified by Nmap
        for port in [80, 443, 8080, 8443, 8000, 3000]:
            if port in target.open_ports and not any(p[0] == port for p in http_ports):
                scheme = "https" if port in (443, 8443) else "http"
                http_ports.append((port, scheme))

        if not http_ports:
            self._emit("info", "No HTTP services found — skipping sensitive file checks")
            return findings

        self._emit("info", f"Checking {len(self.SENSITIVE_PATHS)} sensitive paths on "
                   f"{len(http_ports)} HTTP services...")

        for port, scheme in http_ports:
            for path, title, severity, cvss, description in self.SENSITIVE_PATHS:
                if self._check_path(target.ip, port, scheme, path):
                    url = f"{scheme}://{target.ip}:{port}{path}"
                    findings.append(Finding(
                        title=f"{title} ({url})",
                        description=description,
                        severity=severity,
                        cvss_score=cvss,
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"HTTP 200 OK returned for: {url}",
                        remediation=(
                            f"Block access to {path} in your web server configuration. "
                            f"For Apache: <Location {path}> Deny from all </Location>. "
                            f"For Nginx: location {path} {{ return 404; }}"
                        ),
                    ))

        # Check for directory listing
        for port, scheme in http_ports:
            if self._check_directory_listing(target.ip, port, scheme):
                findings.append(Finding(
                    title=f"Directory Listing Enabled on {scheme}://{target.ip}:{port}",
                    description=(
                        "The web server has directory listing enabled, allowing "
                        "anyone to browse the file structure and discover sensitive files."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Directory listing found on {scheme}://{target.ip}:{port}/",
                    remediation="Disable directory listing. Apache: 'Options -Indexes'. "
                               "Nginx: 'autoindex off;'",
                ))

        return findings

    def _check_path(self, ip: str, port: int, scheme: str, path: str) -> bool:
        """Check if a path returns HTTP 200."""
        try:
            import requests
            url = f"{scheme}://{ip}:{port}{path}"
            response = requests.get(url, timeout=5, verify=False,
                                   allow_redirects=False,
                                   headers={"User-Agent": "VulnForge/1.0"})
            # 200 OK and content length > 0 indicates the file exists
            return (response.status_code == 200 and
                    len(response.content) > 0 and
                    "404" not in response.text[:200].lower())
        except ImportError:
            return self._check_path_socket(ip, port, path)
        except Exception:
            return False

    def _check_path_socket(self, ip: str, port: int, path: str) -> bool:
        """Fallback path check using raw socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))

            request = (
                f"HEAD {path} HTTP/1.1\r\n"
                f"Host: {ip}:{port}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            return "200 OK" in response
        except Exception:
            return False

    def _check_directory_listing(self, ip: str, port: int, scheme: str) -> bool:
        """Check if directory listing is enabled."""
        try:
            import requests
            url = f"{scheme}://{ip}:{port}/"
            response = requests.get(url, timeout=5, verify=False,
                                   headers={"User-Agent": "VulnForge/1.0"})
            content = response.text.lower()
            # Common directory listing indicators
            return any(indicator in content for indicator in [
                "index of /", "directory listing", "parent directory",
                "<title>index of", "autoindex",
            ])
        except Exception:
            return False

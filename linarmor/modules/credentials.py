"""
Weak Credentials Module

Attempts to detect default/weak credentials on exposed services
by trying common username/password combinations.
"""

from __future__ import annotations

import socket
from typing import Optional

from linarmor.config import DEFAULT_PASSWORDS, DEFAULT_USERNAMES
from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class CredentialsModule(BaseModule):
    name = "Weak Credentials"
    description = "Default passwords, empty credentials"
    module_id = "credentials"
    requires_auth = False

    # Service-specific credential checks
    SERVICE_CHECKS = {
        "ssh": {"port": 22, "check_fn": "_check_ssh_creds"},
        "ftp": {"port": 21, "check_fn": "_check_ftp_creds"},
        "mysql": {"port": 3306, "check_fn": "_check_mysql_creds"},
        "redis": {"port": 6379, "check_fn": "_check_redis_noauth"},
    }

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        self._emit("info", "Checking for weak/default credentials on exposed services...")

        # 1. Check Redis for no-auth
        if 6379 in target.open_ports:
            finding = self._check_redis_noauth(target.ip)
            if finding:
                findings.append(finding)

        # 2. Check FTP for anonymous login
        if 21 in target.open_ports:
            finding = self._check_ftp_creds(target.ip)
            if finding:
                findings.append(finding)

        # 3. Check SSH for common weak passwords (limited attempts)
        if 22 in target.open_ports:
            ssh_findings = self._check_ssh_creds(target.ip)
            findings.extend(ssh_findings)

        # 4. Check MySQL for default credentials
        if 3306 in target.open_ports:
            finding = self._check_mysql_creds(target.ip)
            if finding:
                findings.append(finding)

        return findings

    def _check_redis_noauth(self, ip: str, port: int = 6379) -> Optional[Finding]:
        """Check if Redis is accessible without authentication."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.sendall(b"INFO server\r\n")
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if "redis_version" in response:
                return Finding(
                    title="Redis Accessible Without Authentication",
                    description=(
                        "Redis is accessible without any password. An attacker can "
                        "read/write data, execute Lua scripts, and potentially write "
                        "SSH authorized_keys to gain server access."
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Redis responded to INFO without auth. Response preview: "
                             f"{response[:200]}",
                    remediation="Set a strong password with 'requirepass' in redis.conf. "
                               "Bind to 127.0.0.1 and enable protected-mode.",
                )
        except Exception as e:
            self._emit("warn", f"Redis auth check failed: {e}")
        return None

    def _check_ftp_creds(self, ip: str, port: int = 21) -> Optional[Finding]:
        """Check for anonymous FTP login."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore")

            # Try anonymous login
            sock.sendall(b"USER anonymous\r\n")
            response = sock.recv(1024).decode("utf-8", errors="ignore")

            if "331" in response:  # Password required (but might accept anything)
                sock.sendall(b"PASS anonymous@example.com\r\n")
                response = sock.recv(1024).decode("utf-8", errors="ignore")

                if "230" in response:  # Login successful
                    sock.sendall(b"QUIT\r\n")
                    sock.close()
                    return Finding(
                        title="FTP Anonymous Login Successful",
                        description=(
                            "Anonymous FTP login is enabled and functional. "
                            "Anyone can access files on the FTP server without credentials."
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"Anonymous login succeeded. Banner: {banner.strip()}",
                        remediation="Disable anonymous FTP access in the FTP server configuration.",
                    )

            sock.sendall(b"QUIT\r\n")
            sock.close()
        except Exception as e:
            self._emit("warn", f"FTP credential check failed: {e}")
        return None

    def _check_ssh_creds(self, ip: str, port: int = 22) -> list[Finding]:
        """Check for weak SSH passwords (very limited — only root with top 5 passwords)."""
        findings = []

        try:
            import paramiko

            # Only test root with top 5 most common passwords to avoid lockouts
            test_passwords = DEFAULT_PASSWORDS[:5]

            for password in test_passwords:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        ip, port=port,
                        username="root",
                        password=password,
                        timeout=5,
                        banner_timeout=5,
                        auth_timeout=5,
                        look_for_keys=False,
                        allow_agent=False,
                    )
                    # If we get here, login succeeded!
                    client.close()
                    findings.append(Finding(
                        title=f"SSH Root Login with Weak Password: '{password}'",
                        description=(
                            f"Root login via SSH succeeded using the weak password "
                            f"'{password}'. This allows full system compromise."
                        ),
                        severity=Severity.CRITICAL,
                        cvss_score=10.0,
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"SSH root login succeeded with password: {password}",
                        remediation=(
                            "Change the root password immediately. Disable root SSH login "
                            "with 'PermitRootLogin no' in sshd_config. Use key-based auth."
                        ),
                    ))
                    break  # Found one, no need to continue
                except paramiko.AuthenticationException:
                    continue  # Wrong password, try next
                except Exception:
                    break  # Connection error, stop trying

        except ImportError:
            self._emit("warn", "paramiko not installed — skipping SSH credential check")

        return findings

    def _check_mysql_creds(self, ip: str, port: int = 3306) -> Optional[Finding]:
        """Check if MySQL accepts root with empty password."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            response = sock.recv(4096)
            sock.close()

            # MySQL greeting packet analysis
            decoded = response.decode("utf-8", errors="ignore")
            if "mysql" in decoded.lower() or len(response) > 4:
                # We detected a MySQL service, but full auth check requires
                # mysql-connector-python. Flag it as needing review.
                return Finding(
                    title="MySQL Server Accessible — Credential Check Recommended",
                    description=(
                        "MySQL server is accessible on the network. "
                        "Default installations sometimes have root with no password. "
                        "Manual verification is recommended."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=6.5,
                    module=self.module_id,
                    status=FindingStatus.REVIEW,
                    evidence=f"MySQL responded on port {port}",
                    remediation="Ensure all MySQL accounts have strong passwords. "
                               "Run 'mysql_secure_installation' on the server.",
                )
        except Exception as e:
            self._emit("warn", f"MySQL credential check failed: {e}")
        return None

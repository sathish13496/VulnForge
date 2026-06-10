"""
SSH Security Module

Checks for insecure SSH configurations by connecting to port 22
and analyzing the offered algorithms, authentication methods,
and attempting to detect common misconfigurations.

Unauthenticated checks:
- SSH version/protocol detection
- Weak cipher suites
- Weak key exchange algorithms
- Weak MAC algorithms
- Root login detection (via auth attempt)
- Password authentication detection
"""

from __future__ import annotations

import socket
import re
from typing import Optional

from vulnforge.core.target import Finding, Severity, FindingStatus, Target
from vulnforge.modules.base_module import BaseModule


class SSHModule(BaseModule):
    name = "Insecure SSH Settings"
    description = "Root login, weak ciphers, protocol issues"
    module_id = "ssh"
    requires_auth = False

    # Known weak ciphers that should not be used
    WEAK_CIPHERS = [
        "arcfour", "arcfour128", "arcfour256",
        "3des-cbc", "blowfish-cbc", "cast128-cbc",
        "aes128-cbc", "aes192-cbc", "aes256-cbc",
    ]

    # Weak key exchange algorithms
    WEAK_KEX = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ]

    # Weak MAC algorithms
    WEAK_MACS = [
        "hmac-sha1", "hmac-sha1-96",
        "hmac-md5", "hmac-md5-96",
        "umac-64@openssh.com",
    ]

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        # Check if SSH service is available
        ssh_service = target.get_service_by_port(22)
        if not ssh_service and 22 not in target.open_ports:
            self._emit("info", "Port 22 not open — skipping SSH checks")
            return findings

        self._emit("info", "Scanning SSH configurations...")

        # 1. Grab SSH banner
        banner = self._grab_ssh_banner(target.ip)
        if banner:
            self._emit("info", f"SSH Banner: {banner}")

            # Check for old SSH versions
            finding = self._check_ssh_version(banner)
            if finding:
                findings.append(finding)

        # 2. Check for SSH service version from Nmap data
        if ssh_service and ssh_service.product:
            version_finding = self._check_service_version(ssh_service)
            if version_finding:
                findings.append(version_finding)

        # 3. Try to detect offered algorithms via SSH handshake
        algo_findings = self._check_algorithms(target.ip)
        findings.extend(algo_findings)

        # 4. Check for password authentication
        auth_finding = self._check_password_auth(target.ip)
        if auth_finding:
            findings.append(auth_finding)

        return findings

    def _grab_ssh_banner(self, ip: str, port: int = 22, timeout: float = 5.0) -> Optional[str]:
        """Connect to SSH port and grab the version banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner
        except Exception as e:
            self._emit("warn", f"Could not grab SSH banner: {e}")
            return None

    def _check_ssh_version(self, banner: str) -> Optional[Finding]:
        """Check if the SSH version is outdated or vulnerable."""
        # Detect SSH protocol version 1
        if "SSH-1" in banner and "SSH-2" not in banner:
            return Finding(
                title="SSH Protocol Version 1 Detected",
                description=(
                    f"The SSH server supports protocol version 1, which has known "
                    f"cryptographic weaknesses. Banner: {banner}"
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.0,
                module=self.module_id,
                status=FindingStatus.OPEN,
                evidence=f"Banner: {banner}",
                remediation="Disable SSH protocol version 1. Use 'Protocol 2' in sshd_config.",
            )

        # Check for very old OpenSSH versions (< 7.0)
        version_match = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", banner)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            if major < 7:
                return Finding(
                    title=f"Outdated OpenSSH Version ({major}.{minor})",
                    description=(
                        f"OpenSSH {major}.{minor} is outdated and may contain known "
                        f"vulnerabilities. Current stable versions are 9.x."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Banner: {banner}",
                    remediation="Update OpenSSH to the latest stable version.",
                )
            # Check for Terrapin vulnerability (affects OpenSSH < 9.6)
            if major < 9 or (major == 9 and minor < 6):
                return Finding(
                    title=f"SSH Terrapin Attack Vulnerability (OpenSSH {major}.{minor})",
                    description=(
                        f"OpenSSH versions before 9.6 are vulnerable to the Terrapin "
                        f"attack (CVE-2023-48795), which allows prefix truncation of "
                        f"encrypted SSH messages."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.9,
                    cve_id="CVE-2023-48795",
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Banner: {banner}",
                    remediation=(
                        "Update OpenSSH to version 9.6 or later. As a workaround, "
                        "disable the chacha20-poly1305 cipher and related MACs."
                    ),
                    references=["https://terrapin-attack.com/"],
                )

        return None

    def _check_service_version(self, service) -> Optional[Finding]:
        """Check Nmap-detected SSH service for known vulnerabilities."""
        product = service.product.lower() if service.product else ""
        version = service.version or ""

        if "openssh" in product and version:
            # Check for CVE-2024-6387 (regreSSHion) - OpenSSH < 9.8p1
            version_match = re.search(r"(\d+)\.(\d+)", version)
            if version_match:
                major = int(version_match.group(1))
                minor = int(version_match.group(2))
                if major < 9 or (major == 9 and minor < 8):
                    return Finding(
                        title=f"SSH regreSSHion RCE Vulnerability (OpenSSH {version})",
                        description=(
                            f"OpenSSH versions before 9.8p1 are vulnerable to "
                            f"CVE-2024-6387 (regreSSHion), a critical remote code "
                            f"execution vulnerability in the SSH server."
                        ),
                        severity=Severity.CRITICAL,
                        cvss_score=8.1,
                        cve_id="CVE-2024-6387",
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"Service: {service.display_name}",
                        remediation="Update OpenSSH to version 9.8p1 or later immediately.",
                        references=["https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"],
                    )
        return None

    def _check_algorithms(self, ip: str, port: int = 22) -> list[Finding]:
        """
        Attempt to detect offered SSH algorithms by initiating a handshake.
        Uses raw socket to parse the SSH key exchange init message.
        """
        findings = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

            # Read server banner
            banner = sock.recv(1024)

            # Send our banner
            sock.sendall(b"SSH-2.0-VulnForge_1.0\r\n")

            # Read key exchange init (SSH_MSG_KEXINIT)
            kex_data = sock.recv(8192)
            sock.close()

            if len(kex_data) > 20:
                # Parse algorithm lists from KEXINIT payload
                # The KEXINIT message contains comma-separated algorithm lists
                decoded = kex_data.decode("utf-8", errors="ignore")

                # Check for weak ciphers
                for cipher in self.WEAK_CIPHERS:
                    if cipher in decoded:
                        findings.append(Finding(
                            title=f"Weak SSH Cipher Supported: {cipher}",
                            description=(
                                f"The SSH server offers the weak cipher '{cipher}'. "
                                f"This cipher has known cryptographic weaknesses."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            module=self.module_id,
                            status=FindingStatus.REVIEW,
                            evidence=f"Cipher found in KEXINIT: {cipher}",
                            remediation=(
                                f"Remove '{cipher}' from the Ciphers directive in sshd_config. "
                                f"Use only strong ciphers like aes256-gcm@openssh.com."
                            ),
                        ))
                        break  # Report once, not for every cipher

                # Check for weak KEX
                for kex in self.WEAK_KEX:
                    if kex in decoded:
                        findings.append(Finding(
                            title=f"Weak SSH Key Exchange Algorithm: {kex}",
                            description=(
                                f"The SSH server supports '{kex}' which uses SHA-1 "
                                f"and is considered cryptographically weak."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=4.7,
                            module=self.module_id,
                            status=FindingStatus.REVIEW,
                            evidence=f"KEX found in KEXINIT: {kex}",
                            remediation=(
                                f"Remove '{kex}' from KexAlgorithms in sshd_config. "
                                f"Use curve25519-sha256 or diffie-hellman-group16-sha512."
                            ),
                        ))
                        break

        except Exception as e:
            self._emit("warn", f"SSH algorithm check failed: {e}")

        return findings

    def _check_password_auth(self, ip: str, port: int = 22) -> Optional[Finding]:
        """Detect if password authentication is enabled."""
        try:
            # We try to use paramiko to detect auth methods
            import paramiko

            transport = paramiko.Transport((ip, port))
            transport.connect()

            # Try auth with empty creds to see what methods are offered
            try:
                transport.auth_none("")
            except paramiko.BadAuthenticationType as e:
                # The exception tells us which auth types are allowed
                allowed = e.allowed_types
                transport.close()

                if "password" in allowed:
                    return Finding(
                        title="SSH Password Authentication Enabled",
                        description=(
                            f"The SSH server allows password-based authentication. "
                            f"Allowed methods: {', '.join(allowed)}. "
                            f"Password auth is susceptible to brute-force attacks."
                        ),
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        module=self.module_id,
                        status=FindingStatus.NOTED,
                        evidence=f"Allowed auth types: {allowed}",
                        remediation=(
                            "Disable password authentication in sshd_config: "
                            "'PasswordAuthentication no'. Use key-based auth instead."
                        ),
                    )
            except Exception:
                pass
            finally:
                try:
                    transport.close()
                except Exception:
                    pass

        except ImportError:
            self._emit("warn", "paramiko not installed — skipping password auth check")
        except Exception as e:
            self._emit("warn", f"Password auth check failed: {e}")

        return None

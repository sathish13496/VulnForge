"""
NFS Misconfigurations Module

Checks for insecure NFS exports by querying the target's
mountd/portmapper for exported shares.
"""

from __future__ import annotations

import subprocess
from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class NFSModule(BaseModule):
    name = "NFS Misconfigurations"
    description = "Open exports, no_root_squash, insecure mounts"
    module_id = "nfs"
    requires_auth = False

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        # Check if NFS-related ports are open (111=rpcbind, 2049=nfs)
        nfs_ports = [p for p in [111, 2049] if p in target.open_ports]
        if not nfs_ports:
            self._emit("info", "NFS ports not open — skipping NFS checks")
            return findings

        self._emit("info", "Checking NFS exports for misconfigurations...")

        # Use showmount to list exports
        exports = self._get_nfs_exports(target.ip)

        if exports is None:
            self._emit("warn", "Could not query NFS exports (showmount not available)")
            # Still flag the open NFS port
            if 2049 in target.open_ports:
                findings.append(Finding(
                    title="NFS Service Exposed on Port 2049",
                    description=(
                        "NFS service is running and accessible. Could not enumerate "
                        "exports (showmount may not be installed). Manual review recommended."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.0,
                    module=self.module_id,
                    status=FindingStatus.REVIEW,
                    evidence="NFS port 2049 is open",
                    remediation="Review /etc/exports on the target server.",
                ))
            return findings

        if not exports:
            self._emit("info", "No NFS exports found")
            return findings

        # Analyze each export
        for export_path, allowed_hosts in exports:
            self._emit("info", f"Found NFS export: {export_path} -> {allowed_hosts}")

            # Check for world-accessible exports
            if allowed_hosts.strip() == "*" or not allowed_hosts.strip():
                findings.append(Finding(
                    title=f"NFS Export '{export_path}' Accessible to Everyone",
                    description=(
                        f"The NFS export '{export_path}' is shared with all hosts (*). "
                        f"Anyone on the network can mount this share and access files."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    module=self.module_id,
                    status=FindingStatus.OPEN,
                    evidence=f"Export: {export_path} -> {allowed_hosts}",
                    remediation=(
                        f"Restrict NFS export access to specific IPs/subnets in /etc/exports. "
                        f"Example: {export_path} 192.168.1.0/24(ro,sync,root_squash)"
                    ),
                ))

            # Check for sensitive directories being exported
            sensitive_paths = ["/", "/etc", "/home", "/root", "/var", "/opt", "/tmp"]
            for sensitive in sensitive_paths:
                if export_path == sensitive or export_path.startswith(sensitive + "/"):
                    severity = Severity.CRITICAL if sensitive in ("/", "/etc", "/root") else Severity.HIGH
                    cvss = 9.1 if sensitive in ("/", "/etc", "/root") else 7.5
                    findings.append(Finding(
                        title=f"Sensitive Directory '{export_path}' Shared via NFS",
                        description=(
                            f"The sensitive directory '{export_path}' is exported via NFS "
                            f"to {allowed_hosts}. This may expose configuration files, "
                            f"credentials, or user data."
                        ),
                        severity=severity,
                        cvss_score=cvss,
                        module=self.module_id,
                        status=FindingStatus.OPEN,
                        evidence=f"Export: {export_path} -> {allowed_hosts}",
                        remediation="Do not export sensitive system directories via NFS.",
                    ))
                    break  # Only flag once per export

        return findings

    def _get_nfs_exports(self, ip: str) -> list[tuple[str, str]] | None:
        """
        Query NFS exports using showmount -e.
        Returns list of (export_path, allowed_hosts) or None if showmount is not available.
        """
        try:
            result = subprocess.run(
                ["showmount", "-e", ip],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                return []

            exports = []
            lines = result.stdout.strip().split("\n")

            # Skip header line ("Export list for <ip>:")
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 2:
                    export_path = parts[0]
                    allowed_hosts = " ".join(parts[1:])
                    exports.append((export_path, allowed_hosts))
                elif len(parts) == 1:
                    exports.append((parts[0], "*"))

            return exports

        except FileNotFoundError:
            return None  # showmount not installed
        except subprocess.TimeoutExpired:
            self._emit("warn", "showmount timed out")
            return None
        except Exception as e:
            self._emit("warn", f"showmount error: {e}")
            return None

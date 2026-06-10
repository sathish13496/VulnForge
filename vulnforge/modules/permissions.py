"""
Weak Permissions Module

Checks for insecure file and directory permissions.
Requires authenticated (SSH) access to the target system.
"""

from __future__ import annotations

from vulnforge.core.target import Finding, Severity, FindingStatus, Target
from vulnforge.modules.base_module import BaseModule


class PermissionsModule(BaseModule):
    name = "Weak Permissions"
    description = "World-writable files, insecure directories"
    module_id = "permissions"
    requires_auth = True

    # Critical files that should have strict permissions
    CRITICAL_FILES = {
        "/etc/passwd": "644",
        "/etc/shadow": "640",
        "/etc/sudoers": "440",
        "/etc/ssh/sshd_config": "600",
        "/etc/crontab": "644",
        "/root/.ssh/authorized_keys": "600",
    }

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        self._emit("warn", "Permissions module requires authenticated access — "
                   "returning informational finding")

        if target.os_family == "Linux" or "linux" in target.os_name.lower():
            findings.append(Finding(
                title="File Permission Check — Requires Authenticated Scan",
                description=(
                    "Checking file permissions (world-writable files, insecure /etc/shadow, "
                    "/etc/passwd, sudoers, etc.) requires SSH access to the target. "
                    "Run an authenticated scan for full permission analysis."
                ),
                severity=Severity.INFO,
                cvss_score=0.0,
                module=self.module_id,
                status=FindingStatus.REVIEW,
                evidence=f"Target OS: {target.os_name or 'Linux detected'}",
                remediation="Run an authenticated scan with SSH credentials.",
            ))

        return findings

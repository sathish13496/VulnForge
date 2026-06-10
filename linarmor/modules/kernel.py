"""
Kernel Privilege Escalation Module

Checks the detected kernel version against known CVEs for
local privilege escalation vulnerabilities.
"""

from __future__ import annotations

import re
from typing import Optional

from linarmor.core.target import Finding, Severity, FindingStatus, Target
from linarmor.modules.base_module import BaseModule


class KernelModule(BaseModule):
    name = "Kernel Privilege Escalation"
    description = "Known kernel CVEs, exploit suggestions"
    module_id = "kernel"
    requires_auth = False

    # Known kernel privilege escalation vulnerabilities
    # Mapped by version range: (min_version, max_version, cve, title, cvss, desc, remediation)
    KERNEL_CVES = [
        {
            "cve": "CVE-2022-0847",
            "name": "DirtyPipe",
            "min_version": (5, 8, 0),
            "max_version": (5, 16, 10),
            "cvss": 7.8,
            "description": (
                "DirtyPipe allows overwriting data in arbitrary read-only files. "
                "This can be exploited to inject code into root processes and "
                "escalate privileges to root."
            ),
            "remediation": "Update the kernel to 5.16.11, 5.15.25, or 5.10.102.",
            "references": ["https://dirtypipe.cm4all.com/"],
        },
        {
            "cve": "CVE-2021-4034",
            "name": "PwnKit (Polkit pkexec)",
            "min_version": (2, 6, 0),
            "max_version": (99, 99, 99),  # Affects all — it's a userspace issue
            "cvss": 7.8,
            "description": (
                "A local privilege escalation vulnerability in polkit's pkexec "
                "utility. Any unprivileged user can exploit this to gain full "
                "root privileges. Affects virtually all Linux distributions."
            ),
            "remediation": (
                "Update polkit to a patched version. As a workaround, remove "
                "the SUID bit: chmod 0755 /usr/bin/pkexec"
            ),
            "references": ["https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt"],
            "check_type": "pkexec",  # Special check flag
        },
        {
            "cve": "CVE-2022-2588",
            "name": "Dirty Cred",
            "min_version": (5, 0, 0),
            "max_version": (5, 19, 1),
            "cvss": 7.8,
            "description": (
                "A use-after-free vulnerability in the cls_route filter "
                "implementation that can be exploited for local privilege escalation."
            ),
            "remediation": "Update the kernel to the latest stable version.",
            "references": [],
        },
        {
            "cve": "CVE-2023-0386",
            "name": "OverlayFS Privilege Escalation",
            "min_version": (5, 11, 0),
            "max_version": (6, 2, 0),
            "cvss": 7.8,
            "description": (
                "An OverlayFS vulnerability allows local users to gain elevated "
                "privileges by exploiting improper handling of setuid files."
            ),
            "remediation": "Update the kernel. Restrict access to user namespaces.",
            "references": [],
        },
        {
            "cve": "CVE-2023-32233",
            "name": "Netfilter nf_tables Use-After-Free",
            "min_version": (5, 0, 0),
            "max_version": (6, 3, 1),
            "cvss": 7.8,
            "description": (
                "A use-after-free vulnerability in Netfilter nf_tables allows "
                "local attackers to escalate privileges to root."
            ),
            "remediation": "Update the kernel to 6.3.2 or later.",
            "references": [],
        },
        {
            "cve": "CVE-2021-3156",
            "name": "Baron Samedit (sudo heap overflow)",
            "min_version": (2, 6, 0),
            "max_version": (99, 99, 99),  # Userspace - sudo issue
            "cvss": 7.8,
            "description": (
                "A heap-based buffer overflow in sudo's argument parsing allows "
                "any local user to escalate to root without authentication. "
                "Affects sudo versions 1.8.2 through 1.8.31p2 and 1.9.0 through 1.9.5p1."
            ),
            "remediation": "Update sudo to version 1.9.5p2 or later.",
            "references": ["https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt"],
            "check_type": "sudo",
        },
        {
            "cve": "CVE-2016-5195",
            "name": "Dirty COW",
            "min_version": (2, 6, 22),
            "max_version": (4, 8, 2),
            "cvss": 7.8,
            "description": (
                "A race condition in the kernel's memory subsystem allows "
                "local privilege escalation by writing to read-only memory mappings."
            ),
            "remediation": "Update the kernel to 4.8.3 or later.",
            "references": ["https://dirtycow.ninja/"],
        },
        {
            "cve": "CVE-2024-1086",
            "name": "Netfilter nf_tables Use-After-Free (2024)",
            "min_version": (5, 14, 0),
            "max_version": (6, 7, 1),
            "cvss": 7.8,
            "description": (
                "A use-after-free vulnerability in the Netfilter nf_tables "
                "component allows local privilege escalation. A public exploit "
                "achieves reliable root access on most affected kernels."
            ),
            "remediation": "Update the kernel to 6.7.2 or apply vendor patches.",
            "references": ["https://pwning.tech/nftables/"],
        },
    ]

    def scan(self, target: Target) -> list[Finding]:
        findings = []

        self._emit("info", "Checking kernel version for known privilege escalation CVEs...")

        # Try to get kernel version from OS detection
        kernel_version = self._extract_kernel_version(target)

        if kernel_version:
            self._emit("info", f"Detected kernel version: {kernel_version}")
            version_tuple = self._parse_version(kernel_version)

            if version_tuple:
                for cve_info in self.KERNEL_CVES:
                    # Skip userspace checks (pkexec, sudo) — they need separate detection
                    if cve_info.get("check_type") in ("pkexec", "sudo"):
                        continue

                    if self._version_in_range(version_tuple, cve_info["min_version"], cve_info["max_version"]):
                        findings.append(Finding(
                            title=f"Kernel {kernel_version} — {cve_info['name']} Vulnerability",
                            description=cve_info["description"],
                            severity=Severity.CRITICAL if cve_info["cvss"] >= 9.0 else Severity.HIGH,
                            cvss_score=cve_info["cvss"],
                            cve_id=cve_info["cve"],
                            module=self.module_id,
                            status=FindingStatus.OPEN,
                            evidence=f"Kernel version: {kernel_version}",
                            remediation=cve_info["remediation"],
                            references=cve_info.get("references", []),
                        ))
        else:
            self._emit("warn", "Could not determine kernel version from OS fingerprint")

            # Still check for userspace vulnerabilities based on OS detection
            if target.os_name:
                self._emit("info", f"OS detected: {target.os_name} — checking for known OS-level issues")

        # Check for userspace privilege escalation (pkexec, sudo)
        # These affect virtually all Linux systems unless patched
        if target.os_family == "Linux" or "linux" in target.os_name.lower():
            for cve_info in self.KERNEL_CVES:
                if cve_info.get("check_type") == "pkexec":
                    findings.append(Finding(
                        title=f"Potential {cve_info['name']} Vulnerability",
                        description=(
                            f"{cve_info['description']} "
                            f"Note: This requires local access to verify. "
                            f"Check if /usr/bin/pkexec has the SUID bit set."
                        ),
                        severity=Severity.HIGH,
                        cvss_score=cve_info["cvss"],
                        cve_id=cve_info["cve"],
                        module=self.module_id,
                        status=FindingStatus.REVIEW,
                        evidence=f"Target OS: {target.os_name or 'Linux'}",
                        remediation=cve_info["remediation"],
                        references=cve_info.get("references", []),
                    ))

        return findings

    def _extract_kernel_version(self, target: Target) -> Optional[str]:
        """Extract kernel version from Nmap OS detection or service banners."""
        # From Nmap OS detection
        if target.os_name:
            # Try to find kernel version in OS name
            match = re.search(r"(\d+\.\d+\.\d+[-.\w]*)", target.os_name)
            if match:
                return match.group(1)

        # From kernel_version if already set
        if target.kernel_version:
            return target.kernel_version

        # From service banners (some services leak OS info)
        for service in target.services:
            if service.extra_info:
                match = re.search(r"Linux\s+(\d+\.\d+\.\d+[-.\w]*)", service.extra_info)
                if match:
                    return match.group(1)

        return None

    @staticmethod
    def _parse_version(version_str: str) -> Optional[tuple[int, ...]]:
        """Parse a version string like '5.4.0-42-generic' into (5, 4, 0)."""
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return None

    @staticmethod
    def _version_in_range(version: tuple, min_ver: tuple, max_ver: tuple) -> bool:
        """Check if a version tuple falls within the vulnerable range."""
        return min_ver <= version <= max_ver

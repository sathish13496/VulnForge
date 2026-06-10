"""
LinArmor CVE Matcher

Matches discovered services/software against the local CVE database
to find known vulnerabilities.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from linarmor.core.target import Finding, Severity, FindingStatus, Service, Target
from linarmor.cve.database import CVEDatabase
from linarmor.cve.models import CVEEntry
from linarmor.config import get_severity

logger = logging.getLogger("linarmor.cve.matcher")


class CVEMatcher:
    """
    Matches discovered services against the CVE database.

    Pipeline:
        1. Extract product + version from Nmap service data
        2. Convert to CPE string
        3. Query local CVE database
        4. Generate Finding objects for matches

    Usage:
        matcher = CVEMatcher()
        findings = matcher.match_target(target)
    """

    # Common product name mappings (Nmap product → CVE database product name)
    PRODUCT_ALIASES = {
        "openssh": "openssh",
        "apache": "apache_http_server",
        "apache httpd": "apache_http_server",
        "nginx": "nginx",
        "mysql": "mysql",
        "mariadb": "mariadb",
        "postgresql": "postgresql",
        "redis": "redis",
        "vsftpd": "vsftpd",
        "proftpd": "proftpd",
        "pure-ftpd": "pure-ftpd",
        "samba": "samba",
        "dovecot": "dovecot",
        "postfix": "postfix",
        "exim": "exim",
        "bind": "bind",
        "isc bind": "bind",
        "docker": "docker",
        "php": "php",
        "python": "python",
        "node.js": "node.js",
        "tomcat": "tomcat",
        "jenkins": "jenkins",
        "grafana": "grafana",
        "wordpress": "wordpress",
    }

    def __init__(self, db: Optional[CVEDatabase] = None):
        self._db = db or CVEDatabase()
        try:
            self._db.initialize()
        except Exception as e:
            logger.warning(f"Could not initialize CVE database: {e}")

    def match_target(self, target: Target) -> list[Finding]:
        """
        Match all services on a target against the CVE database.
        Returns a list of Finding objects for matched CVEs.
        """
        findings = []

        for service in target.services:
            if service.product:
                service_findings = self.match_service(service)
                findings.extend(service_findings)

        return findings

    def match_service(self, service: Service) -> list[Finding]:
        """Match a single service against the CVE database."""
        findings = []

        product = self._normalize_product(service.product)
        version = service.version

        if not product:
            return findings

        # Search by CPE if available
        if service.cpe:
            cve_entries = self._db.search_by_cpe(service.cpe)
        else:
            cve_entries = self._db.search_by_product(product, version)

        # Convert CVE entries to findings
        for cve in cve_entries[:10]:  # Limit to top 10 per service
            severity = self._cvss_to_severity(cve.cvss_score)
            findings.append(Finding(
                title=f"{service.display_name} — {cve.cve_id}",
                description=cve.description[:500],  # Truncate long descriptions
                severity=severity,
                cvss_score=cve.cvss_score,
                cve_id=cve.cve_id,
                module="cve_matcher",
                status=FindingStatus.OPEN if cve.cvss_score >= 7.0 else FindingStatus.REVIEW,
                evidence=f"Service: {service.display_name} on port {service.port}",
                remediation=f"Update {service.product} to the latest patched version.",
                references=cve.references[:3],
            ))

        return findings

    def lookup_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Look up a specific CVE by ID."""
        return self._db.get_cve(cve_id)

    def get_db_stats(self) -> dict:
        """Get CVE database statistics."""
        return self._db.get_stats()

    def _normalize_product(self, product: str) -> str:
        """Normalize a product name for database lookup."""
        product_lower = product.lower().strip()

        # Check aliases
        for alias, canonical in self.PRODUCT_ALIASES.items():
            if alias in product_lower:
                return canonical

        # Remove common suffixes
        product_lower = re.sub(r"\s+(server|daemon|service)$", "", product_lower)
        return product_lower

    @staticmethod
    def _cvss_to_severity(cvss_score: float) -> Severity:
        """Convert CVSS score to Severity enum."""
        severity_str = get_severity(cvss_score)
        return Severity(severity_str)

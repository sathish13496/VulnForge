"""
LinArmor CVE Data Models

Data structures for CVE entries and CPE matching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEEntry:
    """Represents a single CVE vulnerability entry."""
    cve_id: str                        # e.g., "CVE-2022-0847"
    description: str = ""
    cvss_v3_score: float = 0.0
    cvss_v2_score: float = 0.0
    severity: str = ""                 # CRITICAL, HIGH, MEDIUM, LOW
    published_date: str = ""
    last_modified_date: str = ""
    cpe_matches: list[str] = field(default_factory=list)  # CPE strings this CVE affects
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False

    @property
    def cvss_score(self) -> float:
        """Return the best available CVSS score (prefer v3)."""
        return self.cvss_v3_score if self.cvss_v3_score > 0 else self.cvss_v2_score

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v2_score": self.cvss_v2_score,
            "severity": self.severity,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "cpe_matches": self.cpe_matches,
            "references": self.references[:5],  # Limit references
            "exploit_available": self.exploit_available,
        }


@dataclass
class CPEMatch:
    """Represents a CPE (Common Platform Enumeration) match criteria."""
    cpe_uri: str                       # e.g., "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*"
    vendor: str = ""                   # e.g., "openbsd"
    product: str = ""                  # e.g., "openssh"
    version: str = ""                  # e.g., "8.2"
    version_start: Optional[str] = None
    version_end: Optional[str] = None
    vulnerable: bool = True

    @classmethod
    def from_cpe_uri(cls, cpe_uri: str) -> "CPEMatch":
        """Parse a CPE 2.3 URI into components."""
        parts = cpe_uri.split(":")
        if len(parts) >= 6:
            return cls(
                cpe_uri=cpe_uri,
                vendor=parts[3] if len(parts) > 3 else "",
                product=parts[4] if len(parts) > 4 else "",
                version=parts[5] if len(parts) > 5 and parts[5] != "*" else "",
            )
        return cls(cpe_uri=cpe_uri)

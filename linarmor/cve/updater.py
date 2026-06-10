"""
LinArmor NVD Feed Updater

Downloads CVE data from the NVD (National Vulnerability Database)
and populates the local SQLite database.
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from linarmor.config import DATA_DIR, NVD_DIR, NVD_API_BASE
from linarmor.cve.database import CVEDatabase
from linarmor.cve.models import CVEEntry

logger = logging.getLogger("linarmor.cve.updater")


class NVDUpdater:
    """
    Downloads and processes NVD CVE feeds into the local database.

    Usage:
        updater = NVDUpdater(log_callback=print)
        updater.update()  # Full update from NVD
    """

    # NVD JSON feed files (yearly archives)
    NVD_FEED_YEARS = list(range(2002, datetime.now().year + 1))

    def __init__(
        self,
        db: Optional[CVEDatabase] = None,
        log_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self._db = db or CVEDatabase()
        self._log = log_callback or (lambda level, msg: logger.info(msg))

    def update(self) -> dict:
        """
        Download and process NVD feeds.

        Returns:
            dict with update statistics.
        """
        self._db.initialize()
        NVD_DIR.mkdir(parents=True, exist_ok=True)

        stats = {"total_processed": 0, "total_inserted": 0, "errors": 0}

        self._log("info", "Starting CVE database update from NVD...")

        try:
            import requests

            # Download recent/modified feed first (smaller, most relevant)
            for feed_name in ["recent", "modified"]:
                url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{feed_name}.json.gz"
                self._log("info", f"Downloading NVD feed: {feed_name}")

                try:
                    response = requests.get(url, timeout=60, stream=True)
                    if response.status_code == 200:
                        feed_path = NVD_DIR / f"nvdcve-1.1-{feed_name}.json.gz"
                        with open(feed_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)

                        count = self._process_feed(feed_path)
                        stats["total_inserted"] += count
                        self._log("success", f"Processed {count} CVEs from {feed_name} feed")
                    else:
                        self._log("warn", f"Failed to download {feed_name} feed: HTTP {response.status_code}")
                        stats["errors"] += 1
                except Exception as e:
                    self._log("warn", f"Error downloading {feed_name} feed: {e}")
                    stats["errors"] += 1

            # Update metadata
            self._db.set_metadata("last_update", datetime.now().isoformat())
            self._db.set_metadata("update_stats", json.dumps(stats))

            db_stats = self._db.get_stats()
            self._log("success", f"CVE database updated: {db_stats['total_cves']} total CVEs")

        except ImportError:
            self._log("error", "requests library not installed — cannot download NVD feeds")
            self._log("info", "Install with: pip install requests")
            stats["errors"] += 1

        return stats

    def update_from_api(self, keyword: Optional[str] = None) -> list[CVEEntry]:
        """
        Fetch CVEs from the NVD 2.0 API (for targeted lookups).

        Args:
            keyword: Search keyword (e.g., "openssh")

        Returns:
            List of CVEEntry objects.
        """
        entries = []

        try:
            import requests

            params = {"resultsPerPage": 50}
            if keyword:
                params["keywordSearch"] = keyword

            self._log("info", f"Querying NVD API for: {keyword or 'recent CVEs'}")
            response = requests.get(NVD_API_BASE, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    entry = self._parse_nvd_api_entry(cve_data)
                    if entry:
                        entries.append(entry)
                        self._db.insert_cve(entry)

                self._db._get_connection().commit()
                self._log("success", f"Fetched {len(entries)} CVEs from NVD API")
            else:
                self._log("warn", f"NVD API returned HTTP {response.status_code}")

        except ImportError:
            self._log("error", "requests library not installed")
        except Exception as e:
            self._log("error", f"NVD API query failed: {e}")

        return entries

    def _process_feed(self, feed_path: Path) -> int:
        """Process a downloaded NVD JSON feed file."""
        count = 0

        try:
            if feed_path.suffix == ".gz":
                with gzip.open(feed_path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(feed_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

            cve_items = data.get("CVE_Items", [])
            batch = []

            for item in cve_items:
                entry = self._parse_nvd_feed_entry(item)
                if entry:
                    batch.append(entry)
                    count += 1

                    # Batch insert every 1000 entries
                    if len(batch) >= 1000:
                        self._db.bulk_insert(batch)
                        batch = []

            # Insert remaining
            if batch:
                self._db.bulk_insert(batch)

        except Exception as e:
            logger.exception(f"Error processing feed {feed_path}")
            raise

        return count

    def _parse_nvd_feed_entry(self, item: dict) -> Optional[CVEEntry]:
        """Parse a CVE entry from NVD JSON feed format."""
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")

            if not cve_id:
                return None

            # Description
            description = ""
            desc_data = cve_data.get("description", {}).get("description_data", [])
            for desc in desc_data:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS scores
            impact = item.get("impact", {})
            cvss_v3 = 0.0
            cvss_v2 = 0.0

            if "baseMetricV3" in impact:
                cvss_v3 = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore", 0.0)
            if "baseMetricV2" in impact:
                cvss_v2 = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore", 0.0)

            # Severity
            severity = ""
            if cvss_v3 >= 9.0:
                severity = "CRITICAL"
            elif cvss_v3 >= 7.0:
                severity = "HIGH"
            elif cvss_v3 >= 4.0:
                severity = "MEDIUM"
            elif cvss_v3 > 0:
                severity = "LOW"

            # CPE matches
            cpe_matches = []
            configurations = item.get("configurations", {})
            for node in configurations.get("nodes", []):
                for cpe_match in node.get("cpe_match", []):
                    if cpe_match.get("vulnerable"):
                        cpe_uri = cpe_match.get("cpe23Uri", "")
                        if cpe_uri:
                            cpe_matches.append(cpe_uri)

            # References
            references = []
            for ref in cve_data.get("references", {}).get("reference_data", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            # Dates
            published = item.get("publishedDate", "")
            modified = item.get("lastModifiedDate", "")

            return CVEEntry(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3,
                cvss_v2_score=cvss_v2,
                severity=severity,
                published_date=published,
                last_modified_date=modified,
                cpe_matches=cpe_matches,
                references=references[:10],
            )

        except Exception as e:
            logger.debug(f"Error parsing CVE entry: {e}")
            return None

    def _parse_nvd_api_entry(self, cve_data: dict) -> Optional[CVEEntry]:
        """Parse a CVE entry from NVD 2.0 API format."""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS scores
            cvss_v3 = 0.0
            metrics = cve_data.get("metrics", {})
            for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
                if metric_key in metrics:
                    for metric in metrics[metric_key]:
                        cvss_v3 = metric.get("cvssData", {}).get("baseScore", 0.0)
                        break

            # Severity
            severity = ""
            if cvss_v3 >= 9.0:
                severity = "CRITICAL"
            elif cvss_v3 >= 7.0:
                severity = "HIGH"
            elif cvss_v3 >= 4.0:
                severity = "MEDIUM"
            elif cvss_v3 > 0:
                severity = "LOW"

            # References
            references = [ref.get("url", "") for ref in cve_data.get("references", [])]

            return CVEEntry(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3,
                severity=severity,
                published_date=cve_data.get("published", ""),
                last_modified_date=cve_data.get("lastModified", ""),
                references=references[:10],
            )

        except Exception as e:
            logger.debug(f"Error parsing API CVE entry: {e}")
            return None

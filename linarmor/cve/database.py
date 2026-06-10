"""
LinArmor CVE Database Manager

Manages the local SQLite database of CVE entries.
Provides CRUD operations and search functionality.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Optional

from linarmor.config import CVE_DATABASE_PATH, DATA_DIR
from linarmor.cve.models import CVEEntry

logger = logging.getLogger("linarmor.cve.database")


class CVEDatabase:
    """
    Local SQLite database for CVE vulnerability data.

    Usage:
        db = CVEDatabase()
        db.initialize()
        db.insert_cve(cve_entry)
        results = db.search_by_cpe("openssh", "8.2")
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or CVE_DATABASE_PATH
        self._conn: Optional[sqlite3.Connection] = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create a database connection."""
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def initialize(self) -> None:
        """Create the database tables if they don't exist."""
        conn = self._get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3_score REAL DEFAULT 0.0,
                cvss_v2_score REAL DEFAULT 0.0,
                severity TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                cpe_matches TEXT,      -- JSON array of CPE strings
                references_json TEXT,  -- JSON array of reference URLs
                exploit_available INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_cve_severity ON cves(severity);
            CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cves(cvss_v3_score);

            CREATE TABLE IF NOT EXISTS cpe_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT,
                product TEXT,
                version TEXT,
                cve_id TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            );

            CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_index(product);
            CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_index(vendor, product);

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        """)
        conn.commit()
        logger.info(f"CVE database initialized at {self._db_path}")

    def insert_cve(self, cve: CVEEntry) -> None:
        """Insert or update a CVE entry."""
        conn = self._get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO cves
            (cve_id, description, cvss_v3_score, cvss_v2_score, severity,
             published_date, last_modified_date, cpe_matches, references_json, exploit_available)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve.cve_id, cve.description, cve.cvss_v3_score, cve.cvss_v2_score,
            cve.severity, cve.published_date, cve.last_modified_date,
            json.dumps(cve.cpe_matches), json.dumps(cve.references),
            1 if cve.exploit_available else 0,
        ))

    def insert_cpe_mapping(self, vendor: str, product: str, version: str, cve_id: str) -> None:
        """Insert a CPE to CVE mapping for fast lookups."""
        conn = self._get_connection()
        conn.execute("""
            INSERT INTO cpe_index (vendor, product, version, cve_id)
            VALUES (?, ?, ?, ?)
        """, (vendor.lower(), product.lower(), version, cve_id))

    def bulk_insert(self, cves: list[CVEEntry]) -> None:
        """Insert multiple CVE entries in a transaction."""
        conn = self._get_connection()
        try:
            for cve in cves:
                self.insert_cve(cve)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def search_by_product(self, product: str, version: Optional[str] = None) -> list[CVEEntry]:
        """Search CVEs by product name and optional version."""
        conn = self._get_connection()

        if version:
            query = """
                SELECT DISTINCT c.* FROM cves c
                JOIN cpe_index cp ON c.cve_id = cp.cve_id
                WHERE cp.product = ? AND cp.version = ?
                ORDER BY c.cvss_v3_score DESC
                LIMIT 50
            """
            cursor = conn.execute(query, (product.lower(), version))
        else:
            query = """
                SELECT DISTINCT c.* FROM cves c
                JOIN cpe_index cp ON c.cve_id = cp.cve_id
                WHERE cp.product = ?
                ORDER BY c.cvss_v3_score DESC
                LIMIT 50
            """
            cursor = conn.execute(query, (product.lower(),))

        return [self._row_to_cve(row) for row in cursor.fetchall()]

    def search_by_cpe(self, cpe_pattern: str) -> list[CVEEntry]:
        """Search CVEs by CPE URI pattern (partial match)."""
        conn = self._get_connection()
        query = """
            SELECT * FROM cves
            WHERE cpe_matches LIKE ?
            ORDER BY cvss_v3_score DESC
            LIMIT 50
        """
        cursor = conn.execute(query, (f"%{cpe_pattern}%",))
        return [self._row_to_cve(row) for row in cursor.fetchall()]

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Get a specific CVE by ID."""
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        return self._row_to_cve(row) if row else None

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = self._get_connection()
        total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM cves WHERE severity = 'HIGH'").fetchone()[0]
        last_update = conn.execute("SELECT value FROM metadata WHERE key = 'last_update'").fetchone()

        return {
            "total_cves": total,
            "critical": critical,
            "high": high,
            "last_update": last_update[0] if last_update else "Never",
        }

    def set_metadata(self, key: str, value: str) -> None:
        """Set a metadata key-value pair."""
        conn = self._get_connection()
        conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", (key, value))
        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @staticmethod
    def _row_to_cve(row: sqlite3.Row) -> CVEEntry:
        """Convert a database row to a CVEEntry object."""
        return CVEEntry(
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_v3_score=row["cvss_v3_score"],
            cvss_v2_score=row["cvss_v2_score"],
            severity=row["severity"],
            published_date=row["published_date"],
            last_modified_date=row["last_modified_date"],
            cpe_matches=json.loads(row["cpe_matches"]) if row["cpe_matches"] else [],
            references=json.loads(row["references_json"]) if row["references_json"] else [],
            exploit_available=bool(row["exploit_available"]),
        )

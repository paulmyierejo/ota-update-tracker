"""
Device Version Database
Maintains a local database of known Android devices and their OTA version history.
Supports tracking rollout status, comparing devices, and generating reports.
"""

import json
import os
import sqlite3
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta


@dataclass
class DeviceRecord:
    """A device record in the database."""
    id: Optional[int] = None
    manufacturer: str = ""
    model: str = ""
    codename: str = ""
    region: str = "GLOBAL"
    carrier: Optional[str] = None
    current_version: Optional[str] = None
    current_build: Optional[str] = None
    security_patch: Optional[str] = None
    android_version: Optional[str] = None
    last_updated: Optional[datetime] = None
    update_available: bool = False
    rollout_percentage: int = 0
    tags: List[str] = field(default_factory=list)


@dataclass
class VersionHistoryEntry:
    """An entry in the version history for a device."""
    id: Optional[int] = None
    device_id: int = 0
    version: str = ""
    build_id: str = ""
    security_patch: Optional[str] = None
    release_date: Optional[datetime] = None
    rollout_date: Optional[datetime] = None
    rollout_percentage: int = 0
    changelog: str = ""


class DeviceDatabase:
    """
    SQLite-backed device version database.

    Provides CRUD operations, version history tracking,
    and aggregate reporting.
    """

    DB_FILENAME = "device_versions.db"

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DB_FILENAME
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                manufacturer TEXT NOT NULL,
                model TEXT NOT NULL,
                codename TEXT NOT NULL,
                region TEXT DEFAULT 'GLOBAL',
                carrier TEXT,
                current_version TEXT,
                current_build TEXT,
                security_patch TEXT,
                android_version TEXT,
                last_updated TEXT,
                update_available INTEGER DEFAULT 0,
                rollout_percentage INTEGER DEFAULT 0,
                tags TEXT DEFAULT '',
                UNIQUE(manufacturer, model, codename, region, carrier)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS version_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                version TEXT NOT NULL,
                build_id TEXT,
                security_patch TEXT,
                release_date TEXT,
                rollout_date TEXT,
                rollout_percentage INTEGER DEFAULT 0,
                changelog TEXT DEFAULT '',
                FOREIGN KEY (device_id) REFERENCES devices(id),
                UNIQUE(device_id, version)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_manufacturer ON devices(manufacturer)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_version_history_device ON version_history(device_id)
        """)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _row_to_device(self, row: sqlite3.Row) -> DeviceRecord:
        tags = []
        if row["tags"]:
            tags = json.loads(row["tags"])
        return DeviceRecord(
            id=row["id"],
            manufacturer=row["manufacturer"],
            model=row["model"],
            codename=row["codename"],
            region=row["region"],
            carrier=row["carrier"],
            current_version=row["current_version"],
            current_build=row["current_build"],
            security_patch=row["security_patch"],
            android_version=row["android_version"],
            last_updated=datetime.fromisoformat(row["last_updated"]) if row["last_updated"] else None,
            update_available=bool(row["update_available"]),
            rollout_percentage=row["rollout_percentage"],
            tags=tags,
        )

    def upsert_device(self, device: DeviceRecord) -> int:
        """Insert or update a device record."""
        conn = self._get_conn()
        cursor = conn.execute("""
            INSERT INTO devices (
                manufacturer, model, codename, region, carrier,
                current_version, current_build, security_patch, android_version,
                last_updated, update_available, rollout_percentage, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(manufacturer, model, codename, region, carrier)
            DO UPDATE SET
                current_version = excluded.current_version,
                current_build = excluded.current_build,
                security_patch = excluded.security_patch,
                android_version = excluded.android_version,
                last_updated = excluded.last_updated,
                update_available = excluded.update_available,
                rollout_percentage = excluded.rollout_percentage,
                tags = excluded.tags
        """, (
            device.manufacturer,
            device.model,
            device.codename,
            device.region,
            device.carrier,
            device.current_version,
            device.current_build,
            device.security_patch,
            device.android_version,
            datetime.now().isoformat(),
            int(device.update_available),
            device.rollout_percentage,
            json.dumps(device.tags),
        ))
        conn.commit()
        return cursor.lastrowid or cursor.rowcount

    def get_device(
        self,
        manufacturer: str,
        model: str,
        codename: str,
        region: str = "GLOBAL",
        carrier: Optional[str] = None,
    ) -> Optional[DeviceRecord]:
        """Get a device record."""
        conn = self._get_conn()
        row = conn.execute("""
            SELECT * FROM devices
            WHERE manufacturer=? AND model=? AND codename=? AND region=? AND carrier IS ?
        """, (manufacturer, model, codename, region, carrier)).fetchone()
        if row:
            return self._row_to_device(row)
        return None

    def list_devices(
        self,
        manufacturer: Optional[str] = None,
        region: Optional[str] = None,
        has_update: Optional[bool] = None,
        min_android_version: Optional[str] = None,
    ) -> List[DeviceRecord]:
        """List devices with optional filters."""
        conn = self._get_conn()
        query = "SELECT * FROM devices WHERE 1=1"
        params: List[Any] = []

        if manufacturer:
            query += " AND manufacturer=?"
            params.append(manufacturer)

        if region:
            query += " AND region=?"
            params.append(region)

        if has_update is not None:
            query += " AND update_available=?"
            params.append(int(has_update))

        if min_android_version:
            query += " AND android_version>=?"
            params.append(min_android_version)

        query += " ORDER BY manufacturer, model"
        rows = conn.execute(query, params).fetchall()
        return [self._row_to_device(row) for row in rows]

    def add_version_history(
        self,
        device_id: int,
        entry: VersionHistoryEntry,
    ) -> int:
        """Add a version history entry."""
        conn = self._get_conn()
        cursor = conn.execute("""
            INSERT INTO version_history (
                device_id, version, build_id, security_patch,
                release_date, rollout_date, rollout_percentage, changelog
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, version) DO UPDATE SET
                rollout_date = excluded.rollout_date,
                rollout_percentage = excluded.rollout_percentage,
                changelog = excluded.changelog
        """, (
            device_id,
            entry.version,
            entry.build_id,
            entry.security_patch,
            entry.release_date.isoformat() if entry.release_date else None,
            entry.rollout_date.isoformat() if entry.rollout_date else None,
            entry.rollout_percentage,
            entry.changelog,
        ))
        conn.commit()
        return cursor.lastrowid or 0

    def get_version_history(self, device_id: int) -> List[VersionHistoryEntry]:
        """Get version history for a device."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM version_history
            WHERE device_id=?
            ORDER BY release_date DESC
        """, (device_id,)).fetchall()
        return [
            VersionHistoryEntry(
                id=row["id"],
                device_id=row["device_id"],
                version=row["version"],
                build_id=row["build_id"],
                security_patch=row["security_patch"],
                release_date=datetime.fromisoformat(row["release_date"]) if row["release_date"] else None,
                rollout_date=datetime.fromisoformat(row["rollout_date"]) if row["rollout_date"] else None,
                rollout_percentage=row["rollout_percentage"],
                changelog=row["changelog"],
            )
            for row in rows
        ]

    def get_outdated_devices(self, threshold_months: int = 2) -> List[DeviceRecord]:
        """Get devices that haven't been updated in a while."""
        conn = self._get_conn()
        cutoff = (datetime.now() - timedelta(days=30 * threshold_months)).isoformat()
        rows = conn.execute("""
            SELECT * FROM devices
            WHERE last_updated < ?
            ORDER BY last_updated ASC
        """, (cutoff,)).fetchall()
        return [self._row_to_device(row) for row in rows]

    def get_report(self) -> Dict[str, Any]:
        """Generate an aggregate database report."""
        conn = self._get_conn()

        total = conn.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]
        with_updates = conn.execute(
            "SELECT COUNT(*) as c FROM devices WHERE update_available=1"
        ).fetchone()["c"]

        # Security patch distribution
        patch_rows = conn.execute("""
            SELECT security_patch, COUNT(*) as count
            FROM devices
            WHERE security_patch IS NOT NULL
            GROUP BY security_patch
            ORDER BY count DESC
            LIMIT 20
        """).fetchall()

        # Android version distribution
        version_rows = conn.execute("""
            SELECT android_version, COUNT(*) as count
            FROM devices
            WHERE android_version IS NOT NULL
            GROUP BY android_version
            ORDER BY android_version DESC
        """).fetchall()

        # By manufacturer
        mfr_rows = conn.execute("""
            SELECT manufacturer, COUNT(*) as count
            FROM devices
            GROUP BY manufacturer
            ORDER BY count DESC
        """).fetchall()

        return {
            "total_devices": total,
            "with_pending_updates": with_updates,
            "security_patches": {r["security_patch"]: r["count"] for r in patch_rows},
            "android_versions": {r["android_version"]: r["count"] for r in version_rows},
            "by_manufacturer": {r["manufacturer"]: r["count"] for r in mfr_rows},
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def export_json(self, path: str):
        """Export database to JSON."""
        devices = self.list_devices()
        report = self.get_report()
        data = {
            "export_date": datetime.now().isoformat(),
            "report": report,
            "devices": [asdict(d) for d in devices],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Android Device Database")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Add a device")
    add_parser.add_argument("--manufacturer", required=True)
    add_parser.add_argument("--model", required=True)
    add_parser.add_argument("--codename", required=True)
    add_parser.add_argument("--region", default="GLOBAL")
    add_parser.add_argument("--carrier")
    add_parser.add_argument("--version")
    add_parser.add_argument("--build")
    add_parser.add_argument("--security-patch")
    add_parser.add_argument("--android-version")
    add_parser.add_argument("--update-available", action="store_true")

    list_parser = subparsers.add_parser("list", help="List devices")
    list_parser.add_argument("--manufacturer")
    list_parser.add_argument("--has-update", action="store_true")
    list_parser.add_argument("--json", action="store_true")

    report_parser = subparsers.add_parser("report", help="Generate report")

    args = parser.parse_args()

    db = DeviceDatabase()

    if args.command == "add":
        device = DeviceRecord(
            manufacturer=args.manufacturer,
            model=args.model,
            codename=args.codename,
            region=args.region,
            carrier=args.carrier,
            current_version=args.version,
            current_build=args.build,
            security_patch=args.security_patch,
            android_version=args.android_version,
            update_available=args.update_available,
        )
        db.upsert_device(device)
        print(f"Device {args.manufacturer} {args.model} saved.")

    elif args.command == "list":
        devices = db.list_devices(
            manufacturer=args.manufacturer,
            has_update=args.has_update if "has_update" in args else None,
        )
        if args.json:
            print(json.dumps([asdict(d) for d in devices], indent=2, default=str))
        else:
            print(f"{'Manufacturer':<15} {'Model':<15} {'Version':<15} {'Security Patch':<15} {'Update':<8}")
            print("-" * 70)
            for d in devices:
                print(f"{d.manufacturer:<15} {d.model:<15} {d.current_version or 'N/A':<15} "
                      f"{d.security_patch or 'N/A':<15} {'YES' if d.update_available else 'no':<8}")

    elif args.command == "report":
        report = db.get_report()
        print(json.dumps(report, indent=2))

    db.close()


if __name__ == "__main__":
    main()

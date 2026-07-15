"""
Android OTA Differential Analyzer
Compares two Android system builds to identify changed files, assess risk,
and generate targeted delta update manifests.
"""

import hashlib
import json
import os
import re
import struct
import zipfile
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class FileChangeType(Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


class RiskCategory(Enum):
    CRITICAL = "critical"     # System partition critical files
    HIGH = "high"             # Privilege escalation, SELinux policy
    MEDIUM = "medium"         # Framework, system apps
    LOW = "low"              # Vendor, product partitions
    INFO = "info"            # Non-essential changes


@dataclass
class FileDiff:
    """Represents a changed file between two builds."""
    path: str
    change_type: FileChangeType
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    risk_category: RiskCategory = RiskCategory.INFO
    description: str = ""

    @property
    def size_delta(self) -> int:
        if self.new_size is None:
            return 0
        if self.old_size is None:
            return self.new_size
        return self.new_size - self.old_size

    @property
    def is_security_relevant(self) -> bool:
        return self.risk_category in (RiskCategory.CRITICAL, RiskCategory.HIGH)


@dataclass
class SystemChange:
    """Represents a system-level change category."""
    category: str
    description: str
    risk: RiskCategory
    affected_files: List[str] = field(default_factory=list)
    cvss_score: float = 0.0  # CVSS v3 score if security relevant


class AndroidFileClassifier:
    """
    Classifies Android system files by risk and type.
    Used to assess the impact of changed files.
    """

    # Patterns for critical system files
    CRITICAL_PATTERNS = [
        # Boot critical
        (r"^boot\.img$", "Boot image", RiskCategory.CRITICAL),
        (r"^kernel$", "Linux kernel", RiskCategory.CRITICAL),
        (r"^system\.img$", "System partition image", RiskCategory.CRITICAL),

        # SELinux / security
        (r"/selinux/policy$", "SELinux policy", RiskCategory.HIGH),
        (r"/selinux/mapping$", "SELinux mapping", RiskCategory.HIGH),
        (r"file_contexts", "SELinux file contexts", RiskCategory.HIGH),
        (r"plat_property_contexts", "Property contexts", RiskCategory.HIGH),

        # System partition
        (r"^system/lib(64)?/libandroid_runtime\.so$", "Android Runtime", RiskCategory.HIGH),
        (r"^system/lib(64)?/libart\.so$", "ART runtime", RiskCategory.HIGH),
        (r"^system/lib(64)?/libc\.so$", "Bionic libc", RiskCategory.HIGH),
        (r"^system/framework/.*\.jar$", "Framework JAR", RiskCategory.MEDIUM),
        (r"^system/app/.*/.*\.apk$", "System application APK", RiskCategory.MEDIUM),

        # Permissions / capabilities
        (r"/etc/permissions/.*\.xml$", "Permission definitions", RiskCategory.MEDIUM),
        (r"/etc/default-permissions/.*\.xml$", "Default permissions", RiskCategory.MEDIUM),

        # Vendor / product
        (r"^vendor/", "Vendor partition", RiskCategory.LOW),
        (r"^product/", "Product partition", RiskCategory.LOW),

        # Cryptography
        (r"libkeymaster", "Keymaster TA", RiskCategory.CRITICAL),
        (r"libcrypt", "Crypto library", RiskCategory.HIGH),
        (r"/certs/", "Certificate store", RiskCategory.HIGH),
    ]

    # Known security-relevant package names
    SECURITY_PACKAGES = {
        "com.android.framework",
        "com.android.systemui",
        "com.android.permission",
        "com.android.providers.media",
        "com.android.providers.telephony",
        "com.android.providers.settings",
        "com.android.inputmethod",
        "com.android.bluetooth",
        "com.android.se",
        "platform.xml",
        "framework-res.apk",
    }

    @classmethod
    def classify(cls, filepath: str) -> Tuple[RiskCategory, str]:
        """Classify a file path by risk and return a description."""
        filename = os.path.basename(filepath)

        # Check critical patterns
        for pattern, description, risk in cls.CRITICAL_PATTERNS:
            if re.search(pattern, filepath, re.IGNORECASE):
                return risk, description

        # Check security-relevant packages
        for pkg in cls.SECURITY_PACKAGES:
            if pkg in filepath:
                return RiskCategory.HIGH, f"Security component: {pkg}"

        # Default classification
        if filepath.startswith("system/"):
            return RiskCategory.MEDIUM, "System partition file"
        elif filepath.startswith("vendor/"):
            return RiskCategory.LOW, "Vendor partition file"
        elif filepath.startswith("product/"):
            return RiskCategory.LOW, "Product partition file"
        else:
            return RiskCategory.INFO, "Other file"

    @classmethod
    def is_critical_for_update(cls, filepath: str) -> bool:
        """Check if a file is critical for OTA (cannot be delta-ed safely)."""
        critical_prefixes = (
            "boot.img", "kernel", "dtbo.img", "vbmeta",
            "system.ext4", "vendor.ext4", "product.ext4",
        )
        return any(filepath.startswith(p) for p in critical_prefixes)


class DeltaAnalyzer:
    """
    Analyzes differences between two Android build manifests.
    Supports full OTA ZIP files and build manifests.
    """

    def __init__(self):
        self.changes: List[FileDiff] = []

    def _compute_sha256(self, filepath: str) -> Optional[str]:
        """Compute SHA-256 hash of a file."""
        try:
            with open(filepath, "rb") as f:
                # For large files, only hash first/last chunks
                size = os.path.getsize(filepath)
                if size > 50 * 1024 * 1024:  # > 50MB
                    return self._compute_sparse_hash(filepath)
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def _compute_sparse_hash(self, filepath: str) -> str:
        """Hash a large file by sampling chunks."""
        h = hashlib.sha256()
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(filepath, "rb") as f:
            # Hash first, middle, last 10MB
            size = os.path.getsize(filepath)
            f.read(chunk_size)  # Skip first MB
            f.seek(size // 2)
            h.update(f.read(chunk_size))
            f.seek(max(0, size - chunk_size * 10))
            h.update(f.read())
        return h.hexdigest()

    def _compute_file_hash_from_zip(self, zip_path: str, member: str) -> Optional[str]:
        """Compute SHA-256 of a file inside a ZIP."""
        try:
            with zipfile.ZipFile(zip_path) as zf:
                info = zf.getinfo(member)
                h = hashlib.sha256()
                with zf.open(member) as f:
                    # For large files, hash sparsely
                    if info.file_size > 50 * 1024 * 1024:
                        data = f.read(1024 * 1024)  # First 1MB
                        h.update(data)
                        # Hash last 1MB
                        f.seek(max(0, info.file_size - 1024 * 1024))
                        h.update(f.read())
                    else:
                        h.update(f.read())
                return h.hexdigest()
        except Exception:
            return None

    def analyze_ota_zips(
        self,
        old_zip_path: str,
        new_zip_path: str,
    ) -> List[FileDiff]:
        """
        Compare two OTA ZIP files and return changed files.
        """
        changes = []

        old_files: Dict[str, Tuple[int, str]] = {}
        new_files: Dict[str, Tuple[int, str]] = {}

        # Index old ZIP
        try:
            with zipfile.ZipFile(old_zip_path) as old_zf:
                for info in old_zf.infolist():
                    if info.is_dir():
                        continue
                    h = self._compute_file_hash_from_zip(old_zip_path, info.filename)
                    old_files[info.filename] = (info.file_size, h or "")
        except zipfile.BadZipFile:
            pass

        # Index new ZIP
        try:
            with zipfile.ZipFile(new_zip_path) as new_zf:
                for info in new_zf.infolist():
                    if info.is_dir():
                        continue
                    h = self._compute_file_hash_from_zip(new_zip_path, info.filename)
                    new_files[info.filename] = (info.file_size, h or "")
        except zipfile.BadZipFile:
            pass

        # Compare
        all_files: Set[str] = set(old_files.keys()) | set(new_files.keys())

        for filepath in sorted(all_files):
            old_info = old_files.get(filepath)
            new_info = new_files.get(filepath)

            risk, description = AndroidFileClassifier.classify(filepath)

            if old_info is None and new_info is not None:
                changes.append(FileDiff(
                    path=filepath,
                    change_type=FileChangeType.ADDED,
                    new_size=new_info[0],
                    new_hash=new_info[1],
                    risk_category=risk,
                    description=description,
                ))
            elif old_info is not None and new_info is None:
                changes.append(FileDiff(
                    path=filepath,
                    change_type=FileChangeType.REMOVED,
                    old_size=old_info[0],
                    old_hash=old_info[1],
                    risk_category=risk,
                    description=description,
                ))
            elif old_info is not None and new_info is not None:
                if old_info[1] != new_info[1]:
                    changes.append(FileDiff(
                        path=filepath,
                        change_type=FileChangeType.MODIFIED,
                        old_size=old_info[0],
                        new_size=new_info[0],
                        old_hash=old_info[1],
                        new_hash=new_info[1],
                        risk_category=risk,
                        description=description,
                    ))

        self.changes = changes
        return changes

    def generate_delta_manifest(
        self,
        changes: List[FileDiff],
        include_critical: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a delta update manifest with security-relevant files prioritized.
        """
        critical = [c for c in changes if c.risk_category == RiskCategory.CRITICAL and c.change_type != FileChangeType.UNCHANGED]
        high = [c for c in changes if c.risk_category == RiskCategory.HIGH and c.change_type != FileChangeType.UNCHANGED]
        medium = [c for c in changes if c.risk_category == RiskCategory.MEDIUM and c.change_type != FileChangeType.UNCHANGED]
        low = [c for c in changes if c.risk_category in (RiskCategory.LOW, RiskCategory.INFO) and c.change_type != FileChangeType.UNCHANGED]

        total_size = sum(
            max(c.old_size or 0, c.new_size or 0)
            for c in changes if c.change_type != FileChangeType.UNCHANGED
        )

        return {
            "total_files_changed": len(changes),
            "total_size_delta_bytes": total_size,
            "by_risk": {
                "critical": [asdict(c) for c in critical],
                "high": [asdict(c) for c in high],
                "medium": [asdict(c) for c in medium],
                "low": [asdict(c) for c in low],
            },
            "security_relevant": [
                asdict(c) for c in changes if c.is_security_relevant
            ],
            "can_delta_update": include_critical,
        }

    def get_security_changes(self) -> List[FileDiff]:
        """Return only security-relevant changes."""
        return [c for c in self.changes if c.is_security_relevant]


def asdict(obj):
    """Convert dataclass to dict recursively."""
    import dataclasses
    if dataclasses.is_dataclass(obj):
        result = {}
        for k, v in dataclasses.asdict(obj).items():
            if isinstance(v, Enum):
                result[k] = v.value
            elif isinstance(v, (list, tuple)):
                result[k] = [asdict(i) if dataclasses.is_dataclass(i) else i for i in v]
            else:
                result[k] = v
        return result
    return obj


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Android OTA Delta Analyzer")
    parser.add_argument("--old-zip", required=True, help="Previous OTA ZIP")
    parser.add_argument("--new-zip", required=True, help="New OTA ZIP")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    analyzer = DeltaAnalyzer()
    changes = analyzer.analyze_ota_zips(args.old_zip, args.new_zip)

    manifest = analyzer.generate_delta_manifest(changes)

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print("OTA Delta Analysis Report")
        print("=" * 50)
        print(f"Total files changed: {manifest['total_files_changed']}")
        print(f"Total delta size: {manifest['total_size_delta_bytes'] / (1024**2):.1f} MB")
        print(f"Security-relevant: {len(manifest['security_relevant'])}")
        print()
        for risk in ["critical", "high", "medium"]:
            items = manifest['by_risk'][risk]
            if items:
                print(f"[{risk.upper()}] {len(items)} files:")
                for item in items[:5]:
                    print(f"  {item['change_type']}: {item['path']} ({item['description']})")
                if len(items) > 5:
                    print(f"  ... and {len(items)-5} more")


if __name__ == "__main__":
    main()

"""
Android OTA Update Tracker
Tracks OTA update availability, rollout progress, and version history
for Android devices across manufacturers and carriers.
"""

import json
import hashlib
import time
import re
import requests
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod


class ReleaseType(Enum):
    STABLE = "stable"
    BETA = "beta"
    DEVELOPMENT = "dev"
    FACTORY = "factory"


class SecurityPatchLevel(Enum):
    CRITICAL = "critical"   # Actively exploited 0-day
    HIGH = "high"          # Known exploited
    MEDIUM = "medium"      # General security
    LOW = "low"            # Low severity
    NONE = "none"          # No patch


@dataclass
class OTAVersion:
    """Represents a specific Android OTA version."""
    version: str              # e.g., "13.0.1234.ABC1234"
    build_id: str             # e.g., "AB123456"
    android_version: str      # e.g., "13"
    security_patch: str       # e.g., "2023-12-01"
    security_patch_level: SecurityPatchLevel = SecurityPatchLevel.MEDIUM
    release_type: ReleaseType = ReleaseType.STABLE
    release_date: Optional[datetime] = None
    rollout_percentage: int = 0  # 0-100
    file_size: Optional[int] = None  # bytes
    download_url: Optional[str] = None
    checksum_sha256: Optional[str] = None
    delta_available: bool = False
    carrier: Optional[str] = None
    region: Optional[str] = None
    changelog: List[str] = field(default_factory=list)

    @property
    def is_full_rollout(self) -> bool:
        return self.rollout_percentage == 100

    @property
    def is_security_urgent(self) -> bool:
        return self.security_patch_level in (
            SecurityPatchLevel.CRITICAL,
            SecurityPatchLevel.HIGH,
        )


@dataclass
class DeviceProfile:
    """Device configuration for OTA tracking."""
    model: str              # e.g., "Pixel 7"
    codename: str           # e.g., "cheetah"
    manufacturer: str       # e.g., "Google"
    region: str             # e.g., "US", "GLOBAL"
    carrier: Optional[str]  # e.g., "T-Mobile", None for unlocked
    ota_version: Optional[str] = None
    last_check: Optional[datetime] = None
    update_available: bool = False
    changelog: List[str] = field(default_factory=list)


class OTADataSource(ABC):
    """Abstract base for OTA data sources."""

    @abstractmethod
    def fetch_latest(self, device: DeviceProfile) -> Optional[OTAVersion]:
        pass

    @abstractmethod
    def fetch_version_history(self, device: DeviceProfile) -> List[OTAVersion]:
        pass

    @abstractmethod
    def is_available(self, device: DeviceProfile) -> bool:
        pass


class GoogleOTASource(OTADataSource):
    """Fetch OTA info from Google's OTA servers."""

    BASE_URL = "https://android.googleapis.com/auth"
    OTA_CHECK_URL = "https://android.googleapis.com/checkin"

    def __init__(self, request_timeout: int = 30):
        self.request_timeout = request_timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Android-OTA-Tracker/1.0",
            "Content-Type": "application/json",
        })

    def fetch_latest(self, device: DeviceProfile) -> Optional[OTAVersion]:
        """Fetch the latest OTA for a Google Pixel device."""
        payload = self._build_checkin_payload(device)
        try:
            response = self._session.post(
                self.OTA_CHECK_URL,
                json=payload,
                timeout=self.request_timeout,
            )
            if response.status_code == 200:
                return self._parse_ota_response(response.json(), device)
        except requests.RequestException:
            pass
        return None

    def _build_checkin_payload(self, device: DeviceProfile) -> Dict[str, Any]:
        """Build the checkin request payload (simplified)."""
        return {
            "version": 3,
            "device": device.codename,
            "carrier": device.carrier or "generic",
            "sdk_version": 33,
            "channel": "stable",
        }

    def _parse_ota_response(self, data: Dict, device: DeviceProfile) -> Optional[OTAVersion]:
        """Parse the OTA checkin response."""
        # Simplified parser - real implementation handles protobuf
        if "otacheck" in data:
            info = data["otacheck"].get("update", {})
            return OTAVersion(
                version=info.get("version", "unknown"),
                build_id=info.get("build", "unknown"),
                android_version=info.get("api_level", "33"),
                security_patch=info.get("security_patch", ""),
                rollout_percentage=info.get("percentage", 0),
                file_size=info.get("size", 0),
                download_url=info.get("url", ""),
            )
        return None

    def fetch_version_history(self, device: DeviceProfile) -> List[OTAVersion]:
        """Fetch version history (simplified)."""
        return []

    def is_available(self, device: DeviceProfile) -> bool:
        return device.manufacturer.lower() in ("google", "pixel")


class AOSPOTASource(OTADataSource):
    """Fetch OTA info from AOSP/GSI sources."""

    def __init__(self, request_timeout: int = 30):
        self.request_timeout = request_timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Android-OTA-Tracker/1.0",
        })

    def fetch_latest(self, device: DeviceProfile) -> Optional[OTAVersion]:
        """Fetch latest from AOSP."""
        return None

    def fetch_version_history(self, device: DeviceProfile) -> List[OTAVersion]:
        return []

    def is_available(self, device: DeviceProfile) -> bool:
        return True


class OTATracker:
    """
    Main OTA tracking engine.
    Aggregates data from multiple sources and provides unified access.
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 3600,
        request_timeout: int = 30,
    ):
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: Dict[str, Tuple[datetime, Any]] = {}
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Android-OTA-Tracker/1.0"})
        self.sources: List[OTADataSource] = [
            GoogleOTASource(request_timeout),
            AOSPOTASource(request_timeout),
        ]

    def _cache_key(self, device: DeviceProfile, operation: str) -> str:
        raw = f"{operation}:{device.manufacturer}:{device.model}:{device.carrier or 'unlocked'}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[Any]:
        if key in self._cache:
            timestamp, value = self._cache[key]
            if time.time() - timestamp.timestamp() < self.cache_ttl_seconds:
                return value
            del self._cache[key]
        return None

    def _set_cached(self, key: str, value: Any):
        self._cache[key] = (datetime.now(), value)

    def check_update(self, device: DeviceProfile) -> Optional[OTAVersion]:
        """
        Check if an update is available for the given device.

        Returns the latest OTA version if available, None otherwise.
        """
        cache_key = self._cache_key(device, "check_update")
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        for source in self.sources:
            if source.is_available(device):
                result = source.fetch_latest(device)
                if result:
                    device.last_check = datetime.now()
                    self._set_cached(cache_key, result)
                    return result

        self._set_cached(cache_key, None)
        return None

    def get_update_status(
        self,
        device: DeviceProfile,
        current_version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get a comprehensive update status for a device.
        """
        latest = self.check_update(device)
        current = device.ota_version or current_version

        if latest is None:
            return {
                "update_available": False,
                "latest_version": None,
                "current_version": current,
                "status": "UNKNOWN",
                "message": "Could not determine update status",
            }

        update_available = (
            latest.version != current and
            latest.rollout_percentage > 0
        )

        return {
            "update_available": update_available,
            "latest_version": asdict(latest),
            "current_version": current,
            "status": "AVAILABLE" if update_available else "UP_TO_DATE",
            "rollout_percentage": latest.rollout_percentage,
            "security_urgent": latest.is_security_urgent,
            "delta_available": latest.delta_available,
            "file_size_mb": (latest.file_size or 0) // (1024 * 1024),
        }

    def compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        def parse(v: str) -> List[int]:
            return [int(x) for x in re.findall(r'\d+', v)]

        p1, p2 = parse(v1), parse(v2)
        # Pad shorter list
        max_len = max(len(p1), len(p2))
        p1 += [0] * (max_len - len(p1))
        p2 += [0] * (max_len - len(p2))

        for a, b in zip(p1, p2):
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0

    def close(self):
        self._session.close()


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(description="Android OTA Update Tracker")
    parser.add_argument("--model", required=True, help="Device model (e.g., Pixel 7)")
    parser.add_argument("--codename", required=True, help="Device codename (e.g., cheetah)")
    parser.add_argument("--manufacturer", default="Google", help="Manufacturer")
    parser.add_argument("--carrier", help="Carrier (e.g., T-Mobile)")
    parser.add_argument("--region", default="US", help="Region")
    parser.add_argument("--current-version", help="Current installed version")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    device = DeviceProfile(
        model=args.model,
        codename=args.codename,
        manufacturer=args.manufacturer,
        region=args.region,
        carrier=args.carrier,
    )

    tracker = OTATracker()
    try:
        status = tracker.get_update_status(device, args.current_version)
        if args.json:
            print(json.dumps(status, indent=2, default=str))
        else:
            print("OTA Update Status")
            print("=" * 50)
            print(f"Device: {args.manufacturer} {args.model} ({args.codename})")
            print(f"Update Available: {status['update_available']}")
            if status['latest_version']:
                lv = status['latest_version']
                print(f"Latest Version: {lv['version']}")
                print(f"Build ID: {lv['build_id']}")
                print(f"Android: {lv['android_version']}")
                print(f"Security Patch: {lv['security_patch']}")
                print(f"Rollout: {lv['rollout_percentage']}%")
    finally:
        tracker.close()


if __name__ == "__main__":
    main()

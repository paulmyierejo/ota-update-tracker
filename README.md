# Android OTA Update Tracker

A comprehensive Android OTA (Over-The-Air) update tracking and analysis toolkit.
Track update rollouts, analyze differential updates, scan for security vulnerabilities,
and maintain a device version database.

## Features

- **OTA Version Tracker** — `src/tracker.py`
  Monitor OTA availability and rollout progress for Android devices across
  manufacturers and carriers with multi-source aggregation.

- **Differential Analyzer** — `src/diff_analyzer.py`
  Compare two OTA builds to identify changed files, assess risk, and generate
  targeted delta update manifests.

- **Vulnerability Scanner** — `src/vulnerability_scanner.py`
  Scan devices against known CVE database to identify missing security patches
  with CVSS scoring and active exploitation detection.

- **Device Database** — `src/device_db.py`
  SQLite-backed database for tracking device versions, rollout status, and
  generating aggregate reports.

## Quick Start

```bash
# Install dependencies
pip install requests

# Check for available updates
python -m src.tracker --model "Pixel 7" --codename "cheetah" --manufacturer "Google"

# Scan for vulnerabilities
python -m src.vulnerability_scanner --security-patch "2023-09-01" --android-version "13" --model "Pixel 7"

# Analyze OTA differential
python -m src.diff_analyzer --old-zip old.zip --new-zip new.zip

# Manage device database
python -m src.device_db add --manufacturer Google --model "Pixel 7" --codename cheetah --version "13.0.1234" --security-patch "2024-01-01"
python -m src.device_db list --has-update --json
python -m src.device_db report
```

## Project Structure

```
ota-update-tracker/
├── src/
│   ├── tracker.py           # Main OTA tracker engine
│   ├── diff_analyzer.py     # Differential build analysis
│   ├── vulnerability_scanner.py  # CVE scanning
│   └── device_db.py         # SQLite device database
├── data/
│   └── latest_vulns.json    # Known CVE database
└── README.md
```

## Architecture

```
┌──────────────┐     ┌─────────────┐     ┌──────────────────┐
│ Device Info  │────▶│  OTATracker  │────▶│  Google OTA API  │
│  (profile)   │     │              │     │  AOSP Sources    │
└──────────────┘     └──────┬───────┘     └──────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼             ▼
       ┌──────────┐ ┌──────────┐ ┌──────────┐
       │ DiffAnalyzer│ │VulnScanner│ │ DeviceDB │
       │  ZIP compare│ │ CVE check │ │  SQLite  │
       └──────────┘ └──────────┘ └──────────┘
```

## Security Patch Tracking

Each Android device ships with a monthly security patch level (e.g., `2024-01-01`).
This tool tracks:

- Which security patches are installed
- Which CVEs are addressed by each patch
- Which devices are missing critical patches
- CVSS scores and active exploitation status

## CVE Coverage

The `latest_vulns.json` database includes:

- All CVEs from Google Android Security Bulletins
- CVSS v3.1 scores
- Affected Android versions
- Exploitation status (actively exploited in the wild)
- Fixed-in patch dates

## Contact & Support

- **Website:** [qtphone.com](https://qtphone.com)
- **GitHub Issues:** Open an issue in this repository
- **Email:** contact@qtphone.com

## License

MIT License

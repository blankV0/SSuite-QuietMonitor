```
╔═══════════════════════════════════════╗
║           QuietMonitor v2.0           ║
║   Endpoint Security Suite             ║
╚═══════════════════════════════════════╝
```

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D4?logo=windows&logoColor=white)](https://www.microsoft.com/windows/windows-11)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()
[![Admin Required](https://img.shields.io/badge/Requires-Administrator-red.svg)]()

---

**QuietMonitor** is a lightweight, modular PowerShell-based endpoint security suite for Windows 11.
Designed for real-world threat detection, behavioral analysis, and incident response —
no external dependencies required.

Every capability runs on built-in PowerShell cmdlets and the .NET Base Class Library.
No agents, no cloud telemetry, no vendor lock-in — just your machine, under your control.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [MITRE ATT\&CK Coverage](#mitre-attck-coverage)
- [Screenshots](#screenshots)
- [API Keys (Optional)](#api-keys-optional)
- [License](#license)

---

## Features

### 🔍 Detection
- **Services** — Enumerate running Windows services, flag LOLBin-hosted or temp-path executables
- **Ports** — TCP/UDP listener audit against a trusted-port whitelist
- **Processes** — Authenticode signature check, path anomaly detection for all running processes
- **Persistence** — Registry Run keys, startup folders, WMI subscriptions, shell extensions
- **LOLBins** — Living-Off-The-Land binary detection with argument-pattern analysis
- **Memory injection** — Cross-process memory write detection (WriteProcessMemory / VirtualAllocEx traces)
- **Scheduled tasks** — Non-Microsoft author flag, encoded command-line detection
- **Users** — Unauthorized local admin, dormant accounts, domain accounts in local groups
- **Events** — Brute-force login patterns, audit log clearing (ID 1102), new service installs (ID 7045)
- **Lateral movement** — SMB/WMI/PSRemoting anomaly detection
- **Credential access** — LSASS access patterns, SAM/NTDS enumeration, credential store sweeps
- **Network anomalies** — Beaconing intervals, non-standard protocol usage, suspicious DNS queries
- **Baseline drift** — Compares current state against a signed system snapshot

### 🛡️ Response
- **Quarantine** — AES-256-CBC encryption (PBKDF2/SHA256, 100 000 iterations), file moved not deleted, reversible with password
- **Authorized removal** — Explicit phrase confirmation before permanent deletion, full audit trail
- **Auto-restart watchdog** — Windows Service (QuietMonitorSvc) restarts the suite after unexpected termination
- **Forensic IR package** — One-click ZIP of processes, network state, event logs, handles, open files

### 🔒 Integrity
- **HMAC-SHA256 file signing** — Every module signed with an HMAC key stored in DPAPI-protected registry
- **Hash manifest** — SHA256 manifest of all suite files, verified on every launch
- **Blockchain-style audit log** — Each entry chains to the previous via SHA256 hash; tampering breaks the chain
- **Remote whitelist anchor** — Optional remote endpoint to verify whitelist integrity out-of-band
- **Whitelist encryption** — AES-256 encrypted and HMAC-signed `whitelist.json`, tamper-proof at rest

### 📊 Reporting
- **Per-scan HTML report** — Dark-themed, self-contained, mobile-readable; RED/YELLOW/GREEN finding cards
- **Weekly email digest** — Scheduled summary with trend comparison, delivered via SMTP
- **Risk score 0–100** — Weighted composite score across all findings
- **MITRE ATT&CK mapping** — Every finding tagged with Technique ID and Tactic name

### 🕵️ Threat Intel
- **AbuseIPDB** — Suspicious IP reputation check (optional API key)
- **VirusTotal** — Hash lookup against 70+ AV engines (optional API key)
- **MalwareBazaar** — No-key-required hash check against known malware samples
- **URLhaus** — Offline block-list check for malicious URLs/domains

### 🎯 Advanced
- **RMM detection** — Identifies 35+ remote monitoring and management tools by process/registry signature
- **User Behavior Analytics (UBA)** — Login-time anomalies, unusual privilege escalations, off-hours activity
- **Ransomware guard** — FileSystemWatcher with mass-rename threshold, honeypot canary tokens
- **CVE matching** — Installed software mapped against NVD CVE feed for known vulnerabilities
- **Process integrity** — Service binary path validation, Authenticode chain verification
- **Runtime protection** — Detects injection attempts into the suite's own process space

---

## Architecture

```
C:\QuietMonitor\
├── QuietMonitor.ps1              ← Interactive entry point (19-option menu)
├── Run-SecuritySuite.ps1         ← Automated scan orchestrator (CI/scheduled use)
├── Install-QuietMonitor.ps1      ← Service installer & first-run setup
│
├── Config\
│   ├── settings.json             ← All runtime settings (SMTP, APIs, thresholds)
│   ├── whitelist.json            ← AES-256 encrypted + HMAC-signed whitelist
│   ├── mitre_mapping.json        ← ATT&CK technique metadata
│   ├── module_hashes.json        ← SHA256 manifest (built by installer)
│   ├── nvd_cve_feed.json         ← NVD CVE data feed (user-supplied)
│   ├── threat_cache.json         ← Threat-intel lookup cache
│   └── uba_baseline.json         ← UBA behavior baseline
│
├── Modules\
│   ├── ServiceAudit.ps1          ← T1543 — running services
│   ├── PortScan.ps1              ← T1049 — TCP/UDP listeners
│   ├── TaskAudit.ps1             ← T1053 — scheduled tasks
│   ├── StartupAudit.ps1          ← T1547 — autostart entries
│   ├── SoftwareInventory.ps1     ← inventory + CVE surface
│   ├── UserAudit.ps1             ← T1136 — local accounts
│   ├── EventParser.ps1           ← T1110 / T1562 — event log analysis
│   ├── ProcessAudit.ps1          ← T1036 — process integrity
│   ├── LOLBINDetection.ps1       ← T1218 — living-off-the-land binaries
│   ├── MemoryInjection.ps1       ← T1055 — memory injection
│   ├── PersistenceHunter.ps1     ← T1546 / T1547 — persistence mechanisms
│   ├── LateralMovement.ps1       ← T1021 — lateral movement indicators
│   ├── CredentialAccess.ps1      ← T1003 — credential theft indicators
│   ├── NetworkAnomaly.ps1        ← T1071 — network anomalies
│   ├── IOCScanner.ps1            ← T1566 — IOC matching
│   ├── Baseline.ps1              ← T1070 — drift detection
│   ├── VulnCheck.ps1             ← T1190 — CVE matching
│   ├── ThreatIntel.ps1           ← multi-feed threat intel enrichment
│   ├── UBA.ps1                   ← T1078 — user behavior analytics
│   ├── RansomwareGuard.ps1       ← T1486 — ransomware detection
│   ├── RMMDetect.ps1             ← T1219 — RMM tool detection
│   ├── ForensicCapture.ps1       ← IR package builder
│   ├── Quarantine.ps1            ← AES-256 file quarantine
│   ├── RemoveItem.ps1            ← confirmed permanent removal
│   ├── Alert.ps1                 ← Event Log / Email / Webhook alerting
│   ├── Report.ps1                ← HTML report generator
│   ├── WeeklyReport.ps1          ← weekly email digest
│   ├── SelfProtect.ps1           ← T1562 — suite self-integrity check
│   ├── IntegrityEngine.ps1       ← HMAC-SHA256 file signing engine
│   ├── AuditChain.ps1            ← chained audit log verification
│   ├── WhitelistProtection.ps1   ← encrypted whitelist guard
│   ├── ProcessIntegrity.ps1      ← T1574 — service binary validation
│   ├── RemoteAnchor.ps1          ← remote integrity anchor sync
│   ├── RuntimeProtect.ps1        ← runtime anti-injection
│   ├── PrivilegeAbuse.ps1        ← T1068 — privilege escalation detection
│   └── ServiceWorker.ps1         ← Windows Service host worker
│
├── Baseline\
│   └── baseline.json             ← signed system state snapshot
│
├── Quarantine\
│   └── quarantine_manifest.json  ← metadata for quarantined files
│
├── Reports\
│   ├── SecurityReport_*.html     ← per-scan HTML reports
│   └── Weekly\                   ← weekly digest reports
│
└── Logs\
    ├── audit.log                 ← chained tamper-evident audit trail
  ├── tamper.log                ← integrity violation events
  ├── service_stdout.log        ← ServiceWorker live output (NSSM)
  └── service_stderr.log        ← ServiceWorker errors (NSSM)

└── Tools\
  └── nssm.exe                  ← NSSM service wrapper (auto-downloaded)
```

---

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Operating System | Windows 10 21H2 | Windows 11 recommended |
| PowerShell | 5.1 | PS 7+ recommended for full operator support |
| .NET Framework | 4.7.2 | Required for PBKDF2/SHA256 key derivation |
| Privileges | Administrator | Required for service, ACL, and event log operations |
| NSSM | 2.24 | Auto-downloaded by installer. Open-source service wrapper (~300KB). Manual download: https://nssm.cc |
| Execution Policy | RemoteSigned | Or sign scripts with a trusted certificate |
| Disk space | ~50 MB | For logs, reports, and quarantine files |
| Internet access | Optional | Only needed for Threat Intel API features |

---

## Installation

### 1 — Set execution policy

```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### 2 — Clone the repository

```powershell
git clone https://github.com/blankV0/SSuite-QuietMonitor.git C:\QuietMonitor
```

### 3 — Run the installer as Administrator

```powershell
cd C:\QuietMonitor
.\Install-QuietMonitor.ps1 install
```

The installer will:
1. Create all required directories (Logs, Reports, Quarantine, Tools)
2. Download and verify NSSM 2.24 (SHA256 verified, ~300KB)
3. Register QuietMonitorSvc as a real Windows Service via NSSM
4. Configure service auto-restart on failure (30s delay)
5. Redirect service stdout/stderr to C:\QuietMonitor\Logs\
6. Harden ACLs on Config\ and Logs\
7. Build the SHA256 integrity manifest
8. Create weekly report Task Scheduler entry (Monday 08:00)
9. Initialize DPAPI integrity key in registry

> **Windows Defender:** If Windows Defender blocks scripts, the installer automatically adds
> `C:\QuietMonitor` to Defender exclusions. If blocked before install, run:
> ```powershell
> Add-MpPreference -ExclusionPath 'C:\QuietMonitor'
> ```

### 4 — Configure your environment

```powershell
notepad C:\QuietMonitor\Config\settings.json
```

Change at minimum:
- Quarantine.Password (mandatory — do not use default)
- SMTP settings if you want email alerts
- API keys for threat intel (optional)

### 5 — Launch

```powershell
.\QuietMonitor.ps1
```

---

## Usage

### Interactive Console

Right-click `QuietMonitor.ps1` → **Run with PowerShell (as Administrator)** or:

```powershell
# From an elevated PowerShell prompt
cd C:\QuietMonitor
.\QuietMonitor.ps1
```

The dashboard displays real-time service status, last scan time, risk score, active threat count, and quarantine item count.

#### Menu Reference

| Option | Label | Description |
|--------|-------|-------------|
| `[1]` | Run Full Security Scan | Executes all 29 detection modules, generates HTML report |
| `[2]` | View Threat Report | Opens the most recent HTML report in the default browser |
| `[3]` | Quarantine Manager | Browse, restore, or permanently delete quarantined files |
| `[4]` | Live Audit Log | Tail `audit.log` with color-coded severity in real-time |
| `[5]` | Manage Whitelist | Edit trusted services, ports, publishers, and task authors |
| `[6]` | Configure Settings | Edit SMTP, webhook, thresholds, and API keys |
| `[7]` | Service Control | Start, stop, restart, install, or uninstall QuietMonitorSvc |
| `[8]` | Quick Scan | Fast scan of highest-priority modules only |
| `[9]` | Forensic IR Package | Build a timestamped ZIP of process, network, and log state |
| `[10]` | Rebuild System Baseline | Capture a new signed baseline snapshot |
| `[11]` | Vulnerability Report | Match installed software against NVD CVE feed |
| `[12]` | Threat Intel Check | Run IP/hash/URL lookups against configured threat feeds |
| `[13]` | Weekly Report Now | Generate and email the weekly digest immediately |
| `[14]` | UBA Dashboard | Display user behavior anomaly summary |
| `[15]` | Ransomware Guard | Show FileSystemWatcher status and honeypot state |
| `[16]` | Integrity Check | Manually verify HMAC signatures on all suite files |
| `[17]` | RMM Detection Scan | Scan for remote monitoring and management tools |
| `[18]` | Verify Audit Log Chain | Validate the full blockchain-style audit chain |
| `[19]` | Remote Anchor Sync | Sync local fingerprint with remote anchor endpoint |
| `[0]` | Exit | Close the console |

---

### Automated / Scheduled Mode

Use `Run-SecuritySuite.ps1` directly for CI pipelines or Task Scheduler:

```powershell
# Full scan with HTML report
.\Run-SecuritySuite.ps1 -FullReport

# Detection only — no quarantine, no alerts, no report
.\Run-SecuritySuite.ps1 -ScanOnly

# Auto-quarantine all Red findings (still prompts "Type YES to confirm")
.\Run-SecuritySuite.ps1 -AutoQuarantine -FullReport

# Combined: auto-quarantine + always generate report
.\Run-SecuritySuite.ps1 -AutoQuarantine -FullReport
```

| Flag | Description |
|------|-------------|
| `-ScanOnly` | Disable all response actions and alerts. Detection-only. |
| `-AutoQuarantine` | Automatically initiate quarantine for Red-severity file findings. Requires typed confirmation. |
| `-FullReport` | Always generate the HTML report, even when all findings are Green. |

---

### First Run Walkthrough

1. Launch `.\QuietMonitor.ps1` as Administrator
2. The installer check runs automatically — if `Config\module_hashes.json` is missing, you will be prompted to run `Install-QuietMonitor.ps1` first
3. Press `[10]` to build your initial system baseline (required for drift detection)
4. Press `[1]` to run a full scan — expect Yellow findings on a new install until the whitelist is tuned
5. Review findings in the HTML report (option `[2]`) or in the console
6. Use option `[5]` to add trusted services, ports, and publishers to the whitelist
7. Re-scan until the environment is clean; the risk score should approach 0

---

## Configuration

All settings live in `Config\settings.json`. The file is plain JSON — edit with any text editor.

### Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `SMTP.Server` | string | `smtp.yourdomain.com` | SMTP relay hostname |
| `SMTP.Port` | int | `587` | SMTP port (587 = STARTTLS, 465 = SSL) |
| `SMTP.UseSsl` | bool | `true` | Enable TLS on the SMTP connection |
| `SMTP.From` | string | — | Sender address for alert emails |
| `SMTP.To` | string | — | Recipient address for alert emails |
| `SMTP.PasswordEncrypted` | string | `""` | DPAPI-encrypted SMTP password (see note below) |
| `Webhook.Enabled` | bool | `false` | Enable HTTP POST webhook alerts |
| `Webhook.Url` | string | — | Webhook endpoint URL |
| `Webhook.AuthHeader` | string | `""` | Optional Bearer token for webhook auth |
| `Quarantine.Password` | string | **CHANGE THIS** | AES-256 key derivation password (min 16 chars) |
| `Quarantine.BasePath` | string | `C:\QuietMonitor\Quarantine` | Quarantine storage directory |
| `Logging.MaxLogSizeMB` | int | `50` | Rotate audit.log when it exceeds this size |
| `weeklyReport.enabled` | bool | `true` | Enable scheduled weekly digest |
| `weeklyReport.dayOfWeek` | string | `Monday` | Day to send the weekly report |
| `weeklyReport.time` | string | `08:00` | Time to send the weekly report (24h, local) |
| `weeklyReport.retentionDays` | int | `90` | Delete reports older than this many days |
| `baseline.autoRebuildDays` | int | `30` | Auto-prompt to rebuild baseline after N days |
| `uba.failedLoginThreshold` | int | `5` | Failed logins within window to trigger UBA alert |
| `uba.failedLoginWindowMinutes` | int | `5` | Sliding window for failed login counting |
| `uba.normalHoursStart` | string | `08:00` | Start of normal working hours |
| `uba.normalHoursEnd` | string | `18:00` | End of normal working hours |
| `ransomwareGuard.massRenameThreshold` | int | `10` | Files renamed within window to trigger alert |
| `ransomwareGuard.honeypotEnabled` | bool | `true` | Place canary files in watched folders |
| `threatIntel.abuseIPDB.enabled` | bool | `false` | Enable AbuseIPDB lookups |
| `threatIntel.virusTotal.enabled` | bool | `false` | Enable VirusTotal lookups |
| `threatIntel.cacheHours` | int | `24` | Threat-intel result cache lifetime |
| `vulnerability.criticalPatchAgeDays` | int | `30` | Flag missing patches older than N days |
| `selfProtect.enabled` | bool | `true` | Enable anti-tamper suite self-monitoring |

### Encrypting the SMTP Password (DPAPI)

Run once on the **target machine** (DPAPI keys are machine-bound):

```powershell
$enc = Read-Host "SMTP password" -AsSecureString | ConvertFrom-SecureString
# Paste the output into settings.json -> SMTP.PasswordEncrypted
```

---

## How It Works

### 1 — The Baseline ("taking a photo")

On first run, QuietMonitor captures a signed snapshot of your system: running services, open ports, startup entries, scheduled tasks, installed software, and local user accounts. This baseline is saved to `Baseline\baseline.json` and signed with a DPAPI-protected HMAC key. Every subsequent scan compares live state against this photo — anything that changed since is flagged for review.

### 2 — Scanning ("comparing to the photo")

`Run-SecuritySuite.ps1` dot-sources all 29 detection modules and executes them in sequence. Each module returns a list of finding objects with a severity (`Red` / `Yellow` / `Green`), a MITRE ATT&CK technique ID, and details. Findings are aggregated into a weighted risk score (0–100). The entire process runs in the current PowerShell process — no child processes, no network calls unless explicitly configured.

### 3 — Quarantine ("isolating a threat")

When a file is quarantined, it is **moved** — never deleted. It is AES-256-CBC encrypted with a PBKDF2-derived key (100 000 SHA-256 iterations, 16-byte random salt). The original path, hash, and metadata are stored in `quarantine_manifest.json`. A SHA-256 hash is verified on restore to detect any in-place tampering of the quarantined archive. Nothing is permanently lost until you explicitly choose **Delete** from the Quarantine Manager.

### 4 — Integrity Chain ("tamper-proof logs")

Every entry written to `audit.log` includes the SHA-256 hash of the previous entry — like a blockchain. If any historical entry is modified, the chain breaks and option `[18]` will report the exact position of the break. Each QuietMonitor module file is also HMAC-signed at install time; option `[16]` re-verifies all signatures to detect unauthorized script modification.

### 5 — Weekly Report ("the weekly briefing")

A Windows Task Scheduler entry (created by the installer) calls `Run-SecuritySuite.ps1 -FullReport` every Monday at 08:00. The weekly report module aggregates findings across all reports in the retention window, calculates trend lines (improving / worsening / stable), and emails a self-contained HTML digest. The risk score, top techniques, and quarantine activity are summarized for management review.

### 6 — Windows Service (NSSM)

QuietMonitor runs as a real Windows Service using NSSM (Non-Sucking Service Manager). Unlike a raw PowerShell script, NSSM correctly signals the Windows Service Control Manager (SCM) that the service has started, handles graceful stop/restart, and captures all stdout/stderr output to rotating log files. The service starts automatically on boot and restarts within 30 seconds if it crashes.

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Detecting Module |
|---|---|---|
| T1003 | OS Credential Dumping | CredentialAccess |
| T1021 | Remote Services | LateralMovement |
| T1036 | Masquerading | ProcessAudit, IntegrityEngine |
| T1048 | Exfiltration Over Alternative Protocol | NetworkAnomaly |
| T1049 | System Network Connections Discovery | PortScan |
| T1053.005 | Scheduled Task | TaskAudit |
| T1055 | Process Injection | MemoryInjection, RuntimeProtect |
| T1055.001 | DLL Injection | MemoryInjection |
| T1068 | Exploitation for Privilege Escalation | PrivilegeAbuse |
| T1070 | Indicator Removal on Host | Baseline, AuditChain |
| T1071 | Application Layer Protocol | NetworkAnomaly |
| T1078 | Valid Accounts | UBA |
| T1098 | Account Manipulation | UserAudit |
| T1110 | Brute Force | EventParser, UBA |
| T1136.001 | Create Account: Local Account | UserAudit |
| T1190 | Exploit Public-Facing Application | VulnCheck |
| T1202 | Indirect Command Execution | LOLBINDetection |
| T1204 | User Execution | IOCScanner |
| T1218 | System Binary Proxy Execution | LOLBINDetection |
| T1219 | Remote Access Software | RMMDetect |
| T1486 | Data Encrypted for Impact | RansomwareGuard |
| T1490 | Inhibit System Recovery | RansomwareGuard |
| T1543.003 | Windows Service | ServiceAudit, EventParser |
| T1546 | Event Triggered Execution | PersistenceHunter |
| T1547.001 | Registry Run Keys / Startup Folder | StartupAudit, PersistenceHunter |
| T1553 | Subvert Trust Controls | RemoteAnchor |
| T1555 | Credentials from Password Stores | CredentialAccess |
| T1562.001 | Disable or Modify Tools | WhitelistProtection, SelfProtect |
| T1562.002 | Disable Windows Event Logging | EventParser, AuditChain |
| T1566 | Phishing (IOC matching) | IOCScanner, ThreatIntel |
| T1570 | Lateral Tool Transfer | LateralMovement |
| T1574 | Hijack Execution Flow | ProcessIntegrity |

---

## Screenshots

To contribute screenshots:
1. Run the suite and take screenshots of the menu and a sample report
2. Save to /docs/screenshots/
3. Submit a Pull Request

**Main Dashboard & Menu**

```
[ Menu Screenshot ]
```

**HTML Threat Report**

```
[ HTML Report Screenshot ]
```

**Weekly Digest Email**

```
[ Weekly Report Screenshot ]
```

---

## API Keys (Optional)

QuietMonitor works fully offline without any API keys. The following integrations are **opt-in**:

| Service | Key Required | Free Tier | Where to Register | Setting |
|---|---|---|---|---|
| **AbuseIPDB** | Yes | 1 000 checks/day | [abuseipdb.com/api](https://www.abuseipdb.com/api) | `threatIntel.abuseIPDB.apiKey` |
| **VirusTotal** | Yes | 4 requests/min | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | `threatIntel.virusTotal.apiKey` |
| **MalwareBazaar** | No | Unlimited | [bazaar.abuse.ch](https://bazaar.abuse.ch) | Auto-enabled |
| **URLhaus** | No | Offline block-list | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/downloads/text/) | Download to `Config\urlhaus_blocklist.txt` |
| **NVD CVE Feed** | No | Full feed | [nvd.nist.gov](https://nvd.nist.gov/vuln/data-feeds) | Download to `Config\nvd_cve_feed.json` |

To add a key, edit `Config\settings.json`:

```json
"threatIntel": {
  "abuseIPDB": {
    "enabled": true,
    "apiKey": "YOUR_KEY_HERE"
  },
  "virusTotal": {
    "enabled": true,
    "apiKey": "YOUR_KEY_HERE"
  }
}
```

---

## License

```
MIT License

Copyright (c) 2025 QuietMonitor Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

> **Security notice:** `Config\settings.json` contains credentials. Never commit this file to a public repository. The provided `.gitignore` excludes it by default.



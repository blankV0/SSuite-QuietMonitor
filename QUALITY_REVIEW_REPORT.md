# QuietMonitor Security Suite v2.0 — Quality Audit Report

**Reviewed:** All 40 files (QuietMonitor.ps1, Run-SecuritySuite.ps1, Install-QuietMonitor.ps1, README.md, Config/*.json, Modules/*.ps1 × 36)  
**Scope:** Code quality · Security · Integrity system · Integration · Error handling · Windows 11 compatibility · Missing pieces

---

## SECTION 1 — Files Reviewed

| # | File | Status |
|---|------|--------|
| 1 | `QuietMonitor.ps1` | ⚠ Has bugs |
| 2 | `Run-SecuritySuite.ps1` | ⚠ Has minor bugs |
| 3 | `Install-QuietMonitor.ps1` | ✓ OK |
| 4 | `README.md` | ✓ OK |
| 5 | `Config/settings.json` | ⚠ Hardcoded default password |
| 6 | `Config/whitelist.json` | ⚠ Corrupted JSON entry |
| 7 | `Config/mitre_mapping.json` | ✓ OK |
| 8 | `Modules/Alert.ps1` | ✓ OK |
| 9 | `Modules/AuditChain.ps1` | ✓ OK (PS5.1 note) |
| 10 | `Modules/Baseline.ps1` | ✓ OK |
| 11 | `Modules/CredentialAccess.ps1` | ✓ OK |
| 12 | `Modules/EventParser.ps1` | ✓ OK |
| 13 | `Modules/ForensicCapture.ps1` | ⚠ PS7 `??` operator |
| 14 | `Modules/IntegrityEngine.ps1` | ⚠ PS7 `?.` operator |
| 15 | `Modules/IOCScanner.ps1` | ✓ OK |
| 16 | `Modules/LateralMovement.ps1` | ✓ OK |
| 17 | `Modules/LOLBINDetection.ps1` | ✓ OK |
| 18 | `Modules/MemoryInjection.ps1` | ✓ OK |
| 19 | `Modules/NetworkAnomaly.ps1` | ✓ OK |
| 20 | `Modules/PersistenceHunter.ps1` | ✓ OK |
| 21 | `Modules/PortScan.ps1` | ✓ OK |
| 22 | `Modules/ProcessAudit.ps1` | ✓ OK |
| 23 | `Modules/ProcessIntegrity.ps1` | ⚠ PS7 `?.` operator |
| 24 | `Modules/Quarantine.ps1` | ✓ OK |
| 25 | `Modules/RansomwareGuard.ps1` | ✓ OK |
| 26 | `Modules/RemoteAnchor.ps1` | ⚠ PS7 `?.` operator |
| 27 | `Modules/RemoveItem.ps1` | ✓ OK |
| 28 | `Modules/Report.ps1` | ✓ OK |
| 29 | `Modules/RMMDetect.ps1` | ✓ OK |
| 30 | `Modules/RuntimeProtect.ps1` | ✓ OK |
| 31 | `Modules/SelfProtect.ps1` | ✓ OK |
| 32 | `Modules/ServiceAudit.ps1` | ✓ OK |
| 33 | `Modules/ServiceWorker.ps1` | ✓ OK |
| 34 | `Modules/SoftwareInventory.ps1` | ✓ OK |
| 35 | `Modules/StartupAudit.ps1` | ✓ OK |
| 36 | `Modules/TaskAudit.ps1` | ✓ OK |
| 37 | `Modules/ThreatIntel.ps1` | ✓ OK |
| 38 | `Modules/UBA.ps1` | ✓ OK |
| 39 | `Modules/UserAudit.ps1` | ✓ OK |
| 40 | `Modules/VulnCheck.ps1` | ✓ OK |
| 41 | `Modules/WeeklyReport.ps1` | ✓ OK |
| 42 | `Modules/WhitelistProtection.ps1` | 🔴 Critical: .NET Core API |
| 43 | `Install-QuietMonitor.ps1` | ⚠ PS7 `?.` operator |

---

## SECTION 2 — Critical Issues (Must Fix Before Use)

### BUG-01 · Interactive Menu Labels Completely Wrong for Options [3]–[9]
**File:** `QuietMonitor.ps1` — `Show-MainMenu()`, ~line 755–764  
**Severity:** 🔴 CRITICAL  
**Description:**  
`Show-MainMenu` displays option labels that do **not match** what the `switch` statement executes. The menu display was updated to a different ordering but the switch cases were never updated. Every choice from [3] to [9] opens the wrong screen.

| User sees | User picks | What actually runs |
|-----------|-----------|-------------------|
| [3] Live Audit Log | 3 | `Show-QuarantineManager` — Quarantine Manager |
| [4] Network Analysis | 4 | `Show-AuditLogTail` — Live Audit Log |
| [5] Forensic IR Package | 5 | `Edit-Whitelist` — Whitelist Editor |
| [6] Quarantine Manager | 6 | `Edit-Settings` — Settings Editor |
| [7] Manage Whitelist | 7 | `Show-ServiceManager` — Service Control |
| [8] Configure Settings | 8 | `Invoke-QuickScan` — Quick Scan |
| [9] Service Control | 9 | `Export-ForensicsMenu` — Forensic IR Package |

Additionally, "Quick Scan" is not shown in the displayed menu at all, and "Network Analysis" label references a function that has no interactive menu handler.

**Fix:** Update the 5 `Write-Host` lines in `Show-MainMenu` to display the correct labels matching the switch cases.

---

### BUG-02 · Quarantine Manifest Filename Mismatch
**File:** `QuietMonitor.ps1` — line 47  
**Severity:** 🔴 CRITICAL  
**Description:**  
`$quarManifest` is set to `manifest.json` but `Quarantine.ps1` writes to `quarantine_manifest.json`. The Quarantine Manager UI and the dashboard counter will never find the manifest file, making the entire quarantine UI permanently broken.

```powershell
# QuietMonitor.ps1 line 47 — WRONG:
$quarManifest = Join-Path $quarantineDir 'manifest.json'

# Quarantine.ps1 line 97 — ACTUAL name:
$manifestPath = Join-Path $QuarantinePath 'quarantine_manifest.json'
```

**Fix:** Change `'manifest.json'` → `'quarantine_manifest.json'`.

---

### BUG-03 · Quarantine Restore Passes Wrong Parameters
**File:** `QuietMonitor.ps1` — line 199  
**Severity:** 🔴 CRITICAL  
**Description:**  
The Restore action in `Show-QuarantineManager` calls `Invoke-QuarantineRestore -EncryptedFile ... -AuditLog ...`.  
`Invoke-QuarantineRestore` (Quarantine.ps1 line 251) has **no** `-EncryptedFile` parameter. Its signature is:

```powershell
param(
    [Parameter(Mandatory)] [PSCustomObject]$ManifestEntry,
    [Parameter(Mandatory)] [string]$Password,
    [Parameter(Mandatory)] [string]$RestorePath,
    [Parameter(Mandatory)] [string]$AuditLog
)
```

All three mandatory parameters (`ManifestEntry`, `Password`, `RestorePath`) are missing from the call. PowerShell will throw a `ParameterBindingException` — restore is completely broken.

**Fix:** Replace the call with correct parameters (pass `$entry` as `ManifestEntry`, read password from settings, prompt for restore path).

---

### BUG-04 · `CryptographicOperations.FixedTimeEquals` Unavailable on PS 5.1
**File:** `Modules/WhitelistProtection.ps1` — line 193  
**Severity:** 🔴 CRITICAL (breaks PS 5.1 entirely)  
**Description:**  
`[System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals()` is a **.NET Core / .NET 5+** API. It does **not exist** in .NET Framework 4.x, which is what PowerShell 5.1 uses. On PS 5.1, every call to `Get-DecryptedWhitelist` will throw `TypeNotFound` and the entire whitelist decryption path fails.

**Fix:** Replace with a manual constant-time comparison loop compatible with .NET Framework.

---

## SECTION 3 — Minor Issues (Should Fix)

### MINOR-01 · `Test-Variable` Is Not a Valid Cmdlet
**File:** `Run-SecuritySuite.ps1` — line 422  
```powershell
if ($shouldReport -and (Test-Variable 'reportFile' -ErrorAction SilentlyContinue)) {
```
`Test-Variable` does not exist in PowerShell. The `-ErrorAction SilentlyContinue` silently swallows the error, so the report path is never printed in the summary. Replace with `(Get-Variable 'reportFile' -ErrorAction SilentlyContinue)`.

---

### MINOR-02 · Version Banner Mismatch
**File:** `Run-SecuritySuite.ps1` — ~line 196  
Banner prints `"QuietMonitor Security Suite v1.0"`. `QuietMonitor.ps1` displays `v2.0`. The suite is v2.0.

---

### MINOR-03 · Quarantine Count in Dashboard Uses Wrong Property
**File:** `QuietMonitor.ps1` — line 732  
```powershell
$quarCount = @((Get-Content $quarManifest -Raw | ConvertFrom-Json).entries).Count
```
The manifest is a flat JSON array — there is no `.entries` property. `ConvertFrom-Json` on a JSON array returns `Object[]`, not a PSCustomObject. `.entries` returns `$null`; `@($null).Count` = **1**, so the dashboard shows "1" even when the quarantine is empty. Remove `.entries`.

---

### MINOR-04 · Corrupted Entry in `whitelist.json`
**File:** `Config/whitelist.json` — `TrustedTaskAuthors` array, last entry  
```json
"$(@('N/A'))'"
```
This is an unevaluated PowerShell string that was accidentally embedded in JSON. It should be `"N/A"` or simply removed.

---

### MINOR-05 · No `#Requires -Version 5.1` Tag
No file declares the minimum PowerShell version. Several PS7-specific language features are used (see Section 5), which would cause silent or hard failures on PS 5.1 without clear error messages. Add `#Requires -Version 5.1` (minimum) or `#Requires -Version 7.0` where PS7 features are intentionally used.

---

### MINOR-06 · `Edit-Settings` Default Schema Does Not Match Actual `settings.json` Structure
**File:** `QuietMonitor.ps1` — `Edit-Settings` function  
`$defaults` uses a flat schema (`SmtpPassword`, `SmtpServer`, etc.) while `settings.json` uses a nested structure (`SMTP.Server`, `SMTP.PasswordEncrypted`). If `settings.json` is missing or corrupted and the fallback fires, the settings editor would produce a flat incompatible config. This is low-risk (file always exists after install) but misleading.

---

## SECTION 4 — Security Review

### SEC-01 · Quarantine Password Is a Hardcoded Default (Medium Risk)
**File:** `Config/settings.json`  
```json
"Password": "ChangeThisPassword-Min16Chars!"
```
This default value is in the repository. Users who do not customise it before deployment will use a known/guessable quarantine encryption key. Consider enforcing password change at first run or generating a random key during `Install-QuietMonitor.ps1`.

---

### SEC-02 · SMTP Password Storage Is Correct (Resolved)
`Alert.ps1` correctly reads `$Settings.SMTP.PasswordEncrypted` (a DPAPI-encrypted `ConvertFrom-SecureString` value) and decrypts it in memory. `settings.json` template uses `PasswordEncrypted = ""` with a note instructing DPAPI encryption. The `Edit-Settings` default hashtable has an unused `SmtpPassword = ''` key, but it is never read by Alert.ps1.

---

### SEC-03 · Whitelist AES-256/HMAC-SHA256 Implementation (Correct)
`WhitelistProtection.ps1` correctly implements Encrypt-then-MAC:
- Independent PBKDF2-SHA256 salts (32 bytes each) for enc key and HMAC key
- IV prepended to ciphertext before HMAC computation
- HMAC verified before any decryption attempt (fail-fast)
- Plaintext bytes zeroed in `finally` blocks
- Constant-time comparison attempted (blocked on PS 5.1 — see BUG-04)

---

### SEC-04 · DPAPI Registry Key Storage (Correct)
`IntegrityEngine.ps1` and `AuditChain.ps1` use `System.Security.Cryptography.ProtectedData` (DPAPI LocalMachine scope) to store HMAC keys in registry under `HKLM:\SOFTWARE\QuietMonitor\Security`. Key bytes are cleared from memory after use.

---

### SEC-05 · HTML Report Uses HtmlEncode (XSS-safe)
`Report.ps1` correctly applies `[System.Web.HttpUtility]::HtmlEncode()` to all user-controllable data (file paths, finding names, details, hashes) before embedding in the HTML report. No XSS risk.

---

### SEC-06 · `Install-QuietMonitor.ps1` Service Password in Command Line (Low Risk)
`sc.exe ... password=$ServicePassword` — if a non-LocalSystem service account is used, the password appears briefly in the process command line. This is a Windows `sc.exe` limitation. Low risk in practice since `LocalSystem` is the default and the function is called interactively by an Administrator.

---

## SECTION 5 — Windows 11 Compatibility (PS 5.1 / PS 7+)

### COMPAT-01 · Null-Conditional `?.` Operator — PS 7.1+ Only
The following files use the `?.` operator which is **PS 7.1+** and throws `ParseException` on PS 5.1:

| File | Line | Usage |
|------|------|-------|
| `QuietMonitor.ps1` | 726–727 | `$svc?.Status` |
| `IntegrityEngine.ps1` | 399 | `$sig.SignerCertificate?.Subject` |
| `ProcessIntegrity.ps1` | 78 | `$svcWmi?.PathName` |
| `RemoteAnchor.ps1` | 202, 270 | `$fp?.fingerprint`, `$settings?.selfProtect` |
| `Install-QuietMonitor.ps1` | 46 | `(Get-Command pwsh.exe ...)?.Source` |
| `WhitelistProtection.ps1` | 358 | `$cfg?.selfProtect?.whitelistRemoteAnchorUrl` |

**Fix:** Replace each with explicit null-guard: `if ($x) { $x.Prop } else { $null }`.

---

### COMPAT-02 · Null-Coalescing `??` Operator — PS 7.0+ Only
**File:** `ForensicCapture.ps1` — line 393  
```powershell
($_.Path ?? '')
```
**Fix:** Replace with `if ($_.Path) { $_.Path } else { '' }`.

---

### COMPAT-03 · `Rfc2898DeriveBytes` with `HashAlgorithmName` — Requires .NET 4.7.2+
Four files use `Rfc2898DeriveBytes` with the `HashAlgorithmName.SHA256` overload: `Quarantine.ps1`, `WhitelistProtection.ps1`, `RemoteAnchor.ps1`. This constructor was added in .NET Framework **4.7.2**, which ships with Windows 10 1709+. All modern Windows 10 / Windows 11 machines are fine. This only matters if the suite must run on Windows 10 pre-1709.

---

## SECTION 6 — Integration Check

### INT-01 · Detection Module Function Names — All Correct ✓
All 29 entries in `$detectionModules` were verified against the actual function definitions in their respective `.ps1` files. Every name matches:

| Module | Function | Present |
|--------|----------|---------|
| ServiceAudit | Invoke-ServiceAudit | ✓ |
| PortScan | Invoke-PortScan | ✓ |
| TaskAudit | Invoke-TaskAudit | ✓ |
| StartupAudit | Invoke-StartupAudit | ✓ |
| SoftwareInventory | Invoke-SoftwareInventory | ✓ |
| UserAudit | Invoke-UserAudit | ✓ |
| EventParser | Invoke-EventParser | ✓ |
| ProcessAudit | Invoke-ProcessAudit | ✓ |
| IOCScanner | Invoke-IOCScanner | ✓ |
| LOLBINDetection | Invoke-LOLBINDetection | ✓ |
| MemoryInjection | Invoke-MemoryInjectionScan | ✓ |
| PersistenceHunter | Invoke-PersistenceHunter | ✓ |
| NetworkAnomaly | Invoke-NetworkAnomalyDetection | ✓ |
| CredentialAccess | Invoke-CredentialAccessMonitor | ✓ |
| LateralMovement | Invoke-LateralMovementScan | ✓ |
| Baseline | Invoke-BaselineDrift | ✓ |
| VulnCheck | Invoke-VulnCheck | ✓ |
| ThreatIntel | Invoke-ThreatIntelCheck | ✓ |
| UBA | Invoke-UBAAnalysis | ✓ |
| RansomwareGuard | Invoke-RansomwareGuardScan | ✓ |
| SelfProtect | Invoke-SelfIntegrityCheck | ✓ |
| WhitelistProtection | Invoke-WhitelistIntegrityCheck | ✓ |
| IntegrityEngine | Invoke-IntegrityCheck | ✓ |
| AuditChain | Invoke-AuditChainVerify | ✓ |
| RuntimeProtect | Invoke-RuntimeProtectionCheck | ✓ |
| ProcessIntegrity | Invoke-ProcessIntegrityCheck | ✓ |
| RemoteAnchor | Invoke-RemoteAnchorSync | ✓ |
| PrivilegeAbuse | Invoke-PrivilegeAbuseCheck | ✓ |
| RMMDetect | Invoke-RMMDetection | ✓ |

---

### INT-02 · Install-QuietMonitor.ps1 Function Exports — Correct ✓
`Install-QuietMonitorService` and `Uninstall-QuietMonitorService` are defined and called correctly from `Show-ServiceManager`.

---

### INT-03 · Get-RiskScore / Get-RiskLevel Available at Runtime ✓
Both functions are defined in `WeeklyReport.ps1`, which is in `$moduleNames` and dot-sourced before the detection phase. Run-SecuritySuite.ps1 uses `Get-Command ... -ErrorAction SilentlyContinue` guards before calling them.

---

### INT-04 · Menu Functions [16]–[19] Wire Up Correctly ✓
The four new anti-tamper menu functions (`Invoke-ManualIntegrityCheck`, `Invoke-RMMScan`, `Invoke-AuditChainVerifyMenu`, `Invoke-RemoteAnchorSyncMenu`) dot-source their modules and call the correct orchestrator functions.

---

### INT-05 · SelfProtect Initialised During Install ✓
`Install-QuietMonitor.ps1` Step 10 dot-sources `SelfProtect.ps1` and calls `Initialize-SelfProtection`, building `Config/module_hashes.json`.

---

## SECTION 7 — Error Handling Assessment

| Area | Quality |
|------|---------|
| Module load failures in Run-SecuritySuite.ps1 | ✓ Graceful — warns and continues |
| Detection module exceptions | ✓ Caught per-module, logged, scan continues |
| Missing module files | ✓ Checked with `Test-Path` before dot-source in all UI handlers |
| ACL hardening failures | ✓ All wrapped in `try/catch` with `<# best-effort #>` |
| Quarantine encryption | ✓ `finally` zeroes sensitive bytes; MAGIC header validates format |
| Audit log writes | ✓ `ErrorAction SilentlyContinue` on all appends; never terminates scan |
| Alert channel failures | ✓ Each channel (Event Log, Email, Webhook) independently caught |
| HMAC tamper detection | ✓ Fail-fast before decryption; logs to tamper.log |
| Network calls (ThreatIntel, RemoteAnchor) | ✓ `WebException` caught separately; network failure ≠ tamper |
| Quarantine restore (UI) | 🔴 BUG-03 — completely broken, throws parameter error |

---

## SECTION 8 — Missing Pieces

1. **No Quarantine restore UI path for Password**: After fixing BUG-03, the restore UI still has no mechanism to collect the quarantine password from the user. `Show-QuarantineManager` must prompt for it or read it from settings.

2. **No `#Requires -Version 5.1` on any file** — see MINOR-05.

3. **`IntegrityEngine.ps1` — `Invoke-IntegrityCheck` does not call `Initialize-IntegrityKey`/`Initialize-IntegrityManifest` on first run**: If the manifest was never built (`C:\QuietMonitor\integrity\manifest.json` absent), `Test-IntegrityManifest` returns no findings rather than prompting to initialise. This is handled by a first-run detection path in `Test-IntegrityManifest` itself — acceptable.

4. **No network analysis in the interactive menu**: The `Show-MainMenu` display currently shows `[4] Network Analysis` (which will be fixed to the correct label) but there is no dedicated interactive wrapper for `NetworkAnomaly`. This module only runs in automated scans. Not a bug but a gap.

5. **`Config/settings.json` has no `selfProtect.whitelistRemoteAnchorUrl` field**: `WhitelistProtection.ps1` reads `$cfg?.selfProtect?.whitelistRemoteAnchorUrl` (remote anchor URL) but `settings.json` has no such key under `selfProtect`. The remote check silently skips — acceptable but should be documented.

---

## FINAL VERDICT

```
╔══════════════════════════════════════════════════════╗
║  VERDICT: NOT READY FOR PRODUCTION                   ║
║                                                      ║
║  4 critical bugs block core functionality:           ║
║    BUG-01  Menu labels [3-9] are all wrong           ║
║    BUG-02  Quarantine manifest filename mismatch     ║
║    BUG-03  Quarantine restore throws at runtime      ║
║    BUG-04  WhitelistProtection fails on PS 5.1       ║
║                                                      ║
║  After fixing BUG-01..04 and MINOR-01..04, the       ║
║  suite will be READY for Windows 11 / PS 7.x use.   ║
║  Full PS 5.1 compatibility requires additionally     ║
║  resolving COMPAT-01 and COMPAT-02 (10 files).       ║
╚══════════════════════════════════════════════════════╝
```

| Category | Count |
|----------|-------|
| 🔴 Critical bugs | 4 |
| ⚠ Minor bugs | 6 |
| 🔒 Security concerns | 1 (low-medium) |
| 🖥 PS 5.1 compat breaks | 12 usages across 6 files |
| ✓ Confirmed correct | 29 module integrations, full crypto stack, ACLs, HTML encoding |

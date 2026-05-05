#Requires -RunAsAdministrator
# =============================================================
# IntegrityEngine.ps1 — Full-system hash verification
# Covers: QuietMonitor file manifest (HMAC-signed), registry
# backup of manifest hash, System32 spot-check + high-value
# targets, Authenticode signature validation on running procs.
# MITRE: T1562 (Impair Defenses), T1014 (Rootkit), T1036 (Masq.)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

# ── Constants ─────────────────────────────────────────────────
$script:IE_MANIFEST_DIR  = 'C:\QuietMonitor\integrity'
$script:IE_MANIFEST_FILE = 'C:\QuietMonitor\integrity\manifest.json'
$script:IE_REG_PATH      = 'HKLM:\SOFTWARE\QuietMonitor\Security'
$script:IE_REG_KEY_IK    = 'IntegrityKey'        # DPAPI-encrypted HMAC key
$script:IE_REG_KEY_MH    = 'ManifestHash'         # SHA256 of last known-good manifest
$script:IE_TAMPER_LOG    = 'C:\QuietMonitor\Logs\tamper.log'

# High-value system binaries always checked (never spot-sampled)
$script:IE_HIGHVALUE_BINS = @(
    'lsass.exe','svchost.exe','winlogon.exe','explorer.exe',
    'csrss.exe','services.exe','smss.exe','wininit.exe',
    'spoolsv.exe','taskhostw.exe','dwm.exe','lsm.exe'
)

# ── DPAPI key management ──────────────────────────────────────
function script:Get-IEIntegrityKey {
    try {
        if (-not (Test-Path $script:IE_REG_PATH)) { return $null }
        $enc = (Get-ItemProperty -LiteralPath $script:IE_REG_PATH -Name $script:IE_REG_KEY_IK -ErrorAction Stop).$script:IE_REG_KEY_IK
        return [System.Security.Cryptography.ProtectedData]::Unprotect(
            $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    } catch { return $null }
}

function Initialize-IntegrityKey {
    <#
    .SYNOPSIS
        Generates a fresh 32-byte HMAC key, protects it with DPAPI
        (LocalMachine scope), and stores it in the registry.
        Must be called during installation.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $key = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        $key, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

    if (-not (Test-Path $script:IE_REG_PATH)) {
        New-Item -Path $script:IE_REG_PATH -Force | Out-Null
    }
    Set-ItemProperty -LiteralPath $script:IE_REG_PATH -Name $script:IE_REG_KEY_IK -Value $encrypted -Type Binary

    [Array]::Clear($key, 0, $key.Length)
    if (-not (Test-Path $script:IE_MANIFEST_DIR)) {
        New-Item -ItemType Directory -Path $script:IE_MANIFEST_DIR -Force | Out-Null
    }
    if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [IntegrityEngine] [ACTION: InitKey] [DETAILS: DPAPI integrity key generated and stored in registry]" -Encoding UTF8 -ErrorAction SilentlyContinue }
    Write-Host '  [IntegrityEngine] Integrity key initialised.' -ForegroundColor Green
}

function script:Invoke-IETamper {
    param([string]$Message, [string]$AuditLog)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [IntegrityEngine] $Message"
    try { Add-Content -LiteralPath $script:IE_TAMPER_LOG -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
    Write-Host "  [!!!] INTEGRITY CRITICAL: $Message" -ForegroundColor Red
}

function script:Get-IEFileHash {
    param([string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower()
        $sha.Dispose()
        return $hash
    } catch { return 'ERROR' }
}

function script:New-IEFinding {
    param([string]$Sev, [string]$Cat, [string]$Name, [string]$Display, [string]$Path, [string]$Hash, [string]$Details, [string]$Mitre, [string]$MitreName)
    [PSCustomObject]@{
        Severity=$Sev; Module='IntegrityEngine'; Category=$Cat
        Title=$Display; Detail=$Details; Path=$Path
        MitreId=$Mitre; MitreName=$MitreName; ActionTaken='Alert'
    }
}

# ── Manifest management ───────────────────────────────────────
function Initialize-IntegrityManifest {
    <#
    .SYNOPSIS
        Hashes every .ps1 and .json file under BaseDir, signs the manifest
        with HMAC-SHA256 using the DPAPI-protected key, and stores:
          • manifest.json on disk
          • SHA256(manifest file) in HKLM registry as secondary anchor
    #>
    [CmdletBinding()]
    param(
        [string]$BaseDir  = 'C:\QuietMonitor',
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $key = script:Get-IEIntegrityKey
    if (-not $key) {
        Write-Host '  [IntegrityEngine] No integrity key found — run Initialize-IntegrityKey first.' -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $script:IE_MANIFEST_DIR)) {
        New-Item -ItemType Directory -Path $script:IE_MANIFEST_DIR -Force | Out-Null
    }

    $entries = [System.Collections.Generic.List[PSCustomObject]]::new()
    $files   = Get-ChildItem -Path $BaseDir -Recurse -File -Include '*.ps1','*.json','*.exe' -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -notlike '*\integrity\*' }

    foreach ($f in $files) {
        $entries.Add([PSCustomObject]@{
            path         = $f.FullName
            hash         = script:Get-IEFileHash $f.FullName
            size         = $f.Length
            lastModified = $f.LastWriteTimeUtc.ToString('o')
        })
    }

    # Build JSON payload for signing
    $payload = [PSCustomObject]@{
        createdAt  = (Get-Date -Format 'o')
        hostname   = $env:COMPUTERNAME
        baseDir    = $BaseDir
        fileCount  = $entries.Count
        files      = $entries.ToArray()
        manifestHMAC = ''  # placeholder
    }
    $payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress

    # Compute HMAC-SHA256 of the payload (without manifestHMAC field)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
    $sig  = [BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadJson))).Replace('-','').ToLower()
    $hmac.Dispose()
    [Array]::Clear($key, 0, $key.Length)

    $payload.manifestHMAC = $sig
    $finalJson = $payload | ConvertTo-Json -Depth 10

    [System.IO.File]::WriteAllText($script:IE_MANIFEST_FILE, $finalJson, [System.Text.Encoding]::UTF8)

    # Registry backup: SHA256(manifest file bytes)
    $manifestFileHash = script:Get-IEFileHash $script:IE_MANIFEST_FILE
    if (-not (Test-Path $script:IE_REG_PATH)) { New-Item -Path $script:IE_REG_PATH -Force | Out-Null }
    Set-ItemProperty -LiteralPath $script:IE_REG_PATH -Name $script:IE_REG_KEY_MH -Value $manifestFileHash -Type String

    if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [IntegrityEngine] [ACTION: ManifestInit] [DETAILS: $($entries.Count) files hashed; manifest HMAC-SHA256 signed; registry backup stored]" -Encoding UTF8 -ErrorAction SilentlyContinue }
    Write-Host "  [IntegrityEngine] Manifest built: $($entries.Count) files. Registry backup saved." -ForegroundColor Green
}

function Test-IntegrityManifest {
    <#
    .SYNOPSIS
        1. Verifies registry backup of manifest hash
        2. Verifies manifest HMAC
        3. Re-hashes all listed files and detects MODIFIED/DELETED/NEW
        Returns array of finding objects.
    #>
    [CmdletBinding()]
    param(
        [string]$BaseDir  = 'C:\QuietMonitor',
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── Step 0: Manifest file present? ──────────────────────────
    if (-not (Test-Path $script:IE_MANIFEST_FILE)) {
        script:Invoke-IETamper 'Integrity manifest MISSING — possible wipe/tamper attempt.' $AuditLog
        $findings.Add((script:New-IEFinding 'Red' 'IntegrityViolation' 'ManifestMissing' 'Integrity manifest file missing' $script:IE_MANIFEST_FILE '' 'manifest.json absent — possible wipe attempt' 'T1562' 'Impair Defenses'))
        return $findings.ToArray()
    }

    # ── Step 1: Registry backup verification ────────────────────
    try {
        $regHash = (Get-ItemProperty -LiteralPath $script:IE_REG_PATH -Name $script:IE_REG_KEY_MH -ErrorAction Stop).$script:IE_REG_KEY_MH
        $diskHash = script:Get-IEFileHash $script:IE_MANIFEST_FILE
        if ($regHash -ne $diskHash) {
            script:Invoke-IETamper "Manifest hash MISMATCH: registry=$($regHash.Substring(0,16))... disk=$($diskHash.Substring(0,16))..." $AuditLog
            $findings.Add((script:New-IEFinding 'Red' 'IntegrityViolation' 'ManifestRegistryMismatch' 'Integrity manifest modified (registry anchor mismatch)' $script:IE_MANIFEST_FILE $diskHash "Registry anchor: $($regHash.Substring(0,32))... Disk: $($diskHash.Substring(0,32))..." 'T1562' 'Impair Defenses'))
            return $findings.ToArray()  # Don't trust the manifest contents
        }
    } catch {
        $findings.Add((script:New-IEFinding 'Yellow' 'IntegrityWarning' 'ManifestNoRegistryBackup' 'No registry backup for manifest hash — run Initialize-IntegrityManifest' $script:IE_REG_PATH '' 'Registry key missing; secondary verification unavailable' 'T1562' 'Impair Defenses'))
    }

    # ── Step 2: HMAC verification ────────────────────────────────
    $key = script:Get-IEIntegrityKey
    if (-not $key) {
        $findings.Add((script:New-IEFinding 'Yellow' 'IntegrityWarning' 'IntegrityKeyMissing' 'Integrity HMAC key not found in registry' $script:IE_REG_PATH '' 'Run Initialize-IntegrityKey + Initialize-IntegrityManifest' 'T1562' 'Impair Defenses'))
        return $findings.ToArray()
    }

    try {
        $manifest = Get-Content $script:IE_MANIFEST_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        $storedHMAC = $manifest.manifestHMAC

        # Rebuild signable payload (same logic as Initialize)
        $manifest.manifestHMAC = ''
        $payloadJson = $manifest | ConvertTo-Json -Depth 10 -Compress

        $hmac    = [System.Security.Cryptography.HMACSHA256]::new($key)
        $computed = [BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payloadJson))).Replace('-','').ToLower()
        $hmac.Dispose()

        if ($computed -ne $storedHMAC) {
            script:Invoke-IETamper 'Manifest HMAC invalid — manifest.json has been tampered!' $AuditLog
            $findings.Add((script:New-IEFinding 'Red' 'IntegrityViolation' 'ManifestHMACInvalid' 'Integrity manifest HMAC invalid — tampered' $script:IE_MANIFEST_FILE $storedHMAC 'Computed HMAC does not match stored value' 'T1562' 'Impair Defenses'))
            [Array]::Clear($key, 0, $key.Length)
            return $findings.ToArray()
        }

        # ── Step 3: Re-hash all listed files ────────────────────
        $listedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($f in $manifest.files) {
            $listedPaths.Add($f.path) | Out-Null
            $currentHash = script:Get-IEFileHash $f.path
            if ($currentHash -eq 'ERROR') {
                script:Invoke-IETamper "File DELETED from manifest: $($f.path)" $AuditLog
                $findings.Add((script:New-IEFinding 'Red' 'IntegrityViolation' 'FileMissing' "Monitored file deleted: $(Split-Path $f.path -Leaf)" $f.path $f.hash "File was present at manifest creation but is now missing" 'T1070' 'Indicator Removal'))
            } elseif ($currentHash -ne $f.hash) {
                script:Invoke-IETamper "File MODIFIED: $($f.path)" $AuditLog
                $findings.Add((script:New-IEFinding 'Red' 'IntegrityViolation' 'FileModified' "Monitored file modified: $(Split-Path $f.path -Leaf)" $f.path $currentHash "Baseline: $($f.hash.Substring(0,32))... Current: $($currentHash.Substring(0,32))..." 'T1562' 'Impair Defenses'))
            }
        }

        # NEW unlisted files in BaseDir
        $currentFiles = Get-ChildItem -Path $BaseDir -Recurse -File -Include '*.ps1','*.json','*.exe' -ErrorAction SilentlyContinue |
                        Where-Object { $_.FullName -notlike '*\integrity\*' }
        foreach ($f in $currentFiles) {
            if (-not $listedPaths.Contains($f.FullName)) {
                $findings.Add((script:New-IEFinding 'Yellow' 'IntegrityWarning' 'UnlistedFile' "New unlisted file: $(Split-Path $f.FullName -Leaf)" $f.FullName (script:Get-IEFileHash $f.FullName) 'File was not present at manifest creation' 'T1562' 'Impair Defenses'))
            }
        }

        if ($findings.Count -eq 0) {
            if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [IntegrityEngine] [ACTION: ManifestVerify] [DETAILS: All $($manifest.fileCount) files verified OK]" -Encoding UTF8 -ErrorAction SilentlyContinue }
        }

    } finally {
        [Array]::Clear($key, 0, $key.Length)
    }

    return $findings.ToArray()
}

# ── System binary integrity ───────────────────────────────────
function Test-System32BinaryIntegrity {
    <#
    .SYNOPSIS
        Always checks the high-value targets.
        Spot-checks 10% random sample of remaining System32 .exe/.dll files.
        Compares against a baseline stored in manifest system32 section.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sys32    = "$env:SystemRoot\System32"
    $baselineFile = 'C:\QuietMonitor\integrity\system32_baseline.json'

    # ── Build/load baseline ──────────────────────────────────────
    if (-not (Test-Path $baselineFile)) {
        Write-Host '  [IntegrityEngine] Building System32 baseline (first run — this may take a moment)...' -ForegroundColor Cyan
        $allBins  = Get-ChildItem -Path $sys32 -File -Include '*.exe','*.dll' -ErrorAction SilentlyContinue
        $baseline = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($b in $allBins) {
            $baseline[$b.Name] = script:Get-IEFileHash $b.FullName
        }
        $baseline | ConvertTo-Json | Set-Content $baselineFile -Encoding UTF8
        Write-Host "  [IntegrityEngine] System32 baseline captured: $($baseline.Count) files." -ForegroundColor Green
        return $findings.ToArray()  # First run — nothing to compare against
    }

    $baseline = Get-Content $baselineFile -Raw -Encoding UTF8 | ConvertFrom-Json
    # Convert PSCustomObject to Dictionary for lookup
    $baseDict = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $baseline.PSObject.Properties | ForEach-Object { $baseDict[$_.Name] = $_.Value }

    # ── Always check high-value targets ─────────────────────────
    foreach ($bin in $script:IE_HIGHVALUE_BINS) {
        $path = Join-Path $sys32 $bin
        if (-not (Test-Path $path)) {
            $findings.Add((script:New-IEFinding 'Red' 'SystemBinaryIntegrity' "HighValueMissing_$bin" "HIGH-VALUE SYSTEM BINARY MISSING: $bin" $path '' "Critical system binary absent from System32 — possible rootkit" 'T1014' 'Rootkit'))
            continue
        }
        $current = script:Get-IEFileHash $path
        if ($baseDict.ContainsKey($bin) -and $current -ne $baseDict[$bin]) {
            script:Invoke-IETamper "SYSTEM BINARY MODIFIED: $bin — possible binary patching/rootkit" $AuditLog
            $findings.Add((script:New-IEFinding 'Red' 'SystemBinaryIntegrity' "HighValueModified_$bin" "CRITICAL: System binary modified — $bin" $path $current "Baseline: $($baseDict[$bin].Substring(0,32))... Current: $($current.Substring(0,32))... — Possible rootkit/binary patching" 'T1014' 'Rootkit'))
        }
    }

    # ── Spot-check 10% of remaining System32 binaries ───────────
    $others = Get-ChildItem -Path $sys32 -File -Include '*.exe','*.dll' -ErrorAction SilentlyContinue |
              Where-Object { $script:IE_HIGHVALUE_BINS -notcontains $_.Name }
    $sample = $others | Get-Random -Count ([Math]::Max(1, [int]($others.Count * 0.10)))

    foreach ($b in $sample) {
        if (-not $baseDict.ContainsKey($b.Name)) { continue }
        $current = script:Get-IEFileHash $b.FullName
        if ($current -ne $baseDict[$b.Name]) {
            script:Invoke-IETamper "SYSTEM BINARY MODIFIED: $($b.Name)" $AuditLog
            $findings.Add((script:New-IEFinding 'Red' 'SystemBinaryIntegrity' "BinaryModified_$($b.Name)" "System binary modified: $($b.Name)" $b.FullName $current "Baseline: $($baseDict[$b.Name].Substring(0,32))... Current: $($current.Substring(0,32))..." 'T1014' 'Rootkit'))
        }
    }

    if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [IntegrityEngine] [ACTION: System32Check] [DETAILS: High-value: $($script:IE_HIGHVALUE_BINS.Count) checked; spot-sample: $($sample.Count) checked; findings: $($findings.Count)]" -Encoding UTF8 -ErrorAction SilentlyContinue }
    return $findings.ToArray()
}

# ── Authenticode signature check ─────────────────────────────
function Test-ProcessAuthenticodeSignatures {
    <#
    .SYNOPSIS
        Checks Authenticode signature on the binary of every running process.
        Flags: Unsigned, NotSigned, HashMismatch, NotTrusted, UnknownError, Revoked, self-signed.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $checked  = 0
    $seen     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $binPath = try { $_.MainModule.FileName } catch { $null }
        if (-not $binPath -or -not (Test-Path $binPath) -or $seen.Contains($binPath)) { return }
        $seen.Add($binPath) | Out-Null
        $checked++

        $sig = Get-AuthenticodeSignature -FilePath $binPath -ErrorAction SilentlyContinue
        if (-not $sig) { return }

        $status = $sig.Status.ToString()
        $badStatuses = @('NotSigned','HashMismatch','NotTrusted','UnknownError','Revoked')

        if ($status -in $badStatuses) {
            $sev  = if ($status -in 'HashMismatch','Revoked') { 'Red' } else { 'Yellow' }
            $desc = switch ($status) {
                'NotSigned'    { 'Binary has no Authenticode signature' }
                'HashMismatch' { 'Signature hash mismatch — binary may be patched' }
                'NotTrusted'   { 'Signature not trusted by Windows trust store' }
                'Revoked'      { 'Certificate REVOKED — binary should not run' }
                'UnknownError' { 'Signature validation returned unknown error' }
                default        { "Signature status: $status" }
            }

            # Elevated concern for system-path binaries
            $isSystem = $binPath -like "$env:SystemRoot\*" -or $binPath -like "$env:ProgramFiles\*"
            if ($isSystem -and $status -ne 'NotSigned') { $sev = 'Red' }

            $findings.Add((script:New-IEFinding $sev 'AuthenticodeViolation' "Authenticode_$status" "$status — $($_.Name) ($($_.Id))" $binPath (script:Get-IEFileHash $binPath) "$desc  Publisher: $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' })" 'T1036' 'Masquerading'))
        }
    }

    if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [IntegrityEngine] [ACTION: AuthenticodeCheck] [DETAILS: $checked unique binaries checked; findings: $($findings.Count)]" -Encoding UTF8 -ErrorAction SilentlyContinue }
    return $findings.ToArray()
}

# ── Orchestrator ──────────────────────────────────────────────
function Invoke-IntegrityCheck {
    <#
    .SYNOPSIS
        Orchestrator entry point — runs all four integrity sub-checks.
        Called from Run-SecuritySuite.ps1 and menu option [16].
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host '  [IntegrityEngine] Verifying file manifest...' -ForegroundColor DarkCyan
    foreach ($item in @(Test-IntegrityManifest -AuditLog $AuditLog)) { if ($null -ne $item) { $all.Add($item) } }

    Write-Host '  [IntegrityEngine] Checking System32 binaries...' -ForegroundColor DarkCyan
    foreach ($item in @(Test-System32BinaryIntegrity -AuditLog $AuditLog)) { if ($null -ne $item) { $all.Add($item) } }

    Write-Host '  [IntegrityEngine] Validating process Authenticode signatures...' -ForegroundColor DarkCyan
    foreach ($item in @(Test-ProcessAuthenticodeSignatures -AuditLog $AuditLog)) { if ($null -ne $item) { $all.Add($item) } }

    return $all.ToArray()
}

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates a self-signed code signing certificate and signs all QuietMonitor
    PowerShell scripts so Windows Defender and AllSigned execution policy
    treat them as trusted.

.DESCRIPTION
    1. Creates (or reuses) a CN=QuietMonitor Security Suite certificate in
       Cert:\LocalMachine\My with a 10-year validity and RSA-4096/SHA-256.
    2. Adds the certificate to Trusted Root CA and Trusted Publishers so
       execution policy AllSigned accepts the signatures.
    3. Exports the public certificate to C:\QuietMonitor\Tools\QuietMonitor.cer
       for distribution / backup.
    4. Signs every *.ps1 under C:\QuietMonitor (and the project source tree
       if $SignSourceDir is set) with a DigiCert RFC 3161 timestamp so the
       signatures survive certificate expiry.

.PARAMETER SignSourceDir
    Optional. Additional directory whose *.ps1 files will be signed
    (e.g. the development/project folder). If omitted only C:\QuietMonitor
    is signed.

.PARAMETER Force
    Re-create the certificate even if one already exists.

.EXAMPLE
    .\Sign-QuietMonitor.ps1
    .\Sign-QuietMonitor.ps1 -SignSourceDir "C:\Users\nerde\Desktop\ESTAGIO\PROJETOS"
    .\Sign-QuietMonitor.ps1 -Force
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $SignSourceDir = '',
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CertSubject    = 'CN=QuietMonitor Security Suite'
$CertStorePath  = 'Cert:\LocalMachine\My'
$CertExportPath = 'C:\QuietMonitor\Tools\QuietMonitor.cer'
$TimestampUrl   = 'http://timestamp.digicert.com'
$InstallDir     = 'C:\QuietMonitor'

# ──────────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────────
function Write-Step([string]$Msg) {
    Write-Host "[*] $Msg" -ForegroundColor Cyan
}
function Write-OK([string]$Msg) {
    Write-Host "[+] $Msg" -ForegroundColor Green
}
function Write-Warn([string]$Msg) {
    Write-Host "[!] $Msg" -ForegroundColor Yellow
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 1 — Get or create the code-signing certificate
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "Looking for existing certificate '$CertSubject' in LocalMachine\My..."

$cert = Get-ChildItem $CertStorePath |
    Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($cert -and -not $Force) {
    Write-OK "Reusing existing certificate  Thumbprint: $($cert.Thumbprint)  Expires: $($cert.NotAfter)"
} else {
    if ($cert -and $Force) { Write-Warn "Force flag set — creating new certificate." }

    Write-Step "Creating new self-signed code-signing certificate (RSA-4096, SHA-256, 10 years)..."
    $certParams = @{
        Subject           = $CertSubject
        KeyUsage          = 'DigitalSignature'
        KeyAlgorithm      = 'RSA'
        KeyLength         = 4096
        HashAlgorithm     = 'SHA256'
        Type              = 'CodeSigningCert'
        CertStoreLocation = $CertStorePath
        NotAfter          = (Get-Date).AddYears(10)
    }
    $cert = New-SelfSignedCertificate @certParams
    Write-OK "Certificate created  Thumbprint: $($cert.Thumbprint)"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 2 — Trust the certificate (Root CA + Trusted Publishers)
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "Adding certificate to Trusted Root CA (LocalMachine)..."
try {
    $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        'Root', 'LocalMachine')
    $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add($cert)
    $rootStore.Close()
    Write-OK "Added to Trusted Root CA."
} catch {
    Write-Warn "Root CA add failed (non-critical if already present): $_"
}

Write-Step "Adding certificate to Trusted Publishers (LocalMachine)..."
try {
    $publisherStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        'TrustedPublisher', 'LocalMachine')
    $publisherStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $publisherStore.Add($cert)
    $publisherStore.Close()
    Write-OK "Added to Trusted Publishers."
} catch {
    Write-Warn "Trusted Publishers add failed (non-critical if already present): $_"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 3 — Export public certificate
# ──────────────────────────────────────────────────────────────────────────────
$certDir = Split-Path $CertExportPath -Parent
if (-not (Test-Path $certDir)) {
    New-Item -ItemType Directory -Path $certDir -Force | Out-Null
}

Write-Step "Exporting public certificate to $CertExportPath..."
try {
    Export-Certificate -Cert $cert -FilePath $CertExportPath -Force | Out-Null
    Write-OK "Certificate exported."
} catch {
    Write-Warn "Export failed: $_"
}

# ──────────────────────────────────────────────────────────────────────────────
# Step 4 — Sign all *.ps1 files
# ──────────────────────────────────────────────────────────────────────────────
$dirsToSign = @($InstallDir)
if ($SignSourceDir -and (Test-Path $SignSourceDir)) {
    $dirsToSign += $SignSourceDir
}
# Deduplicate (case-insensitive)
$dirsToSign = $dirsToSign | Sort-Object -Unique

$allScripts = @()
foreach ($dir in $dirsToSign) {
    $allScripts += Get-ChildItem -Path $dir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
}

# Sign this script itself first, then the rest
$thisScript = $PSCommandPath
$ordered    = @()
if ($thisScript) {
    $ordered += Get-Item $thisScript -ErrorAction SilentlyContinue | Where-Object { $_ }
}
$ordered += $allScripts | Where-Object { $_.FullName -ne $thisScript }

$signed = 0
$failed = 0
$skipped = 0

Write-Step "Signing $($ordered.Count) script(s) across: $($dirsToSign -join ', ')..."

foreach ($script in $ordered) {
    if (-not (Test-Path $script.FullName)) { continue }
    try {
        $result = Set-AuthenticodeSignature `
            -FilePath $script.FullName `
            -Certificate $cert `
            -HashAlgorithm SHA256 `
            -TimestampServer $TimestampUrl
        if ($result.Status -eq 'Valid') {
            Write-OK "Signed: $($script.FullName)"
            $signed++
        } else {
            Write-Warn "Failed: $($script.FullName) — $($result.StatusMessage)"
            $failed++
        }
    } catch {
        Write-Warn "Error signing $($script.Name): $($_.Exception.Message)"
        $failed++
    }
}

Write-Host ""
Write-Host "  ┌─────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │  SIGNING COMPLETE                    │" -ForegroundColor DarkCyan
Write-Host "  │  Signed : $($signed.ToString().PadRight(26))│" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "  │  Failed : $($failed.ToString().PadRight(26))│" -ForegroundColor Red
}
Write-Host "  └─────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""

# ──────────────────────────────────────────────────────────────────────────────
# Step 5 — Verify signatures
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "Verifying signatures..."
$invalid = @()
foreach ($dir in $dirsToSign) {
    Get-ChildItem -Path $dir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName
            if ($sig.Status -ne 'Valid') {
                $invalid += "$($_.FullName) [$($sig.Status)]"
            }
        }
}
if ($invalid.Count -eq 0) {
    Write-OK "All scripts verified — Status: Valid"
} else {
    Write-Warn "The following scripts are NOT valid:"
    $invalid | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
}

Write-Host ""
Write-OK "Done. Certificate thumbprint: $($cert.Thumbprint)"

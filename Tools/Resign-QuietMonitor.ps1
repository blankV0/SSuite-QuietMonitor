#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Re-signs all QuietMonitor PowerShell scripts using the existing
    CN=QuietMonitor Security Suite certificate.

.DESCRIPTION
    Run this after every `git pull` or manual edit to ensure all scripts
    carry a valid Authenticode signature that Windows Defender and the
    AllSigned execution policy will accept.

.PARAMETER SourceDir
    Additional source directory to sign (e.g. dev/project folder).
    Defaults to C:\QuietMonitor only.

.EXAMPLE
    .\Resign-QuietMonitor.ps1
    .\Resign-QuietMonitor.ps1 -SourceDir "C:\Users\nerde\Desktop\ESTAGIO\PROJETOS"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $SourceDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CertSubject = 'CN=QuietMonitor Security Suite'
$InstallDir  = 'C:\QuietMonitor'
$TimestampUrl = 'http://timestamp.digicert.com'

# ──────────────────────────────────────────────────────────────────────────────
# Locate certificate
# ──────────────────────────────────────────────────────────────────────────────
$cert = Get-ChildItem 'Cert:\LocalMachine\My' |
    Where-Object { $_.Subject -eq $CertSubject -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "[!] Certificate '$CertSubject' not found in LocalMachine\My." -ForegroundColor Red
    Write-Host "    Run .\Tools\Sign-QuietMonitor.ps1 first to create and trust the certificate." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Using certificate: $($cert.Thumbprint)  (expires $($cert.NotAfter))" -ForegroundColor Cyan

# ──────────────────────────────────────────────────────────────────────────────
# Collect scripts
# ──────────────────────────────────────────────────────────────────────────────
$dirsToSign = @($InstallDir)
if ($SourceDir -and (Test-Path $SourceDir)) { $dirsToSign += $SourceDir }
$dirsToSign = $dirsToSign | Sort-Object -Unique

$allScripts = @()
foreach ($dir in $dirsToSign) {
    $allScripts += Get-ChildItem -Path $dir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
}

Write-Host "[*] Re-signing $($allScripts.Count) script(s)..." -ForegroundColor Cyan

$signed = 0
$failed = 0

foreach ($script in $allScripts) {
    try {
        $result = Set-AuthenticodeSignature `
            -FilePath $script.FullName `
            -Certificate $cert `
            -HashAlgorithm SHA256 `
            -TimestampServer $TimestampUrl
        if ($result.Status -eq 'Valid') {
            $signed++
        } else {
            Write-Host "[!] Failed: $($script.Name) — $($result.StatusMessage)" -ForegroundColor Yellow
            $failed++
        }
    } catch {
        Write-Host "[!] Error: $($script.Name) — $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "[+] Re-signed: $signed" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "[!] Failed:    $failed" -ForegroundColor Red
}

# ──────────────────────────────────────────────────────────────────────────────
# Quick verification pass
# ──────────────────────────────────────────────────────────────────────────────
$invalid = @()
foreach ($dir in $dirsToSign) {
    Get-ChildItem -Path $dir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $sig = Get-AuthenticodeSignature $_.FullName
            if ($sig.Status -ne 'Valid') {
                $invalid += "$($_.Name) [$($sig.Status)]"
            }
        }
}
if ($invalid.Count -eq 0) {
    Write-Host "[+] Verification: ALL scripts Valid." -ForegroundColor Green
} else {
    Write-Host "[!] Unsigned/invalid scripts:" -ForegroundColor Red
    $invalid | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
}

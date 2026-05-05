<#
.SYNOPSIS
    ProcessAudit.ps1 - Audits running processes for unsigned publishers or suspicious paths.
.DESCRIPTION
    Enumerates all running processes and performs two checks:
      1. Authenticode signature validation - unsigned or invalidly signed processes are flagged.
      2. Execution path check - processes running from temp directories, AppData, Downloads,
         or other non-standard locations are flagged as suspicious or threats.

    System processes (PID 0, 4) and processes that cannot be accessed are skipped gracefully.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\ProcessAudit.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-ProcessAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $suspiciousPathPatterns = @(
        [regex]::Escape([System.IO.Path]::GetTempPath().TrimEnd('\').ToLower()),
        '\\appdata\\local\\temp',
        '\\appdata\\roaming\\',
        '\\users\\[^\\]+\\downloads\\',
        '\\users\\[^\\]+\\desktop\\',
        '\\public\\',
        '\\windows\\temp\\'
    )

    # System PIDs to skip
    $systemPids = @(0, 4)

    $flaggedCount    = 0
    $processedCount  = 0

    try {
        $processes = Get-Process -ErrorAction SilentlyContinue

        foreach ($proc in $processes) {
            if ($proc.Id -in $systemPids) { continue }

            $exePath = ''
            try { $exePath = $proc.MainModule.FileName } catch {}

            if (-not $exePath) { continue }   # Cannot access path (access denied or system process)

            $processedCount++
            $pathLower = $exePath.ToLower()

            # --- Signature Check ---
            $sigStatus    = 'Unknown'
            $sigPublisher = ''
            $sha256       = 'N/A'

            try {
                $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                if ($sig) {
                    $sigStatus    = $sig.Status.ToString()
                    $sigPublisher = $sig.SignerCertificate.Subject
                    # Extract CN from subject
                    if ($sigPublisher -match 'CN=([^,]+)') {
                        $sigPublisher = $Matches[1].Trim()
                    }
                }
            } catch {}

            try {
                $sha256 = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash
            } catch { $sha256 = 'HashError' }

            $isTrustedPublisher = $false
            if ($sigPublisher) {
                foreach ($tp in $Whitelist.TrustedPublishers) {
                    if ($sigPublisher -like "*$tp*" -or $tp -like "*$sigPublisher*") {
                        $isTrustedPublisher = $true
                        break
                    }
                }
            }

            $isInTrustedPath = $false
            foreach ($trusted in $Whitelist.TrustedTaskPaths) {
                if ($exePath.StartsWith($trusted, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $isInTrustedPath = $true
                    break
                }
            }

            # --- Path Anomaly Check ---
            $isInSuspiciousPath = $false
            foreach ($pat in $suspiciousPathPatterns) {
                if ($pathLower -match $pat) {
                    $isInSuspiciousPath = $true
                    break
                }
            }

            $severity    = $null
            $detailParts = [System.Collections.Generic.List[string]]::new()

            if ($isInSuspiciousPath) {
                $severity = 'Red'
                $detailParts.Add("Running from suspicious path: $exePath")
                $flaggedCount++
            }

            if ($sigStatus -eq 'NotSigned' -or $sigStatus -eq 'UnknownError') {
                if (-not $isInTrustedPath) {
                    if ($null -eq $severity) { $severity = 'Yellow' }
                    $detailParts.Add("Not digitally signed (Status: $sigStatus)")
                    if ($null -eq $severity -or $severity -eq 'Yellow') { $flaggedCount++ }
                }
            } elseif ($sigStatus -eq 'HashMismatch' -or $sigStatus -eq 'NotTrusted') {
                $severity = 'Red'
                $detailParts.Add("Invalid/tampered signature (Status: $sigStatus). Publisher: $sigPublisher")
                $flaggedCount++
            } elseif ($sigStatus -eq 'Valid' -and -not $isTrustedPublisher -and -not $isInTrustedPath) {
                if ($null -eq $severity) { $severity = 'Yellow' }
                $detailParts.Add("Signed but publisher '$sigPublisher' is not in trusted publisher list.")
            }

            if ($severity) {
                $findings.Add([PSCustomObject]@{
                    Module      = 'ProcessAudit'
                    Severity    = $severity
                    Category    = 'Running Process'
                    Title       = "$($proc.ProcessName) (PID: $($proc.Id))"
                    Path        = $exePath
                    Detail          = $detailParts -join ' | '
                    MitreId     = 'T1057'
                    MitreName   = 'Process Discovery'
                    ActionTaken = ''
                })
            }
        }

        if ($flaggedCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'ProcessAudit'
                Severity    = 'Green'
                Category    = 'Running Process'
                Title       = 'Process Audit'
                Path        = ''
                Detail          = "Audited $processedCount accessible processes. No unsigned executables in suspicious paths."
                MitreId     = 'T1057'
                MitreName   = 'Process Discovery'
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: ProcessAudit] [ACTION: Scan] " +
            "[DETAILS: Processes checked: $processedCount; Flagged: $flaggedCount]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ProcessAudit] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

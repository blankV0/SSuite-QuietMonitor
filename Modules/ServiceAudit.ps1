<#
.SYNOPSIS
    ServiceAudit.ps1 - Audits running Windows services against a trusted whitelist.
.DESCRIPTION
    Enumerates all running services, compares them against the whitelist in whitelist.json,
    and flags unknown or suspicious services. Suspicious patterns include services whose
    executable path resolves to temp directories, user AppData, or known LOLBin wrappers.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\ServiceAudit.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-ServiceAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Patterns that indicate high-risk service executable paths
    $suspiciousPathPatterns = @(
        '\\temp\\',
        '\\tmp\\',
        '\\appdata\\local\\temp\\',
        '\\appdata\\roaming\\',
        '\\downloads\\',
        '\\desktop\\',
        '\\public\\',
        '\\recycle',
        '%temp%',
        '%appdata%'
    )

    # LOLBins that should not normally host services
    $lolbins = @(
        'cmd\.exe', 'powershell\.exe', 'pwsh\.exe',
        'wscript\.exe', 'cscript\.exe', 'mshta\.exe',
        'regsvr32\.exe', 'rundll32\.exe', 'msiexec\.exe',
        'wmic\.exe', 'certutil\.exe', 'bitsadmin\.exe',
        'msbuild\.exe', 'installutil\.exe', 'regasm\.exe',
        'regsvcs\.exe', 'cmstp\.exe', 'xwizard\.exe'
    )

    try {
        $runningServices = Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Running' }

        $wmiServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Running' }

        # Build a hashtable for fast WMI lookup by service name
        $wmiLookup = @{}
        foreach ($w in $wmiServices) {
            $wmiLookup[$w.Name] = $w
        }

        $unknownCount = 0

        foreach ($svc in $runningServices) {
            $isWhitelisted = $Whitelist.Services -contains $svc.ServiceName

            # Retrieve executable path from WMI
            $wmiEntry    = $wmiLookup[$svc.ServiceName]
            $rawPath     = if ($wmiEntry) { $wmiEntry.PathName } else { '' }
            $startMode   = if ($wmiEntry) { $wmiEntry.StartMode } else { 'Unknown' }
            $description = if ($wmiEntry) { $wmiEntry.Description } else { '' }
            $runAs       = if ($wmiEntry) { $wmiEntry.StartName } else { '' }

            # Extract clean exe path (strip arguments, quotes)
            $exePath = ''
            if ($rawPath) {
                if ($rawPath -match '^"([^"]+)"') {
                    $exePath = $Matches[1]
                } else {
                    $exePath = ($rawPath -split ' ')[0]
                }
            }

            # Compute hash only for files that exist
            $sha256 = 'N/A'
            if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                try { $sha256 = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash }
                catch { $sha256 = 'HashError' }
            }

            if (-not $isWhitelisted) {
                $unknownCount++
                $severity = 'Yellow'
                $details  = "Service not in whitelist. StartMode: $startMode. RunAs: $runAs"

                # Elevate to Red on suspicious path
                $pathLower = $rawPath.ToLower()
                foreach ($pat in $suspiciousPathPatterns) {
                    if ($pathLower -match [regex]::Escape($pat)) {
                        $severity = 'Red'
                        $details  = "Service executable in suspicious path: $rawPath"
                        break
                    }
                }

                # Elevate to Red on LOLBin host
                if ($severity -ne 'Red') {
                    foreach ($lol in $lolbins) {
                        if ($pathLower -match $lol) {
                            $severity = 'Red'
                            $details  = "Service hosted by LOLBin ($lol): $rawPath"
                            break
                        }
                    }
                }

                $findings.Add([PSCustomObject]@{
                    Module      = 'ServiceAudit'
                    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Severity    = $severity
                    Category    = 'Service'
                    Name        = $svc.ServiceName
                    DisplayName = $svc.DisplayName
                    Path        = $exePath
                    Hash        = $sha256
                    Details     = $details
                    ActionTaken = ''
                })
            }
        }

        # Add a single Green summary when no unknowns found
        if ($unknownCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'ServiceAudit'
                Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Severity    = 'Green'
                Category    = 'Service'
                Name        = 'AllServicesClean'
                DisplayName = 'Service Audit'
                Path        = ''
                Hash        = ''
                Details     = "All $($runningServices.Count) running services are whitelisted."
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: ServiceAudit] [ACTION: Scan] " +
            "[DETAILS: Scanned $($runningServices.Count) services; $unknownCount flagged]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: ServiceAudit] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

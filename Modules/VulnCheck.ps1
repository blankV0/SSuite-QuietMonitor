<#
.SYNOPSIS
    VulnCheck.ps1 - Vulnerability scanning: EOL software, CVE feed matching, Windows patch age.
.DESCRIPTION
    Invoke-VulnCheck
      1. EOL Detection: Checks installed software against a hardcoded EOL database.
      2. CVE Feed: Optionally loads Config\nvd_cve_feed.json for name/version matching.
      3. Windows Patch Age: Flags hotfixes older than criticalPatchAgeDays (default 30) and
         highlights if the last patch is missing.

    MITRE ATT&CK:
      T1190 - Exploit Public-Facing Application (CVE/EOL finding)
      T1203 - Exploitation for Client Execution (client-side vuln)
.OUTPUTS
    [PSCustomObject[]] - QuietMonitor finding schema
#>

# ============================================================
# EOL Database (hardcoded, offline)
# ============================================================
$script:EolDatabase = @(
    @{ Pattern = 'Windows 7';                     EOL = '2020-01-14'; Severity = 'Red'    }
    @{ Pattern = 'Windows 8.1';                   EOL = '2023-01-10'; Severity = 'Red'    }
    @{ Pattern = 'Windows Server 2008';           EOL = '2020-01-14'; Severity = 'Red'    }
    @{ Pattern = 'Windows Server 2012';           EOL = '2023-10-10'; Severity = 'Red'    }
    @{ Pattern = 'Internet Explorer 11';          EOL = '2022-06-15'; Severity = 'Red'    }
    @{ Pattern = 'Microsoft Internet Explorer';   EOL = '2022-06-15'; Severity = 'Red'    }
    @{ Pattern = 'Python 2';                      EOL = '2020-01-01'; Severity = 'Yellow' }
    @{ Pattern = 'Python 2.7';                    EOL = '2020-01-01'; Severity = 'Yellow' }
    @{ Pattern = 'Java 8';                        EOL = '2022-03-31'; Severity = 'Yellow' }
    @{ Pattern = 'Java(TM) SE Development Kit 8'; EOL = '2022-03-31'; Severity = 'Yellow' }
    @{ Pattern = 'Java(TM) SE Runtime 8';         EOL = '2022-03-31'; Severity = 'Yellow' }
    @{ Pattern = 'PHP 5.';                        EOL = '2019-01-10'; Severity = 'Red'    }
    @{ Pattern = 'PHP 7.0';                       EOL = '2019-12-03'; Severity = 'Yellow' }
    @{ Pattern = 'PHP 7.1';                       EOL = '2019-12-01'; Severity = 'Yellow' }
    @{ Pattern = 'PHP 7.2';                       EOL = '2020-11-30'; Severity = 'Yellow' }
    @{ Pattern = 'Microsoft Office 2016';         EOL = '2025-10-14'; Severity = 'Yellow' }  # mainstream support ended 2020
    @{ Pattern = 'Microsoft Office 2010';         EOL = '2020-10-13'; Severity = 'Red'    }
    @{ Pattern = 'Microsoft Office 2007';         EOL = '2017-10-10'; Severity = 'Red'    }
    @{ Pattern = 'Adobe Flash Player';            EOL = '2020-12-31'; Severity = 'Red'    }
    @{ Pattern = 'Microsoft Silverlight';         EOL = '2021-10-12'; Severity = 'Yellow' }
    @{ Pattern = 'OpenSSL 1.0';                   EOL = '2020-01-01'; Severity = 'Yellow' }
    @{ Pattern = 'OpenSSL 1.1.0';                 EOL = '2019-09-11'; Severity = 'Yellow' }
    @{ Pattern = 'Oracle Database 12c';           EOL = '2022-07-31'; Severity = 'Yellow' }
    @{ Pattern = 'MySQL 5.5';                     EOL = '2018-12-31'; Severity = 'Yellow' }
    @{ Pattern = 'MySQL 5.6';                     EOL = '2021-02-05'; Severity = 'Yellow' }
    @{ Pattern = '.NET Framework 3.5';            EOL = '2029-10-09'; Severity = 'Green'  }  # still supported, informational
    @{ Pattern = 'Node.js 12';                    EOL = '2022-04-30'; Severity = 'Yellow' }
    @{ Pattern = 'Node.js 14';                    EOL = '2023-04-30'; Severity = 'Yellow' }
    @{ Pattern = 'Ruby 2.5';                      EOL = '2021-04-05'; Severity = 'Yellow' }
)

# ============================================================
# Helper: build finding object
# ============================================================
function script:New-VulnFinding {
    param($Sev, $Cat, $Name, $DisplayName, $Path, $Details, $MitreId, $MitreName)
    [PSCustomObject]@{
        Module      = 'VulnCheck'
        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity    = $Sev
        Category    = $Cat
        Name        = $Name
        DisplayName = $DisplayName
        Path        = $Path
        Hash        = ''
        Details     = $Details
        ActionTaken = ''
        MitreId     = $MitreId
        MitreName   = $MitreName
    }
}

# ============================================================
# Invoke-VulnCheck
# ============================================================
function Invoke-VulnCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Whitelist,
        [Parameter(Mandatory)] [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ---- Load Settings ----
    $cfgPath = 'C:\QuietMonitor\Config\settings.json'
    if (-not (Test-Path $cfgPath)) {
        $cfgPath = Join-Path (Split-Path $PSCommandPath -Parent) '..\Config\settings.json'
    }
    $settings      = $null
    $critPatchDays = 30
    $cveFeedPath   = ''
    $warnEOL       = $true
    $patchEnabled  = $true

    if (Test-Path $cfgPath) {
        try {
            $settings    = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($settings.vulnerability.criticalPatchAgeDays) { $critPatchDays = [int]$settings.vulnerability.criticalPatchAgeDays }
            if ($null -ne $settings.vulnerability.patchCheckEnabled) { $patchEnabled = [bool]$settings.vulnerability.patchCheckEnabled }
            if ($null -ne $settings.vulnerability.warnEolSoftware) { $warnEOL = [bool]$settings.vulnerability.warnEolSoftware }
            if ($settings.vulnerability.cveFeedPath) {
                $cveFeedPath = Join-Path 'C:\QuietMonitor' $settings.vulnerability.cveFeedPath
            }
        } catch {}
    }

    Write-Host "  [VulnCheck] Scanning for vulnerabilities..." -ForegroundColor Cyan

    # ---- Collect Installed Software ----
    $software = [System.Collections.Generic.List[PSCustomObject]]::new()
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($rp in $regPaths) {
        try {
            Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    $software.Add([PSCustomObject]@{
                        Name      = $_.DisplayName
                        Version   = $_.DisplayVersion
                        Publisher = $_.Publisher
                        InstallDate = $_.InstallDate
                    })
                }
        } catch {}
    }

    $seen = @{}

    # ---- EOL Check ----
    if ($warnEOL) {
        foreach ($sw in $software) {
            foreach ($eol in $script:EolDatabase | Where-Object { $_.Severity -ne 'Green' }) {
                if ($sw.Name -and $sw.Name -like "*$($eol.Pattern)*") {
                    $key = "eol-$($sw.Name)"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true

                    $eolDate = try { [datetime]::Parse($eol.EOL) } catch { [datetime]::MinValue }
                    $statusMsg = if ($eolDate -lt (Get-Date)) { "PAST EOL ($($eol.EOL))" } else { "EOL APPROACHING ($($eol.EOL))" }
                    $findings.Add((script:New-VulnFinding `
                        -Sev        $eol.Severity `
                        -Cat        'EOL Software' `
                        -Name       "eol-$($sw.Name.Replace(' ','-').ToLower())" `
                        -DisplayName "EOL: $($sw.Name)" `
                        -Path       '' `
                        -Details    "$($sw.Name) v$($sw.Version) - $statusMsg. End-of-life software no longer receives security patches." `
                        -MitreId    'T1190' -MitreName 'Exploit Public-Facing Application'))
                    break
                }
            }
        }
    }

    # ---- CVE Feed Check (optional) ----
    if ($cveFeedPath -and (Test-Path $cveFeedPath)) {
        Write-Host "  [VulnCheck] Loading CVE feed: $cveFeedPath" -ForegroundColor DarkGray
        try {
            $cveFeed = Get-Content $cveFeedPath -Raw -Encoding UTF8 | ConvertFrom-Json

            # Expected format: array of {cve, description, cpe, severity, cvss} or NVD JSON feed format
            $cveItems = if ($cveFeed.CVE_Items) { $cveFeed.CVE_Items } else { $cveFeed }

            foreach ($cveItem in $cveItems | Select-Object -First 5000) {
                # Support NVD CVE JSON 1.1 format and simplified format
                $cveId   = if ($cveItem.cve.CVE_data_meta.ID) { $cveItem.cve.CVE_data_meta.ID } else { $cveItem.cve }
                $desc    = if ($cveItem.cve.description.description_data) { $cveItem.cve.description.description_data[0].value } else { $cveItem.description }
                $cvss    = if ($cveItem.impact.baseMetricV3.cvssV3.baseScore) { [double]$cveItem.impact.baseMetricV3.cvssV3.baseScore } else { if($cveItem.cvss){[double]$cveItem.cvss}else{0} }
                $sev     = if ($cvss -ge 9.0) { 'Red' } elseif ($cvss -ge 7.0) { 'Red' } elseif ($cvss -ge 4.0) { 'Yellow' } else { 'Yellow' }

                if (-not $desc) { continue }

                foreach ($sw in $software) {
                    if (-not $sw.Name) { continue }
                    # Simple name match — checks if CVE description mentions the software name
                    $swShort = ($sw.Name -replace '\s+(version|v|release)\s+.*$', '').Trim().ToLower()
                    if ($swShort.Length -gt 3 -and $desc.ToLower().Contains($swShort)) {
                        $key = "cve-$cveId-$($sw.Name)"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true

                        $findings.Add((script:New-VulnFinding `
                            -Sev        $sev `
                            -Cat        'CVE' `
                            -Name       "cve-$cveId" `
                            -DisplayName "CVE $cveId - $($sw.Name)" `
                            -Path       '' `
                            -Details    "[$cveId CVSS:$cvss] $sw.Name v$($sw.Version). $desc" `
                            -MitreId    'T1190' -MitreName 'Exploit Public-Facing Application'))
                        break
                    }
                }
            }
        } catch {
            $findings.Add((script:New-VulnFinding 'Yellow' 'CVE Feed' 'cve-feed-error' 'CVE Feed: Parse Error' $cveFeedPath "Could not parse CVE feed: $($_.Exception.Message). Verify the file is valid NVD JSON." '' ''))
        }
    } else {
        $findings.Add((script:New-VulnFinding 'Green' 'CVE Feed' 'cve-feed-absent' 'CVE Feed: Not Configured' '' "No CVE feed found at '$cveFeedPath'. Download the NVD JSON feed and place at Config\nvd_cve_feed.json for CVE matching." '' ''))
    }

    # ---- Windows Patch Check ----
    if ($patchEnabled) {
        Write-Host "  [VulnCheck] Checking Windows patch age..." -ForegroundColor DarkGray
        try {
            $patches = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
                Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue)

            if ($patches.Count -eq 0) {
                $findings.Add((script:New-VulnFinding 'Yellow' 'Windows Patches' 'patch-nodata' 'Patch Data: Unavailable' '' "Could not enumerate installed Windows patches (Win32_QuickFixEngineering returned empty). Verify WMI is operational." 'T1190' 'Exploit Public-Facing Application'))
            } else {
                $newest   = $patches | Where-Object { $_.InstalledOn } | Select-Object -First 1
                $now      = Get-Date

                if ($newest -and $newest.InstalledOn) {
                    $age = ($now - [datetime]$newest.InstalledOn).TotalDays
                    if ($age -gt $critPatchDays) {
                        $findings.Add((script:New-VulnFinding `
                            -Sev        'Red' `
                            -Cat        'Windows Patches' `
                            -Name       'patch-overdue' `
                            -DisplayName "Patch Overdue: Last patch $([int]$age) days ago" `
                            -Path       '' `
                            -Details    "Last Windows patch installed $([int]$age) days ago ($($newest.HotFixID) on $($newest.InstalledOn)). Threshold is $critPatchDays days. Apply missing security updates immediately." `
                            -MitreId    'T1190' -MitreName 'Exploit Public-Facing Application'))
                    } else {
                        $findings.Add((script:New-VulnFinding `
                            -Sev        'Green' `
                            -Cat        'Windows Patches' `
                            -Name       'patch-current' `
                            -DisplayName "Patches: Current (last $([int]$age) days ago)" `
                            -Path       '' `
                            -Details    "Last patch: $($newest.HotFixID) installed $([int]$age) days ago. $($patches.Count) total patches installed." `
                            -MitreId    '' -MitreName ''))
                    }
                }

                # Flag any patches over 90 days without a newer patch (already caught above, but also list critical by description)
                $critical = @($patches | Where-Object { $_.Description -match 'Security' -and $_.InstalledOn -and (($now - [datetime]$_.InstalledOn).TotalDays -gt 90) } | Select-Object -First 5)
                foreach ($p in $critical) {
                    $age2 = [int]($now - [datetime]$p.InstalledOn).TotalDays
                    $key  = "patch-old-$($p.HotFixID)"
                    if (-not $seen.ContainsKey($key)) {
                        $seen[$key] = $true
                        $findings.Add((script:New-VulnFinding 'Yellow' 'Windows Patches' $key "Old Security Patch: $($p.HotFixID)" '' "$($p.HotFixID) ($($p.Description)) was installed $age2 days ago. Verify no superseded critical patches are pending." 'T1190' 'Exploit Public-Facing Application'))
                    }
                }
            }
        } catch {
            $findings.Add((script:New-VulnFinding 'Yellow' 'Windows Patches' 'patch-error' 'Patch Check: Error' '' "Failed to enumerate patches: $($_.Exception.Message)" '' ''))
        }
    }

    # ---- Windows OS version check ----
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os.Version -match '^6\.1') {
            $findings.Add((script:New-VulnFinding 'Red' 'EOL OS' 'os-win7-eol' 'EOL: Windows 7 Detected' '' "Windows 7 (version $($os.Version)) reached End of Life on 2020-01-14. Upgrade to Windows 10/11 immediately." 'T1190' 'Exploit Public-Facing Application'))
        } elseif ($os.Version -match '^6\.3') {
            $eolDate = [datetime]'2023-01-10'
            if ((Get-Date) -gt $eolDate) {
                $findings.Add((script:New-VulnFinding 'Red' 'EOL OS' 'os-win81-eol' 'EOL: Windows 8.1 Detected' '' "Windows 8.1 (version $($os.Version)) reached End of Life on 2023-01-10." 'T1190' 'Exploit Public-Facing Application'))
            }
        }
    } catch {}

    # ---- Write audit log ----
    $rCnt = @($findings | Where-Object { $_.Severity -eq 'Red'    }).Count
    $yCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count
    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: VulnCheck] [ACTION: Scan] " +
            "[DETAILS: RED=$rCnt YELLOW=$yCnt SoftwareChecked=$($software.Count)]"
        ) -Encoding UTF8
    }

    if ($findings.Count -eq 0 -or ($rCnt -eq 0 -and $yCnt -eq 0)) {
        $findings.Add((script:New-VulnFinding 'Green' 'VulnCheck' 'vuln-no-findings' 'VulnCheck: No Critical Vulnerabilities' '' "No EOL software, critical CVEs, or overdue Windows patches detected. $($software.Count) software packages checked." '' ''))
    }

    Write-Host ("  [VulnCheck] Complete — RED: $rCnt  YELLOW: $yCnt") -ForegroundColor Cyan
    return $findings
}

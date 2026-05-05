<#
.SYNOPSIS
    SoftwareInventory.ps1 - Exports installed software to a timestamped CSV file.
.DESCRIPTION
    Queries both 32-bit and 64-bit Uninstall registry hives to build a complete
    software inventory including name, version, publisher, and install date.
    The CSV is saved to C:\QuietMonitor\Reports\SoftwareInventory_<timestamp>.csv.
    Returns a single summary finding for inclusion in the HTML report.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\SoftwareInventory.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - Single summary finding object.
#>

function Invoke-SoftwareInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    try {
        $software = foreach ($path in $registryPaths) {
            if (Test-Path ($path -replace '\\\*$', '')) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName.Trim() -ne '' }
            }
        }

        # Deduplicate by DisplayName + DisplayVersion
        $seen    = [System.Collections.Generic.HashSet[string]]::new()
        $records = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($app in $software) {
            $key = "$($app.DisplayName)|$($app.DisplayVersion)"
            if ($seen.Add($key)) {
                $installDate = ''
                if ($app.InstallDate) {
                    # InstallDate is typically YYYYMMDD
                    if ($app.InstallDate -match '^\d{8}$') {
                        try {
                            $installDate = [datetime]::ParseExact($app.InstallDate, 'yyyyMMdd', $null).ToString('yyyy-MM-dd')
                        } catch { $installDate = $app.InstallDate }
                    } else {
                        $installDate = $app.InstallDate
                    }
                }

                $records.Add([PSCustomObject]@{
                    Name        = $app.DisplayName
                    Version     = $app.DisplayVersion
                    Publisher   = $app.Publisher
                    InstallDate = $installDate
                    InstallLocation = $app.InstallLocation
                    UninstallString = $app.UninstallString
                })
            }
        }

        # Sort by publisher, then name
        $sorted = $records | Sort-Object Publisher, Name

        # Save CSV to QuietMonitor Reports folder
        $reportDir   = 'C:\QuietMonitor\Reports'
        if (-not (Test-Path $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        }

        $csvFile = Join-Path $reportDir ("SoftwareInventory_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".csv")
        $sorted | Select-Object Name, Version, Publisher, InstallDate, InstallLocation |
            Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8

        $findings.Add([PSCustomObject]@{
            Module      = 'SoftwareInventory'
            Severity    = 'Green'
            Category    = 'Software Inventory'
            Title       = 'Software Inventory'
            Path        = $csvFile
            Detail          = "Exported $($sorted.Count) unique installed applications to: $csvFile"
            MitreId     = 'T1518'
            MitreName   = 'Software Discovery'
            ActionTaken = ''
        })

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: SoftwareInventory] [ACTION: Export] " +
            "[DETAILS: $($sorted.Count) apps exported to $csvFile]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: SoftwareInventory] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

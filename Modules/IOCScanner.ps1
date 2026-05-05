<#
.SYNOPSIS
    IOCScanner.ps1 - Scans running process hashes against known-bad IOC lists.
.DESCRIPTION
    Compares SHA256 hashes of every running process executable against a local IOC
    CSV file in MalwareBazaar format (or a simple two-column sha256,label CSV).

    IOC CSV formats supported:
      MalwareBazaar export:  columns include "sha256_hash", optionally "file_name",
                             "tags", "signature"
      Simple format:         "sha256,label" (header row required)

    IOC database path: Config\ioc_hashes.csv  (created empty if not found)

    Update your IOC list from MalwareBazaar:
      https://bazaar.abuse.ch/export/csv/full/  (download full export)
    Or simple CSV example:
      sha256,label
      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,test-empty

    MITRE ATT&CK: T1204 (User Execution), T1059 (Command and Scripting Interpreter)

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-IOCScanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # Path to IOC CSV file; defaults to Config\ioc_hashes.csv next to the module
        [string]$IOCFilePath = ''
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $moduleRoot  = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $moduleRoot) { $moduleRoot = Join-Path 'C:\QuietMonitor' 'Modules' }
    $configPath  = Join-Path (Split-Path -Parent $moduleRoot) 'Config'

    if (-not $IOCFilePath) {
        $IOCFilePath = Join-Path $configPath 'ioc_hashes.csv'
    }

    # --- Build IOC lookup table from CSV ----------------------------------------
    $iocTable = @{}   # sha256_upper -> label

    if (-not (Test-Path $IOCFilePath)) {
        # Create empty IOC file with header so users know what format to use
        Set-Content -Path $IOCFilePath -Value 'sha256_hash,file_name,tags,signature' -Encoding UTF8
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: IOCScanner] [ACTION: Scan] " +
            "[DETAILS: IOC file not found; created empty template at $IOCFilePath]"
        ) -Encoding UTF8

        # Return a single Green informational finding
        $findings.Add([PSCustomObject]@{
            Module      = 'IOCScanner'
            Severity    = 'Green'
            Category    = 'IOC'
            Title       = 'IOC Database Empty'
            Path        = $IOCFilePath
            Detail          = "No IOC hashes loaded. Populate $IOCFilePath with MalwareBazaar CSV export."
            ActionTaken = ''
            MitreId     = ''
            MitreName   = ''
        })
        return $findings
    }

    try {
        $csvRows = Import-Csv -Path $IOCFilePath -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Warning "IOCScanner: Failed to parse IOC CSV: $($_.Exception.Message)"
        return $findings
    }

    # Detect column name (MalwareBazaar uses 'sha256_hash'; simple format uses 'sha256')
    $hashCol  = if ($csvRows[0].PSObject.Properties['sha256_hash'])   { 'sha256_hash' }
                elseif ($csvRows[0].PSObject.Properties['sha256'])    { 'sha256' }
                else { $null }

    $labelCol = if ($csvRows[0].PSObject.Properties['signature'])     { 'signature' }
                elseif ($csvRows[0].PSObject.Properties['tags'])      { 'tags' }
                elseif ($csvRows[0].PSObject.Properties['label'])     { 'label' }
                else { $null }

    $nameCol  = if ($csvRows[0].PSObject.Properties['file_name'])     { 'file_name' } else { $null }

    if (-not $hashCol) {
        Write-Warning "IOCScanner: CSV missing expected 'sha256_hash' or 'sha256' column."
        return $findings
    }

    foreach ($row in $csvRows) {
        $h = ($row.$hashCol -replace '\s','').ToUpperInvariant()
        if ($h.Length -eq 64) {
            $label = if ($labelCol) { $row.$labelCol } else { 'unknown-malware' }
            $name  = if ($nameCol)  { $row.$nameCol  } else { '' }
            $iocTable[$h] = @{ Label = $label; Name = $name }
        }
    }

    $iocCount = $iocTable.Count
    if ($iocCount -eq 0) {
        $findings.Add([PSCustomObject]@{
            Module      = 'IOCScanner'
            Severity    = 'Green'
            Category    = 'IOC'
            Title       = 'IOC Database Empty'
            Path        = $IOCFilePath
            Detail          = "IOC CSV loaded but contains 0 valid SHA256 hashes. Add hashes to $IOCFilePath."
            ActionTaken = ''
            MitreId     = ''
            MitreName   = ''
        })
        return $findings
    }

    # --- Enumerate running processes and hash their executables -----------------
    $processes = Get-Process -ErrorAction SilentlyContinue
    $scanned   = 0
    $hits      = 0

    # Cache hashes per path to avoid rehashing the same executable multiple times
    $hashCache = @{}

    foreach ($proc in $processes) {
        $exePath = $null
        try {
            $exePath = $proc.MainModule.FileName
        } catch {
            # Access denied (e.g., protected system process) - skip
            continue
        }

        if (-not $exePath -or -not (Test-Path $exePath -PathType Leaf -ErrorAction SilentlyContinue)) {
            continue
        }

        $exeUpper = $exePath.ToUpperInvariant()
        if ($hashCache.ContainsKey($exeUpper)) {
            $sha256 = $hashCache[$exeUpper]
        } else {
            try {
                $sha256 = (Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction Stop).Hash
                $hashCache[$exeUpper] = $sha256
            } catch {
                continue
            }
        }

        $scanned++

        if ($iocTable.ContainsKey($sha256)) {
            $hits++
            $iocEntry = $iocTable[$sha256]
            $label    = $iocEntry.Label
            $iocName  = $iocEntry.Name

            $displayLabel = if ($iocName) { "$iocName ($label)" } else { $label }

            $findings.Add([PSCustomObject]@{
                Module      = 'IOCScanner'
                Severity    = 'Red'
                Category    = 'IOC Match'
                Title       = "$($proc.Name) [PID $($proc.Id)] - IOC MATCH"
                Path        = $exePath
                Detail          = "Process '$($proc.Name)' (PID $($proc.Id)) matches IOC database entry: $displayLabel | Path: $exePath"
                ActionTaken = ''
                MitreId     = 'T1204'
                MitreName   = 'User Execution'
            })

            Add-Content -Path $AuditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
                "[MODULE: IOCScanner] [ACTION: IOCMatch] " +
                "[DETAILS: PID=$($proc.Id) Name='$($proc.Name)' SHA256=$sha256 Label='$label' Path='$exePath']"
            ) -Encoding UTF8
        }
    }

    # Summary finding (always append even on clean scan)
    $findings.Add([PSCustomObject]@{
        Module      = 'IOCScanner'
        Severity    = if ($hits -gt 0) { 'Red' } else { 'Green' }
        Category    = 'IOC'
        Title       = "IOC Scan - $hits match(es)"
        Path        = $IOCFilePath
        Detail          = "Scanned $scanned process executables against $iocCount IOC hashes. Matches: $hits."
        ActionTaken = ''
        MitreId     = ''
        MitreName   = ''
    })

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
        "[MODULE: IOCScanner] [ACTION: Scan] " +
        "[DETAILS: Scanned=$scanned IOCDatabase=$iocCount Matches=$hits]"
    ) -Encoding UTF8

    return $findings
}

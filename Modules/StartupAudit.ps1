<#
.SYNOPSIS
    StartupAudit.ps1 - Audits registry Run keys and startup folders for persistence entries.
.DESCRIPTION
    Checks all standard autorun locations (HKLM/HKCU Run & RunOnce, startup folders)
    and compares entries against the whitelist. Non-whitelisted entries are flagged.
    Entries pointing to suspicious paths or using LOLBin wrappers are escalated to Red.

    Registry keys checked:
      HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
      HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run

    Startup folders:
      %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
      %ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\StartupAudit.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-StartupAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $suspiciousPathPatterns = @(
        '\\temp\\', '\\tmp\\', '\\appdata\\roaming\\', '\\appdata\\local\\temp\\',
        '\\downloads\\', '\\desktop\\', '\\public\\', '\\recycle', '%temp%', '%appdata%'
    )

    $lolbins = @(
        'cmd\.exe', 'powershell\.exe', 'pwsh\.exe', 'wscript\.exe', 'cscript\.exe',
        'mshta\.exe', 'regsvr32\.exe', 'rundll32\.exe', 'msiexec\.exe', 'wmic\.exe',
        'certutil\.exe', 'bitsadmin\.exe', 'msbuild\.exe', 'installutil\.exe',
        'bash\.exe', 'scriptrunner\.exe', 'forfiles\.exe'
    )

    $registryKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    $startupFolders = @(
        [System.Environment]::GetFolderPath('Startup'),
        [System.Environment]::GetFolderPath('CommonStartup')
    )

    $unknownCount = 0

    # Helper to evaluate a single startup entry
    function Test-StartupEntry {
        param([string]$EntryName, [string]$EntryValue, [string]$Source)

        $isWhitelisted = $Whitelist.StartupEntries -contains $EntryName

        $expandedValue = ''
        try { $expandedValue = [System.Environment]::ExpandEnvironmentVariables($EntryValue) }
        catch { $expandedValue = $EntryValue }

        # Extract executable path
        $exePath = $expandedValue
        if ($expandedValue -match '^"([^"]+)"') {
            $exePath = $Matches[1]
        } else {
            $exePath = ($expandedValue -split '\s+')[0]
        }

        $sha256 = 'N/A'
        if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
            try { $sha256 = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash }
            catch { $sha256 = 'HashError' }
        }

        if ($isWhitelisted) { return $null }

        $severity = 'Yellow'
        $details  = "Startup entry not in whitelist. Source: $Source. Value: $EntryValue"

        $valueLower = $EntryValue.ToLower()
        foreach ($pat in $suspiciousPathPatterns) {
            if ($valueLower -match [regex]::Escape($pat)) {
                $severity = 'Red'
                $details  = "Startup entry points to suspicious path. Source: $Source. Value: $EntryValue"
                break
            }
        }

        if ($severity -ne 'Red') {
            foreach ($lol in $lolbins) {
                if ($valueLower -match $lol) {
                    $severity = 'Red'
                    $details  = "Startup entry uses LOLBin. Source: $Source. Value: $EntryValue"
                    break
                }
            }
        }

        return [PSCustomObject]@{
            Module      = 'StartupAudit'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = $severity
            Category    = 'Startup Persistence'
            Name        = $EntryName
            DisplayName = "$EntryName ($Source)"
            Path        = $exePath
            Hash        = $sha256
            Details     = $details
            ActionTaken = ''
        }
    }

    try {
        # --- Registry Run Keys ---
        foreach ($regKey in $registryKeys) {
            if (-not (Test-Path $regKey)) { continue }

            try {
                $key = Get-Item -Path $regKey -ErrorAction SilentlyContinue
                foreach ($valueName in $key.GetValueNames()) {
                    if ($valueName -eq '') { continue }
                    $valueData = $key.GetValue($valueName)
                    $finding = Test-StartupEntry -EntryName $valueName -EntryValue $valueData -Source $regKey
                    if ($finding) {
                        $unknownCount++
                        $findings.Add($finding)
                    }
                }
            } catch {
                # Key may not be accessible under current context
            }
        }

        # --- Startup Folders ---
        foreach ($folder in $startupFolders) {
            if (-not $folder -or -not (Test-Path $folder)) { continue }

            $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $finding = Test-StartupEntry -EntryName $item.BaseName -EntryValue $item.FullName -Source $folder
                if ($finding) {
                    $unknownCount++
                    $findings.Add($finding)
                }
            }
        }

        if ($unknownCount -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'StartupAudit'
                Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Severity    = 'Green'
                Category    = 'Startup Persistence'
                Name        = 'AllStartupClean'
                DisplayName = 'Startup Audit'
                Path        = ''
                Hash        = ''
                Details     = 'All startup registry entries and folder items are whitelisted.'
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: StartupAudit] [ACTION: Scan] " +
            "[DETAILS: Unknown/flagged startup entries: $unknownCount]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: StartupAudit] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

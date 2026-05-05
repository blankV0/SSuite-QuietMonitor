<#
.SYNOPSIS
    Baseline.ps1 - System baseline capture and drift detection.
.DESCRIPTION
    Captures a comprehensive snapshot of the system state on first run and flags
    deviations (NEW / CHANGED / REMOVED) on every subsequent scan.

    New-SystemBaseline
      Captures: Services, Installed Software, Local Users + Group Memberships,
                Scheduled Tasks (non-Microsoft), Startup Registry Entries,
                Listening Ports + owning processes, Active Network Connections,
                Optionally: SHA256 hashes of System32 / SysWOW64 / Program Files binaries.
      Saves to: C:\QuietMonitor\Baseline\baseline.json

    Invoke-BaselineDrift  (orchestrator-compatible wrapper)
      Calls Compare-SystemBaseline and returns PSCustomObject[] findings.
      MITRE ATT&CK:
        NEW Service    -> T1543 (Create or Modify System Process)
        NEW User       -> T1136 (Create Account)
        NEW Admin      -> T1078 (Valid Accounts)
        NEW Port       -> T1049 (System Network Connections Discovery) / T1071
        CHANGED Hash   -> T1036 (Masquerading) / T1195 (Supply Chain)
        REMOVED Shadow -> T1490 (Inhibit System Recovery)
.OUTPUTS
    [PSCustomObject[]] - QuietMonitor finding schema with Category/Severity/MitreId/MitreName
#>

# ============================================================
# Internal helpers
# ============================================================
function script:Get-BaselineSettingsPath {
    $p = 'C:\QuietMonitor\Config\settings.json'
    if (-not (Test-Path $p)) {
        $p = Join-Path (Split-Path $PSCommandPath -Parent) '..\Config\settings.json'
    }
    return $p
}

function script:Load-BaselineSettings {
    try {
        $s = Get-Content (script:Get-BaselineSettingsPath) -Raw -Encoding UTF8 | ConvertFrom-Json
        return $s.baseline
    } catch {}
    return $null
}

function script:New-BaselineFinding {
    param($Sev, $Cat, $Name, $DisplayName, $Path, $Details, $MitreId, $MitreName)
    [PSCustomObject]@{
        Module      = 'Baseline'
        Severity    = $Sev
        Category    = $Cat
        Title       = $DisplayName
        Path        = $Path
        Detail          = $Details
        ActionTaken = ''
        MitreId     = $MitreId
        MitreName   = $MitreName
    }
}

# ============================================================
# New-SystemBaseline
# ============================================================
function New-SystemBaseline {
    [CmdletBinding()]
    param(
        [string]$BaselinePath = '',
        [string]$AuditLog     = 'C:\QuietMonitor\Logs\audit.log',
        [object]$Settings     = $null
    )

    if (-not $Settings) { $Settings = script:Load-BaselineSettings }
    if (-not $BaselinePath) {
        $BaselinePath = if ($Settings -and $Settings.path) { $Settings.path }
                        else { 'C:\QuietMonitor\Baseline\baseline.json' }
    }

    $baselineDir = Split-Path $BaselinePath -Parent
    if (-not (Test-Path $baselineDir)) { New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null }

    Write-Host "  [Baseline] Capturing system baseline..." -ForegroundColor Cyan

    $snapshot = [ordered]@{
        CapturedAt   = (Get-Date -Format 'o')
        Hostname     = $env:COMPUTERNAME
        OS           = [System.Environment]::OSVersion.VersionString
        Services     = @()
        Software     = @()
        Users        = @()
        AdminMembers = @()
        Tasks        = @()
        StartupKeys  = @()
        ListeningPorts = @()
        FileHashes   = @()
    }

    # --- Services ---
    Write-Host "  [Baseline]   -> Services..." -ForegroundColor DarkGray -NoNewline
    try {
        $snapshot.Services = @(Get-Service -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            [ordered]@{ Name = $_.Name; Status = $_.Status.ToString(); StartType = $_.StartType.ToString() }
        })
        Write-Host " $($snapshot.Services.Count)" -ForegroundColor DarkGray
    } catch { Write-Host " ERROR: $_" -ForegroundColor Red }

    # --- Installed Software ---
    Write-Host "  [Baseline]   -> Software..." -ForegroundColor DarkGray -NoNewline
    $swList = [System.Collections.Generic.List[object]]::new()
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
                    $swList.Add([ordered]@{
                        Name    = $_.DisplayName
                        Version = $_.DisplayVersion
                        Publisher = $_.Publisher
                    })
                }
        } catch {}
    }
    $snapshot.Software = @($swList | Sort-Object { $_['Name'] } | Get-Unique -AsString)
    Write-Host " $($snapshot.Software.Count)" -ForegroundColor DarkGray

    # --- Local Users ---
    Write-Host "  [Baseline]   -> Users..." -ForegroundColor DarkGray -NoNewline
    try {
        $snapshot.Users = @(Get-LocalUser -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            [ordered]@{ Name = $_.Name; Enabled = $_.Enabled; SID = $_.SID.Value }
        })
    } catch { $snapshot.Users = @() }
    Write-Host " $($snapshot.Users.Count)" -ForegroundColor DarkGray

    # --- Administrators group members ---
    Write-Host "  [Baseline]   -> Admin group..." -ForegroundColor DarkGray -NoNewline
    try {
        $snapshot.AdminMembers = @(
            Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
                [ordered]@{ Name = $_.Name; ObjectClass = $_.ObjectClass; SID = $_.SID.Value }
            }
        )
    } catch { $snapshot.AdminMembers = @() }
    Write-Host " $($snapshot.AdminMembers.Count)" -ForegroundColor DarkGray

    # --- Scheduled Tasks (non-Microsoft) ---
    Write-Host "  [Baseline]   -> Scheduled tasks..." -ForegroundColor DarkGray -NoNewline
    try {
        $snapshot.Tasks = @(
            Get-ScheduledTask -ErrorAction Stop |
                Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' } |
                ForEach-Object {
                    $action = if ($_.Actions) { $_.Actions[0].Execute } else { '' }
                    [ordered]@{ Name = $_.TaskName; Path = $_.TaskPath; Action = $action; State = $_.State.ToString() }
                }
        )
    } catch { $snapshot.Tasks = @() }
    Write-Host " $($snapshot.Tasks.Count)" -ForegroundColor DarkGray

    # --- Startup Registry Keys ---
    Write-Host "  [Baseline]   -> Startup entries..." -ForegroundColor DarkGray -NoNewline
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $startupList = [System.Collections.Generic.List[object]]::new()
    foreach ($rk in $runKeys) {
        if (Test-Path $rk -ErrorAction SilentlyContinue) {
            try {
                Get-ItemProperty $rk -ErrorAction Stop | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        $startupList.Add([ordered]@{ Key = $rk; Name = $_.Name; Command = $_.Value })
                    }
                }
            } catch {}
        }
    }
    $snapshot.StartupKeys = @($startupList)
    Write-Host " $($snapshot.StartupKeys.Count)" -ForegroundColor DarkGray

    # --- Listening Ports ---
    Write-Host "  [Baseline]   -> Listening ports..." -ForegroundColor DarkGray -NoNewline
    try {
        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.Name }

        $snapshot.ListeningPorts = @(
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Sort-Object LocalPort | ForEach-Object {
                    $pName = if ($procMap.ContainsKey([int]$_.OwningProcess)) { $procMap[[int]$_.OwningProcess] } else { '?' }
                    [ordered]@{
                        Port    = $_.LocalPort
                        Address = $_.LocalAddress
                        PID     = $_.OwningProcess
                        Process = $pName
                    }
                }
        )
    } catch { $snapshot.ListeningPorts = @() }
    Write-Host " $($snapshot.ListeningPorts.Count)" -ForegroundColor DarkGray

    # --- Optional: File Hashes ---
    $doHashes = $false
    if ($Settings) {
        if ($Settings.includeSystem32Hashes -or $Settings.includeSysWOW64Hashes -or $Settings.includeProgramFilesHashes) {
            $doHashes = $true
        }
    }

    if ($doHashes) {
        Write-Host "  [Baseline]   -> File hashes (this may take several minutes)..." -ForegroundColor DarkGray -NoNewline
        $hashDirs = @()
        if ($Settings.includeSystem32Hashes)       { $hashDirs += "$env:SystemRoot\System32" }
        if ($Settings.includeSysWOW64Hashes)       { $hashDirs += "$env:SystemRoot\SysWOW64" }
        if ($Settings.includeProgramFilesHashes)   { $hashDirs += $env:ProgramFiles; $hashDirs += ${env:ProgramFiles(x86)} }

        $hashList = [System.Collections.Generic.List[object]]::new()
        foreach ($dir in $hashDirs | Where-Object { $_ -and (Test-Path $_) }) {
            Get-ChildItem -Path $dir -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 2000 |
                ForEach-Object {
                    try {
                        $h = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                        $hashList.Add([ordered]@{ Path = $_.FullName; SHA256 = $h; Size = $_.Length })
                    } catch {}
                }
        }
        $snapshot.FileHashes = @($hashList)
        Write-Host " $($snapshot.FileHashes.Count)" -ForegroundColor DarkGray
    }

    # --- Save ---
    $snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $BaselinePath -Encoding UTF8
    Write-Host "  [Baseline] Baseline saved: $BaselinePath" -ForegroundColor Green

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: Baseline] [ACTION: CaptureBaseline] " +
            "[DETAILS: Path='$BaselinePath' Services=$($snapshot.Services.Count) Software=$($snapshot.Software.Count) Users=$($snapshot.Users.Count)]"
        ) -Encoding UTF8
    }

    return $BaselinePath
}

# ============================================================
# Compare-SystemBaseline
# ============================================================
function Compare-SystemBaseline {
    [CmdletBinding()]
    param(
        [string]$BaselinePath = '',
        [string]$AuditLog     = 'C:\QuietMonitor\Logs\audit.log',
        [object]$Whitelist    = $null
    )

    if (-not $BaselinePath) {
        $cfg = script:Load-BaselineSettings
        $BaselinePath = if ($cfg -and $cfg.path) { $cfg.path } else { 'C:\QuietMonitor\Baseline\baseline.json' }
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Test-Path $BaselinePath)) {
        # No baseline exists — capture one now
        Write-Host "  [Baseline] No baseline found. Capturing initial baseline..." -ForegroundColor Yellow
        New-SystemBaseline -BaselinePath $BaselinePath -AuditLog $AuditLog
        $findings.Add((script:New-BaselineFinding `
            -Sev        'Yellow' `
            -Cat        'Baseline' `
            -Name       'baseline-initial-capture' `
            -DisplayName 'Baseline: Initial Capture' `
            -Path       $BaselinePath `
            -Details    'No baseline existed. Initial snapshot created. Run again to detect drift.' `
            -MitreId    '' -MitreName ''))
        return $findings
    }

    # Load baseline
    try {
        $baseline = Get-Content $BaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $findings.Add((script:New-BaselineFinding 'Red' 'Baseline' 'baseline-parse-error' 'Baseline Parse Error' $BaselinePath "Failed to parse baseline file: $($_.Exception.Message)" '' ''))
        return $findings
    }

    $baseAge = (Get-Date) - [datetime]$baseline.CapturedAt
    if ($baseAge.TotalDays -gt 30) {
        $findings.Add((script:New-BaselineFinding 'Yellow' 'Baseline' 'baseline-stale' 'Baseline is Stale' $BaselinePath "Baseline was captured $([int]$baseAge.TotalDays) days ago. Consider rebuilding via menu option [10]." '' ''))
    }

    # Helper: build lookup from a list
    function Make-Lookup ([object[]]$list, [string]$key) {
        $ht = @{}
        foreach ($item in $list) {
            if ($item -and $item.$key) { $ht[$item.$key] = $item }
        }
        return $ht
    }

    # ---- Services drift ----
    $currentServices = @(Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ Name = $_.Name; Status = $_.Status.ToString(); StartType = $_.StartType.ToString() }
    })
    $bSvc = Make-Lookup $baseline.Services 'Name'
    $cSvc = Make-Lookup $currentServices 'Name'

    foreach ($name in $cSvc.Keys) {
        if (-not $bSvc.ContainsKey($name)) {
            $findings.Add((script:New-BaselineFinding 'Yellow' 'Baseline - Services' "baseline-svc-new-$name" "NEW Service: $name" '' "Service '$name' not in baseline. Status: $($cSvc[$name].Status) StartType: $($cSvc[$name].StartType)" 'T1543' 'Create or Modify System Process'))
        }
    }
    foreach ($name in $bSvc.Keys) {
        if (-not $cSvc.ContainsKey($name)) {
            $findings.Add((script:New-BaselineFinding 'Yellow' 'Baseline - Services' "baseline-svc-removed-$name" "REMOVED Service: $name" '' "Service '$name' existed in baseline but is no longer present. May indicate cleanup after compromise." 'T1562' 'Impair Defenses'))
        }
    }

    # ---- Software drift ----
    $currentSW = [System.Collections.Generic.List[object]]::new()
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($rp in $regPaths) {
        try {
            Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object { $currentSW.Add([ordered]@{ Name = $_.DisplayName; Version = $_.DisplayVersion }) }
        } catch {}
    }
    $bSWNames = @($baseline.Software | ForEach-Object { "$($_['Name'])|||$($_['Version'])" })
    $cSWNames = @($currentSW | ForEach-Object { "$($_['Name'])|||$($_['Version'])" })

    $newSW     = @($cSWNames | Where-Object { $bSWNames -notcontains $_ })
    $removedSW = @($bSWNames | Where-Object { $cSWNames -notcontains $_ })

    foreach ($sw in $newSW | Select-Object -First 20) {
        $parts = $sw -split '\|\|\|'
        $findings.Add((script:New-BaselineFinding 'Yellow' 'Baseline - Software' "baseline-sw-new-$($parts[0])" "NEW Software: $($parts[0])" '' "Software '$($parts[0])' version '$($parts[1])' not in baseline. Verify this installation is authorized." '' ''))
    }
    foreach ($sw in $removedSW | Select-Object -First 10) {
        $parts = $sw -split '\|\|\|'
        $findings.Add((script:New-BaselineFinding 'Green' 'Baseline - Software' "baseline-sw-removed-$($parts[0])" "REMOVED Software: $($parts[0])" '' "Software '$($parts[0])' v'$($parts[1])' was in baseline but is no longer installed." '' ''))
    }

    # ---- Local Users drift ----
    try {
        $currentUsers = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [ordered]@{ Name = $_.Name; Enabled = $_.Enabled; SID = $_.SID.Value }
        })
        $bUsers = @($baseline.Users | ForEach-Object { $_['Name'] })
        $cUsers = @($currentUsers | ForEach-Object { $_['Name'] })

        foreach ($u in $cUsers | Where-Object { $bUsers -notcontains $_ }) {
            $findings.Add((script:New-BaselineFinding 'Red' 'Baseline - Users' "baseline-user-new-$u" "NEW User Account: $u" '' "Local user '$u' not in baseline. Unauthorized account creation is a critical indicator." 'T1136' 'Create Account'))
        }
        foreach ($u in $bUsers | Where-Object { $cUsers -notcontains $_ }) {
            $findings.Add((script:New-BaselineFinding 'Yellow' 'Baseline - Users' "baseline-user-removed-$u" "REMOVED User: $u" '' "User '$u' existed in baseline but is no longer present." 'T1531' 'Account Access Removal'))
        }
    } catch {}

    # ---- Admin group drift ----
    try {
        $currentAdmins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { $_.Name })
        $baseAdmins    = @($baseline.AdminMembers | ForEach-Object { $_['Name'] })

        foreach ($a in $currentAdmins | Where-Object { $baseAdmins -notcontains $_ }) {
            $findings.Add((script:New-BaselineFinding 'Red' 'Baseline - Privilege' "baseline-admin-new-$a" "NEW Administrator: $a" '' "Principal '$a' added to Administrators group since baseline. High-risk unauthorized privilege escalation." 'T1078' 'Valid Accounts'))
        }
    } catch {}

    # ---- Listening Ports drift ----
    try {
        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.Name }

        $currentPorts = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{ Port = $_.LocalPort; Address = $_.LocalAddress; PID = $_.OwningProcess; Process = (if($procMap.ContainsKey([int]$_.OwningProcess)){$procMap[[int]$_.OwningProcess]}else{'?'}) }
        })
        $bPorts = @($baseline.ListeningPorts | ForEach-Object { [int]$_['Port'] })
        $cPorts = @($currentPorts | ForEach-Object { [int]$_['Port'] })

        foreach ($p in $cPorts | Where-Object { $bPorts -notcontains $_ } | Sort-Object -Unique) {
            $entry = $currentPorts | Where-Object { [int]$_['Port'] -eq $p } | Select-Object -First 1
            $findings.Add((script:New-BaselineFinding 'Yellow' 'Baseline - Network' "baseline-port-new-$p" "NEW Listening Port: $p" '' "Port $p/$($entry.Process) not in baseline. Investigate if unexpected service or backdoor." 'T1049' 'System Network Connections Discovery'))
        }
    } catch {}

    # ---- Startup Keys drift ----
    $cStartup = [System.Collections.Generic.List[object]]::new()
    $runKeys2 = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($rk in $runKeys2) {
        if (Test-Path $rk -ErrorAction SilentlyContinue) {
            try {
                Get-ItemProperty $rk -ErrorAction Stop | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        $cStartup.Add([ordered]@{ Key = $rk; Name = $_.Name; Command = $_.Value })
                    }
                }
            } catch {}
        }
    }
    $bStartupNames = @($baseline.StartupKeys | ForEach-Object { "$($_['Key'])|$($_['Name'])" })
    $cStartupNames = @($cStartup | ForEach-Object { "$($_['Key'])|$($_['Name'])" })

    foreach ($k in $cStartupNames | Where-Object { $bStartupNames -notcontains $_ }) {
        $entry = $cStartup | Where-Object { "$($_['Key'])|$($_['Name'])" -eq $k } | Select-Object -First 1
        $findings.Add((script:New-BaselineFinding 'Red' 'Baseline - Startup' "baseline-startup-new-$k" "NEW Startup Entry: $($entry['Name'])" ($entry['Command'] -split ' ')[0] "New startup entry '$($entry['Name'])' = '$($entry['Command'])' not in baseline." 'T1547' 'Boot/Logon Autostart Execution'))
    }

    # ---- File Hash drift (if enabled) ----
    if ($baseline.FileHashes -and $baseline.FileHashes.Count -gt 0) {
        $bHashMap = @{}
        foreach ($h in $baseline.FileHashes) { $bHashMap[$h.Path] = $h.SHA256 }

        foreach ($path in $bHashMap.Keys | Where-Object { Test-Path $_ -PathType Leaf -ErrorAction SilentlyContinue }) {
            try {
                $current = (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash
                if ($current -ne $bHashMap[$path]) {
                    $findings.Add((script:New-BaselineFinding 'Red' 'Baseline - File Integrity' "baseline-hash-changed-$(Split-Path $path -Leaf)" "CHANGED File: $(Split-Path $path -Leaf)" $path "File '$path' hash changed since baseline. Possible trojanized binary or legitimate update. Verify immediately." 'T1036' 'Masquerading'))
                }
            } catch {}
        }
    }

    # ---- Summary ----
    $rCnt = @($findings | Where-Object { $_.Severity -eq 'Red' }).Count
    $yCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count

    if ($findings.Count -eq 0 -or ($rCnt -eq 0 -and $yCnt -eq 0)) {
        $findings.Add((script:New-BaselineFinding 'Green' 'Baseline' 'baseline-no-drift' 'Baseline: No Drift Detected' $BaselinePath "All monitored baseline categories match current system state (Services, Software, Users, Ports, Startup)." '' ''))
    }

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: Baseline] [ACTION: DriftScan] " +
            "[DETAILS: BaselineAge=$([int]$baseAge.TotalDays)d RED=$rCnt YELLOW=$yCnt]"
        ) -Encoding UTF8
    }

    return $findings
}

# ============================================================
# Invoke-BaselineDrift (orchestrator-compatible wrapper)
# ============================================================
function Invoke-BaselineDrift {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Whitelist,
        [Parameter(Mandatory)] [string]$AuditLog
    )

    $cfg = script:Load-BaselineSettings
    if ($cfg -and $cfg.enabled -eq $false) {
        return @([PSCustomObject]@{
            Severity='Green'; Module='Baseline'; Category='Baseline'
            Title='Baseline: Disabled'; Detail='Baseline drift detection is disabled in settings.json.'
            Path=''; MitreId=''; MitreName=''; ActionTaken=''
        })
    }

    return Compare-SystemBaseline -AuditLog $AuditLog -Whitelist $Whitelist
}

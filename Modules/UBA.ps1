<#
.SYNOPSIS
    UBA.ps1 - User Behavior Analytics from Windows Security event log.
.DESCRIPTION
    Invoke-UBAAnalysis
      Analyzes Windows Security event log for behavioral anomalies:
        Event 4624 (Logon)         - Off-hours interactive/remote logon detection
        Event 4625 (Failed Logon)  - Brute force / password spray detection
        Event 4648 (Explicit Cred) - Credential switching (runas / lateral movement)
        Event 4672 (Special Priv)  - Privileged logon (unexpected admins)
        Event 4720 (Account Create)- New local user account
        Event 4732 (Group Add)     - Member added to security group
        Event 4740 (Account Lockout)- Account lockout (brute force indicator)

    All thresholds come from settings.json (settings.uba.*).
    Fully offline — reads only local Windows event log.

    MITRE ATT&CK:
      T1078  - Valid Accounts (off-hours logon, unexpected admin)
      T1110  - Brute Force (failed login burst)
      T1098  - Account Manipulation (group membership change)
      T1136  - Create Account (new user)
.OUTPUTS
    [PSCustomObject[]] - QuietMonitor finding schema
#>

# ============================================================
# Helpers
# ============================================================
function script:New-UBAFinding {
    param($Sev, $Cat, $Name, $DisplayName, $Path, $Details, $MitreId, $MitreName)
    [PSCustomObject]@{
        Module      = 'UBA'
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

function script:Get-EventFieldValue {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event, [int]$Index)
    try {
        $props = $Event.Properties
        if ($props -and $Index -lt $props.Count) { return $props[$Index].Value }
    } catch {}
    return ''
}

function script:Parse-TimeOnly ([string]$timeStr) {
    # Returns TimeSpan from "HH:mm" string; defaults to 08:00 / 18:00 on error
    try { return [TimeSpan]::Parse($timeStr) } catch { return $null }
}

# ============================================================
# Invoke-UBAAnalysis
# ============================================================
function Invoke-UBAAnalysis {
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

    $normalStart      = [TimeSpan]::FromHours(8)
    $normalEnd        = [TimeSpan]::FromHours(18)
    $lookbackHours    = 24
    $failThreshold    = 5
    $failWindowMin    = 5
    $ubaEnabled       = $true
    $ubaBaselinePath  = 'C:\QuietMonitor\Config\uba_baseline.json'

    if (Test-Path $cfgPath) {
        try {
            $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($cfg.uba) {
                if ($null -ne $cfg.uba.enabled) { $ubaEnabled = [bool]$cfg.uba.enabled }
                $ts = script:Parse-TimeOnly $cfg.uba.normalHoursStart
                if ($ts) { $normalStart = $ts }
                $te = script:Parse-TimeOnly $cfg.uba.normalHoursEnd
                if ($te) { $normalEnd = $te }
                if ($cfg.uba.lookbackHours)          { $lookbackHours = [int]$cfg.uba.lookbackHours }
                if ($cfg.uba.failedLoginThreshold)   { $failThreshold = [int]$cfg.uba.failedLoginThreshold }
                if ($cfg.uba.failedLoginWindowMinutes){ $failWindowMin  = [int]$cfg.uba.failedLoginWindowMinutes }
                if ($cfg.uba.baselinePath)           { $ubaBaselinePath = $cfg.uba.baselinePath }
            }
        } catch {}
    }

    if (-not $ubaEnabled) {
        return @((script:New-UBAFinding 'Green' 'UBA' 'uba-disabled' 'UBA: Disabled' '' 'User Behavior Analytics is disabled in settings.json.' '' ''))
    }

    Write-Host "  [UBA] Analyzing Security event log (lookback: $lookbackHours h)..." -ForegroundColor Cyan

    $cutoff   = (Get-Date).AddHours(-$lookbackHours)
    $seenKeys = @{}

    # ---- Load UBA Baseline (expected admins) ----
    $knownAdmins = @('Administrator', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'DWM-1', 'DWM-2', 'DWM-3')
    if (Test-Path $ubaBaselinePath -ErrorAction SilentlyContinue) {
        try {
            $ub = Get-Content $ubaBaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($ub.knownAdmins) { $knownAdmins += $ub.knownAdmins }
        } catch {}
    }
    # Also add current local Administrators members as known
    try {
        $knownAdmins += @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] })
    } catch {}
    $knownAdmins = $knownAdmins | Select-Object -Unique

    # ---- Query Security Log ----
    $events = @()
    try {
        # Get all relevant events in one pass (more efficient than multiple queries)
        $filter = @{
            LogName   = 'Security'
            Id        = @(4624, 4625, 4648, 4672, 4720, 4732, 4740)
            StartTime = $cutoff
        }
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Sort-Object TimeCreated)
        Write-Host "  [UBA]   Events collected: $($events.Count)" -ForegroundColor DarkGray
    } catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Host "  [UBA]   No relevant events in lookback window." -ForegroundColor DarkGray
        } else {
            $findings.Add((script:New-UBAFinding 'Yellow' 'UBA' 'uba-error' 'UBA: Event Log Access Error' '' "Could not read Security event log: $($_.Exception.Message). Ensure this script runs as Administrator." '' ''))
            return $findings
        }
    }

    # ---- Pre-group failed logins for brute force detection ----
    $failedLogins = @{}  # key: "user|workstation" -> list of DateTimes
    foreach ($ev in $events | Where-Object { $_.Id -eq 4625 }) {
        $user = script:Get-EventFieldValue $ev 5    # TargetUserName
        $ws   = script:Get-EventFieldValue $ev 13   # WorkstationName
        if (-not $user -or $user -match '^\$|^-$') { continue }
        $key = "$user|$ws"
        if (-not $failedLogins.ContainsKey($key)) { $failedLogins[$key] = [System.Collections.Generic.List[datetime]]::new() }
        $failedLogins[$key].Add($ev.TimeCreated)
    }

    # Sliding window brute force check
    foreach ($key in $failedLogins.Keys) {
        $times  = @($failedLogins[$key] | Sort-Object)
        $parts  = $key -split '\|'
        $user   = $parts[0]; $ws = if ($parts.Count -gt 1) { $parts[1] } else { '' }

        for ($i = 0; $i -lt $times.Count; $i++) {
            $window = @($times | Where-Object { ($_ - $times[$i]).TotalMinutes -le $failWindowMin -and $_ -ge $times[$i] })
            if ($window.Count -ge $failThreshold) {
                $fkey = "uba-bruteforce-$user"
                if (-not $seenKeys.ContainsKey($fkey)) {
                    $seenKeys[$fkey] = $true
                    $findings.Add((script:New-UBAFinding `
                        -Sev 'Red' -Cat 'UBA - Brute Force' `
                        -Name $fkey -DisplayName "Brute Force: $user" `
                        -Path '' `
                        -Details "$($window.Count) failed logon attempts for '$user' from '$ws' within $failWindowMin minutes (first: $($times[$i].ToString('HH:mm:ss'))). Password spray or brute force attack." `
                        -MitreId 'T1110' -MitreName 'Brute Force'))
                }
                break
            }
        }
    }

    # ---- Event-by-event analysis ----
    foreach ($ev in $events) {
        switch ($ev.Id) {

            # 4624 - Successful Logon
            4624 {
                $logonType = [int](script:Get-EventFieldValue $ev 8)
                $user      = [string](script:Get-EventFieldValue $ev 5)
                $domain    = [string](script:Get-EventFieldValue $ev 6)
                $ip        = [string](script:Get-EventFieldValue $ev 18)
                if (-not $user -or $user -match '^\$|^-$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$') { break }

                $tod  = $ev.TimeCreated.TimeOfDay
                $offH = ($tod -lt $normalStart) -or ($tod -gt $normalEnd)
                $isWknd = $ev.TimeCreated.DayOfWeek -in @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday)

                # Type 10 = RemoteInteractive (RDP)
                if ($logonType -eq 10) {
                    $key2 = "uba-rdp-$user-$($ev.TimeCreated.ToString('yyyyMMdd'))"
                    if (-not $seenKeys.ContainsKey($key2)) {
                        $seenKeys[$key2] = $true
                        $sev = if ($offH -or $isWknd) { 'Red' } else { 'Yellow' }
                        $findings.Add((script:New-UBAFinding `
                            -Sev $sev -Cat 'UBA - Remote Logon' `
                            -Name $key2 -DisplayName "RDP Logon: $user" `
                            -Path '' `
                            -Details "Remote interactive (RDP) logon for '$user' at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))$(if($offH){' (OUTSIDE NORMAL HOURS)'}). Source IP: $ip" `
                            -MitreId 'T1078' -MitreName 'Valid Accounts'))
                    }
                } elseif ($offH -or $isWknd) {
                    # Type 2 = Interactive console
                    if ($logonType -eq 2) {
                        $key2 = "uba-offhours-$user-$($ev.TimeCreated.ToString('yyyyMMddHH'))"
                        if (-not $seenKeys.ContainsKey($key2)) {
                            $seenKeys[$key2] = $true
                            $findings.Add((script:New-UBAFinding `
                                -Sev 'Yellow' -Cat 'UBA - Off-Hours Logon' `
                                -Name $key2 -DisplayName "Off-Hours Logon: $user" `
                                -Path '' `
                                -Details "Interactive logon for '$user' at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) - outside normal hours ($($normalStart.Hours):00-$($normalEnd.Hours):00)$(if($isWknd){' on weekend'})." `
                                -MitreId 'T1078' -MitreName 'Valid Accounts'))
                        }
                    }
                }
            }

            # 4648 - Explicit Credential Use (runas / lateral movement)
            4648 {
                $subjectUser = [string](script:Get-EventFieldValue $ev 1)
                $targetUser  = [string](script:Get-EventFieldValue $ev 5)
                $targetServer= [string](script:Get-EventFieldValue $ev 8)
                if (-not $subjectUser -or $subjectUser -eq $targetUser) { break }
                if ($subjectUser -match '^\$|^-$|^SYSTEM$') { break }

                $key2 = "uba-4648-$subjectUser-$targetUser"
                if (-not $seenKeys.ContainsKey($key2)) {
                    $seenKeys[$key2] = $true
                    $findings.Add((script:New-UBAFinding `
                        -Sev 'Yellow' -Cat 'UBA - Credential Switch' `
                        -Name $key2 -DisplayName "Explicit Credential Use: $subjectUser -> $targetUser" `
                        -Path '' `
                        -Details "User '$subjectUser' used explicit credentials for '$targetUser' at $($ev.TimeCreated.ToString('HH:mm:ss')). Target server: $targetServer. May indicate lateral movement or privilege escalation." `
                        -MitreId 'T1078' -MitreName 'Valid Accounts'))
                }
            }

            # 4672 - Special Privileges on Logon
            4672 {
                $user = [string](script:Get-EventFieldValue $ev 1)
                if (-not $user -or $user -match '^\$|^-$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$|^DWM-') { break }
                # Only flag if not in known admins
                $shortUser = ($user -split '\\')[-1]
                if ($knownAdmins -contains $shortUser -or $knownAdmins -contains $user) { break }

                $key2 = "uba-4672-$user"
                if (-not $seenKeys.ContainsKey($key2)) {
                    $seenKeys[$key2] = $true
                    $findings.Add((script:New-UBAFinding `
                        -Sev 'Red' -Cat 'UBA - Privilege Escalation' `
                        -Name $key2 -DisplayName "Special Privileges: $user" `
                        -Path '' `
                        -Details "User '$user' logged on with special/elevated privileges at $($ev.TimeCreated.ToString('HH:mm:ss')). This user is not in the known administrators list. Possible unauthorized privilege escalation." `
                        -MitreId 'T1078' -MitreName 'Valid Accounts'))
                }
            }

            # 4720 - User Account Created
            4720 {
                $newUser    = [string](script:Get-EventFieldValue $ev 0)
                $createdBy  = [string](script:Get-EventFieldValue $ev 4)
                $findings.Add((script:New-UBAFinding `
                    -Sev 'Red' -Cat 'UBA - Account Created' `
                    -Name "uba-4720-$newUser-$($ev.TimeCreated.ToString('yyyyMMddHHmmss'))" `
                    -DisplayName "New User Account: $newUser" `
                    -Path '' `
                    -Details "New local user account '$newUser' created by '$createdBy' at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')). Verify this account is authorized." `
                    -MitreId 'T1136' -MitreName 'Create Account'))
            }

            # 4732 - Member Added to Security-Enabled Local Group
            4732 {
                $member    = [string](script:Get-EventFieldValue $ev 0)
                $group     = [string](script:Get-EventFieldValue $ev 2)
                $addedBy   = [string](script:Get-EventFieldValue $ev 6)
                if (-not $group) { break }

                $sev  = if ($group -match 'Admin') { 'Red' } else { 'Yellow' }
                $findings.Add((script:New-UBAFinding `
                    -Sev $sev -Cat 'UBA - Group Membership Change' `
                    -Name "uba-4732-$member-$group-$($ev.TimeCreated.ToString('yyyyMMddHHmmss'))" `
                    -DisplayName "Group Add: $member -> $group" `
                    -Path '' `
                    -Details "Principal '$member' added to group '$group' by '$addedBy' at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))." `
                    -MitreId 'T1098' -MitreName 'Account Manipulation'))
            }

            # 4740 - Account Locked Out
            4740 {
                $lockedUser = [string](script:Get-EventFieldValue $ev 0)
                $callerWS   = [string](script:Get-EventFieldValue $ev 1)
                $key2       = "uba-4740-$lockedUser"
                if (-not $seenKeys.ContainsKey($key2)) {
                    $seenKeys[$key2] = $true
                    $findings.Add((script:New-UBAFinding `
                        -Sev 'Yellow' -Cat 'UBA - Account Lockout' `
                        -Name $key2 -DisplayName "Account Locked Out: $lockedUser" `
                        -Path '' `
                        -Details "Account '$lockedUser' locked out at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')). Caller workstation: $callerWS. May indicate brute-force or misconfigured service account." `
                        -MitreId 'T1110' -MitreName 'Brute Force'))
                }
            }
        }
    }

    # ---- Summary ----
    $rCnt = @($findings | Where-Object { $_.Severity -eq 'Red'    }).Count
    $yCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count

    if ($rCnt -eq 0 -and $yCnt -eq 0) {
        $findings.Add((script:New-UBAFinding 'Green' 'UBA' 'uba-clean' 'UBA: No Behavioral Anomalies' '' "Analyzed $($events.Count) security events over the last $lookbackHours hours. No suspicious logon patterns, brute force, privilege escalation, or account changes detected." '' ''))
    }

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: UBA] [ACTION: Analyze] " +
            "[DETAILS: Events=$($events.Count) LookbackH=$lookbackHours RED=$rCnt YELLOW=$yCnt]"
        ) -Encoding UTF8
    }

    Write-Host ("  [UBA] Complete — Events: $($events.Count)  RED: $rCnt  YELLOW: $yCnt") -ForegroundColor Cyan
    return $findings
}

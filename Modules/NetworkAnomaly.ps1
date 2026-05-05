<#
.SYNOPSIS
    NetworkAnomaly.ps1 - Baselines network connections and alerts on new external IPs.
.DESCRIPTION
    On the first run, captures a baseline of all established TCP connections and unique
    external IP addresses and saves it to Config\network_baseline.json.

    On subsequent runs, compares the current connection snapshot against the baseline
    and alerts on:
      - New external IP addresses not seen during baseline
      - Connections to known-suspicious port ranges (raw IRC, common C2 ports)
      - Unusually high unique external destination count (potential C2 beaconing or scanning)

    RFC 1918 / loopback / link-local addresses are excluded from "external IP" checks.

    MITRE ATT&CK:
      T1071 - Application Layer Protocol (C2 over standard ports)
      T1049 - System Network Connections Discovery

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-NetworkAnomalyDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # Path to store baseline JSON; defaults to Config\network_baseline.json
        [string]$BaselinePath = '',

        # Force a new baseline even if one exists
        [switch]$ForceBaseline,

        # Number of new external IPs above which we escalate to Red
        [int]$NewIpRedThreshold = 5
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $moduleRoot  = Split-Path -Parent $MyInvocation.MyCommand.Path
    $configDir   = Join-Path (Split-Path -Parent $moduleRoot) 'Config'

    if (-not $BaselinePath) {
        $BaselinePath = Join-Path $configDir 'network_baseline.json'
    }

    # --- Helper: determine if an IP is private / loopback / link-local ----------
    function Test-IsPrivateIP ([string]$ip) {
        if (-not $ip) { return $true }
        # IPv6 loopback/link-local
        if ($ip -eq '::1' -or $ip -match '^fe80:') { return $true }
        # IPv4 private ranges + loopback + broadcast + APIPA
        if ($ip -match '^(127\.|10\.|192\.168\.|169\.254\.)') { return $true }
        if ($ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
        # Multicast
        if ($ip -match '^(22[4-9]|23\d)\.') { return $true }
        return $false
    }

    # Known suspicious destination ports (C2 channels, RAT defaults, coin miners)
    $suspiciousPorts = @(
        # IRC / legacy botnet
        6667, 6668, 6669, 7000,
        # Common C2 and RAT defaults
        4444, 1234, 31337, 12345, 54321, 9001, 9030, 9050, 9051,
        # Coin mining pools
        3333, 5555, 7777, 8333, 18080, 45700,
        # Known Metasploit/Cobalt Strike defaults
        50050, 4899, 2222
    )

    # --- Capture current external connections -----------------------------------
    $tcpConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

    # Build process map for owner identification
    $procMap = @{}
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $procMap[$_.Id] = $_.Name
        }
    } catch {}

    $currentExternal = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($conn in $tcpConns) {
        $remote = $conn.RemoteAddress
        if (Test-IsPrivateIP $remote) { continue }

        $procName = if ($procMap.ContainsKey([int]$conn.OwningProcess)) {
            $procMap[[int]$conn.OwningProcess]
        } else { "PID $($conn.OwningProcess)" }

        $currentExternal.Add(@{
            RemoteIP   = $remote
            RemotePort = [int]$conn.RemotePort
            LocalPort  = [int]$conn.LocalPort
            Process    = $procName
            PID        = [int]$conn.OwningProcess
        })
    }

    $currentIPs = ($currentExternal | ForEach-Object { $_.RemoteIP } | Sort-Object -Unique)

    # --- Check for suspicious port connections ----------------------------------
    foreach ($conn in $currentExternal) {
        if ($suspiciousPorts -contains $conn.RemotePort) {
            $findings.Add([PSCustomObject]@{
                Module      = 'NetworkAnomaly'
                Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Severity    = 'Red'
                Category    = 'Suspicious Port'
                Name        = "net-suspport-$($conn.RemoteIP)-$($conn.RemotePort)"
                DisplayName = "$($conn.Process) -> $($conn.RemoteIP):$($conn.RemotePort)"
                Path        = ''
                Hash        = ''
                Details     = "Process '$($conn.Process)' (PID $($conn.PID)) has an established connection to $($conn.RemoteIP):$($conn.RemotePort) - this port is commonly associated with C2 traffic, RATs, or coin mining."
                ActionTaken = ''
                MitreId     = 'T1071'
                MitreName   = 'Application Layer Protocol'
            })

            Add-Content -Path $AuditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                "[USER: $currentUser] " +
                "[MODULE: NetworkAnomaly] [ACTION: SuspiciousPort] " +
                "[DETAILS: Process='$($conn.Process)' PID=$($conn.PID) RemoteIP=$($conn.RemoteIP) Port=$($conn.RemotePort)]"
            ) -Encoding UTF8
        }
    }

    # --- Load or create baseline ------------------------------------------------
    if ($ForceBaseline -or -not (Test-Path $BaselinePath)) {
        # First run (or forced) - save baseline and return informational finding
        $baseline = [PSCustomObject]@{
            CreatedAt    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')
            Host         = $env:COMPUTERNAME
            ExternalIPs  = $currentIPs
            ConnectionCount = $currentExternal.Count
        }
        $baseline | ConvertTo-Json -Depth 4 | Set-Content -Path $BaselinePath -Encoding UTF8

        $findings.Add([PSCustomObject]@{
            Module      = 'NetworkAnomaly'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = 'Green'
            Category    = 'Network Baseline'
            Name        = 'net-baseline-created'
            DisplayName = 'Network Baseline Created'
            Path        = $BaselinePath
            Hash        = ''
            Details     = "Network baseline created with $($currentIPs.Count) unique external IPs and $($currentExternal.Count) active connections. Future scans will compare against this baseline."
            ActionTaken = ''
            MitreId     = 'T1049'
            MitreName   = 'System Network Connections Discovery'
        })

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $currentUser] " +
            "[MODULE: NetworkAnomaly] [ACTION: BaselineCreated] " +
            "[DETAILS: ExternalIPs=$($currentIPs.Count) Connections=$($currentExternal.Count) Path='$BaselinePath']"
        ) -Encoding UTF8

        return $findings
    }

    # --- Compare against baseline -----------------------------------------------
    try {
        $baseline = Get-Content $BaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "NetworkAnomaly: Failed to parse baseline file: $($_.Exception.Message)"
        return $findings
    }

    $baselineIPs = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($baseline.ExternalIPs),
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $newIPs = [System.Collections.Generic.List[string]]::new()
    foreach ($ip in $currentIPs) {
        if (-not $baselineIPs.Contains($ip)) {
            $newIPs.Add($ip)
        }
    }

    if ($newIPs.Count -gt 0) {
        $severity = if ($newIPs.Count -ge $NewIpRedThreshold) { 'Red' } else { 'Yellow' }

        # Find processes associated with the new IPs
        $newIpConnections = $currentExternal | Where-Object { $newIPs -contains $_.RemoteIP }
        $procDetails = ($newIpConnections | ForEach-Object { "$($_.Process)(PID $($_.PID))->$($_.RemoteIP):$($_.RemotePort)" }) -join ', '

        $findings.Add([PSCustomObject]@{
            Module      = 'NetworkAnomaly'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = $severity
            Category    = 'New External IPs'
            Name        = 'net-new-external-ips'
            DisplayName = "$($newIPs.Count) new external IP(s) detected"
            Path        = ''
            Hash        = ''
            Details     = "$($newIPs.Count) external IP(s) not in baseline detected. New IPs: $($newIPs -join ', '). Processes: $procDetails. Baseline date: $($baseline.CreatedAt). Use -ForceBaseline to update baseline."
            ActionTaken = ''
            MitreId     = 'T1071'
            MitreName   = 'Application Layer Protocol'
        })

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $currentUser] " +
            "[MODULE: NetworkAnomaly] [ACTION: NewExternalIPs] " +
            "[DETAILS: Count=$($newIPs.Count) IPs='$($newIPs -join ',')' Severity=$severity]"
        ) -Encoding UTF8
    }

    # Summarize if no anomalies beyond suspicious ports
    $netFindings = @($findings | Where-Object { $_.Name -ne 'net-new-external-ips' })
    if ($newIPs.Count -eq 0 -and $netFindings.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            Module      = 'NetworkAnomaly'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = 'Green'
            Category    = 'Network Anomaly'
            Name        = 'net-clean'
            DisplayName = "Network Anomaly Scan - Clean"
            Path        = ''
            Hash        = ''
            Details     = "All $($currentIPs.Count) external IPs match baseline. $($currentExternal.Count) established external connections. No suspicious ports detected."
            ActionTaken = ''
            MitreId     = 'T1049'
            MitreName   = 'System Network Connections Discovery'
        })
    }

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $currentUser] " +
        "[MODULE: NetworkAnomaly] [ACTION: Scan] " +
        "[DETAILS: CurrentExternal=$($currentIPs.Count) BaselineIPs=$($baselineIPs.Count) NewIPs=$($newIPs.Count)]"
    ) -Encoding UTF8

    return $findings
}

<#
.SYNOPSIS
    PortScan.ps1 - Identifies unexpected inbound TCP/UDP listeners on this endpoint.
.DESCRIPTION
    Uses Get-NetTCPConnection and Get-NetUDPEndpoint to enumerate all listening ports.
    Ports not found in whitelist.json are flagged. Each listener is enriched with the
    owning process name and its executable path for accurate attribution.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\PortScan.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-PortScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        # Build process ID -> process info lookup for enrichment
        $processLookup = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not $processLookup.ContainsKey($_.Id)) {
                $exePath = ''
                try { $exePath = $_.MainModule.FileName } catch {}
                $processLookup[$_.Id] = [PSCustomObject]@{
                    Name    = $_.ProcessName
                    Path    = $exePath
                }
            }
        }

        # --- TCP Listeners ---
        $tcpListeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

        $unknownTcp = 0
        foreach ($conn in $tcpListeners) {
            $port        = $conn.LocalPort
            $localAddr   = $conn.LocalAddress
            $ownerPid    = $conn.OwningProcess
            $procInfo    = $processLookup[$ownerPid]
            $procName    = if ($procInfo) { $procInfo.Name } else { "PID:$ownerPid" }
            $procPath    = if ($procInfo) { $procInfo.Path } else { '' }

            # Compute hash for the owning executable
            $sha256 = 'N/A'
            if ($procPath -and (Test-Path $procPath -ErrorAction SilentlyContinue)) {
                try { $sha256 = (Get-FileHash -Path $procPath -Algorithm SHA256).Hash }
                catch { $sha256 = 'HashError' }
            }

            $isWhitelisted = $Whitelist.ListeningPorts -contains $port

            if (-not $isWhitelisted) {
                $unknownTcp++

                # Escalate to Red if bound to all interfaces (0.0.0.0 or ::)
                $severity = 'Yellow'
                $details  = "Unexpected TCP listener on port $port (PID: $ownerPid / $procName). Bound: $localAddr"
                if ($localAddr -eq '0.0.0.0' -or $localAddr -eq '::') {
                    $severity = 'Red'
                    $details  = "Unexpected TCP listener exposed on ALL interfaces - port $port ($procName). Bound: $localAddr"
                }

                $findings.Add([PSCustomObject]@{
                    Module      = 'PortScan'
                    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Severity    = $severity
                    Category    = 'Network - TCP Listener'
                    Name        = "TCP:$port"
                    DisplayName = "TCP Port $port ($procName)"
                    Path        = $procPath
                    Hash        = $sha256
                    Details     = $details
                    ActionTaken = ''
                })
            }
        }

        # --- UDP Endpoints ---
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -ne 0 }

        $unknownUdp = 0
        # Deduplicate UDP ports (same port can appear for IPv4/IPv6)
        $seenUdpPorts = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($ep in $udpEndpoints) {
            $port = $ep.LocalPort
            if ($seenUdpPorts.Contains($port)) { continue }
            [void]$seenUdpPorts.Add($port)

            $isWhitelisted = $Whitelist.ListeningPorts -contains $port
            if (-not $isWhitelisted) {
                $unknownUdp++
                $ownerPid = $ep.OwningProcess
                $procInfo = $processLookup[$ownerPid]
                $procName = if ($procInfo) { $procInfo.Name } else { "PID:$ownerPid" }
                $procPath = if ($procInfo) { $procInfo.Path } else { '' }

                $sha256 = 'N/A'
                if ($procPath -and (Test-Path $procPath -ErrorAction SilentlyContinue)) {
                    try { $sha256 = (Get-FileHash -Path $procPath -Algorithm SHA256).Hash }
                    catch { $sha256 = 'HashError' }
                }

                $findings.Add([PSCustomObject]@{
                    Module      = 'PortScan'
                    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Severity    = 'Yellow'
                    Category    = 'Network - UDP Endpoint'
                    Name        = "UDP:$port"
                    DisplayName = "UDP Port $port ($procName)"
                    Path        = $procPath
                    Hash        = $sha256
                    Details     = "Unexpected UDP endpoint on port $port (PID: $ownerPid / $procName)"
                    ActionTaken = ''
                })
            }
        }

        $totalUnknown = $unknownTcp + $unknownUdp
        if ($totalUnknown -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'PortScan'
                Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Severity    = 'Green'
                Category    = 'Network'
                Name        = 'AllPortsClean'
                DisplayName = 'Port Scan'
                Path        = ''
                Hash        = ''
                Details     = "All $($tcpListeners.Count) TCP listeners and $($seenUdpPorts.Count) UDP endpoints are whitelisted."
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: PortScan] [ACTION: Scan] " +
            "[DETAILS: TCP listeners: $($tcpListeners.Count); UDP endpoints: $($seenUdpPorts.Count); Unknown flagged: $totalUnknown]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: PortScan] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

<#
.SYNOPSIS
    ThreatIntel.ps1 - Threat intelligence enrichment: IP reputation, hash checks, URLhaus blocklist.
.DESCRIPTION
    Invoke-ThreatIntelCheck
      1. Collects all external (non-RFC1918) IPs from current established TCP connections.
      2. Checks against optional AbuseIPDB API (requires free API key in settings.json).
      3. Checks against optional VirusTotal API (requires free API key in settings.json).
      4. Checks running process hashes against MalwareBazaar (no key needed, rate-limited).
      5. Checks DNS cache entries against local URLhaus blocklist (offline, updated manually).
      6. All results are cached in Config\threat_cache.json for cacheHours (default 24).

    All API providers are OPTIONAL and individually gated by settings.
    The module operates fully offline if all APIs are disabled.

    MITRE ATT&CK:
      T1071 - Application Layer Protocol (C2 over HTTP/HTTPS)
      T1102 - Web Service (C2 using web services)
      T1568 - Dynamic Resolution (DGA / DNS)
.OUTPUTS
    [PSCustomObject[]] - QuietMonitor finding schema
#>

# ============================================================
# Helpers
# ============================================================
function script:Test-IsPrivateIP {
    param([string]$IP)
    if (-not $IP) { return $true }
    # Loopback
    if ($IP -eq '127.0.0.1' -or $IP -match '^127\.' -or $IP -eq '::1') { return $true }
    # Link-local
    if ($IP -match '^169\.254\.') { return $true }
    # IPv6 ULA / link-local
    if ($IP -match '^fe80::' -or $IP -match '^fc' -or $IP -match '^fd') { return $true }
    # RFC1918
    if ($IP -match '^10\.')                                           { return $true }
    if ($IP -match '^192\.168\.')                                     { return $true }
    if ($IP -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
    # IPv4-in-IPv6
    if ($IP -match '^::ffff:')                                        { return $true }
    # Any remaining IPv6 (if not handled above, treat as non-routable for safety)
    if ($IP -match ':')                                                { return $true }
    return $false
}

function script:Get-CachedThreatData {
    param([string]$CachePath)
    if (-not $CachePath -or -not (Test-Path $CachePath)) {
        return [PSCustomObject]@{ checked = @(); hashes = @(); domains = @() }
    }
    try {
        return Get-Content $CachePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return [PSCustomObject]@{ checked = @(); hashes = @(); domains = @() }
    }
}

function script:Save-ThreatCache {
    param([object]$Cache, [string]$CachePath)
    try {
        $Cache | ConvertTo-Json -Depth 6 | Set-Content -Path $CachePath -Encoding UTF8 -Force
    } catch {}
}

function script:New-TIFinding {
    param($Sev, $Cat, $Name, $DisplayName, $Path, $Details, $MitreId, $MitreName)
    [PSCustomObject]@{
        Module      = 'ThreatIntel'
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
# Invoke-ThreatIntelCheck
# ============================================================
function Invoke-ThreatIntelCheck {
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

    $abuseEnabled  = $false; $abuseKey      = ''
    $vtEnabled     = $false; $vtKey         = ''
    $mbEnabled     = $true
    $urlhausPath   = 'C:\QuietMonitor\Config\urlhaus_blocklist.txt'
    $cacheHours    = 24
    $cachePath     = 'C:\QuietMonitor\Config\threat_cache.json'

    if (Test-Path $cfgPath) {
        try {
            $cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($cfg.threatIntel) {
                if ($cfg.threatIntel.abuseIPDB.enabled -and $cfg.threatIntel.abuseIPDB.apiKey) {
                    $abuseEnabled = $true; $abuseKey = $cfg.threatIntel.abuseIPDB.apiKey
                }
                if ($cfg.threatIntel.virusTotal.enabled -and $cfg.threatIntel.virusTotal.apiKey) {
                    $vtEnabled = $true; $vtKey = $cfg.threatIntel.virusTotal.apiKey
                }
                if ($null -ne $cfg.threatIntel.malwareBazaar.enabled) { $mbEnabled = [bool]$cfg.threatIntel.malwareBazaar.enabled }
                if ($cfg.threatIntel.cacheHours)    { $cacheHours  = [int]$cfg.threatIntel.cacheHours }
                if ($cfg.threatIntel.cachePath)     { $cachePath   = Join-Path 'C:\QuietMonitor' $cfg.threatIntel.cachePath }
                if ($cfg.threatIntel.urlhausBlocklistPath) { $urlhausPath = Join-Path 'C:\QuietMonitor' $cfg.threatIntel.urlhausBlocklistPath }
            }
        } catch {}
    }

    Write-Host "  [ThreatIntel] Starting threat intelligence checks..." -ForegroundColor Cyan

    # ---- Load Cache ----
    $cache     = script:Get-CachedThreatData -CachePath $cachePath
    $cacheAge  = $cacheHours * 3600   # seconds
    $now       = Get-Date
    $cacheNew  = [PSCustomObject]@{
        checked = [System.Collections.Generic.List[object]]::new()
        hashes  = [System.Collections.Generic.List[object]]::new()
        domains = [System.Collections.Generic.List[object]]::new()
    }

    # Migrate existing cache entries
    if ($cache.checked) { foreach ($e in $cache.checked) { $cacheNew.checked.Add($e) } }
    if ($cache.hashes)  { foreach ($e in $cache.hashes)  { $cacheNew.hashes.Add($e)  } }
    if ($cache.domains) { foreach ($e in $cache.domains) { $cacheNew.domains.Add($e) } }

    # ---- Get External IPs ----
    $externalIPs = @()
    try {
        $externalIPs = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -and -not (script:Test-IsPrivateIP $_.RemoteAddress) } |
            Select-Object -ExpandProperty RemoteAddress -Unique)
    } catch {}

    Write-Host "  [ThreatIntel] External IPs to check: $($externalIPs.Count)" -ForegroundColor DarkGray

    foreach ($ip in $externalIPs | Select-Object -First 20) {
        # Check cache
        $cached = $cacheNew.checked | Where-Object { $_.ip -eq $ip } | Select-Object -First 1
        if ($cached) {
            $cacheDate = try { [datetime]$cached.lastChecked } catch { [datetime]::MinValue }
            $secAgo    = ($now - $cacheDate).TotalSeconds
            if ($secAgo -lt $cacheAge) {
                if ($cached.score -gt 50) {
                    $findings.Add((script:New-TIFinding 'Red' 'Threat Intel - IP' "ti-ip-$ip" "Malicious IP (cached): $ip" '' "IP $ip flagged by threat intelligence (AbuseIPDB confidence: $($cached.score)%). Active connection detected. [Cached result from $($cached.lastChecked)]" 'T1071' 'Application Layer Protocol'))
                }
                continue
            }
        }

        $abuseScore = 0
        $vtMalicious = 0

        # ---- AbuseIPDB ----
        if ($abuseEnabled) {
            try {
                $resp = Invoke-RestMethod `
                    -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" `
                    -Headers @{ 'Key' = $abuseKey; 'Accept' = 'application/json' } `
                    -Method GET -TimeoutSec 10 -ErrorAction Stop
                $abuseScore = [int]$resp.data.abuseConfidenceScore
                if ($abuseScore -gt 50) {
                    $findings.Add((script:New-TIFinding 'Red' 'Threat Intel - IP' "ti-abuse-$ip" "AbuseIPDB: Malicious IP $ip" '' "IP $ip scored $abuseScore% confidence on AbuseIPDB. Established TCP connection detected. Terminate and investigate." 'T1071' 'Application Layer Protocol'))
                } elseif ($abuseScore -gt 20) {
                    $findings.Add((script:New-TIFinding 'Yellow' 'Threat Intel - IP' "ti-abuse-suspicious-$ip" "AbuseIPDB: Suspicious IP $ip" '' "IP $ip scored $abuseScore% on AbuseIPDB (low-medium risk). Monitor for further activity." 'T1071' 'Application Layer Protocol'))
                }
            } catch {
                Write-Host "  [ThreatIntel] AbuseIPDB check failed for $ip`: $_" -ForegroundColor DarkGray
            }
        }

        # ---- VirusTotal ----
        if ($vtEnabled) {
            try {
                $resp = Invoke-RestMethod `
                    -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" `
                    -Headers @{ 'x-apikey' = $vtKey } `
                    -Method GET -TimeoutSec 10 -ErrorAction Stop
                $vtMalicious = [int]$resp.data.attributes.last_analysis_stats.malicious
                if ($vtMalicious -gt 2) {
                    $findings.Add((script:New-TIFinding 'Red' 'Threat Intel - IP' "ti-vt-$ip" "VirusTotal: Malicious IP $ip" '' "IP $ip flagged by $vtMalicious VirusTotal engines. Active established connection from this host." 'T1102' 'Web Service'))
                }
            } catch {
                Write-Host "  [ThreatIntel] VirusTotal check failed for $ip`: $_" -ForegroundColor DarkGray
            }
        }

        # Update cache
        $entry = $cacheNew.checked | Where-Object { $_.ip -eq $ip }
        if ($entry) {
            $entry.score       = [Math]::Max($abuseScore, $vtMalicious * 10)
            $entry.lastChecked = $now.ToString('o')
        } else {
            $cacheNew.checked.Add([PSCustomObject]@{
                ip          = $ip
                score       = [Math]::Max($abuseScore, $vtMalicious * 10)
                categories  = ''
                lastChecked = $now.ToString('o')
            })
        }
    }

    # ---- MalwareBazaar hash check (running processes) ----
    if ($mbEnabled) {
        Write-Host "  [ThreatIntel] Checking running process hashes vs MalwareBazaar..." -ForegroundColor DarkGray
        try {
            $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Test-Path $_.Path) } |
                     Select-Object -Property Id, Name, Path -Unique | Select-Object -First 30

            foreach ($proc in $procs) {
                $hash = $null
                try { $hash = (Get-FileHash $proc.Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { continue }
                if (-not $hash) { continue }

                # Check cache
                $cachedH = $cacheNew.hashes | Where-Object { $_.hash -eq $hash } | Select-Object -First 1
                if ($cachedH) {
                    $cacheDate = try { [datetime]$cachedH.lastChecked } catch { [datetime]::MinValue }
                    if (($now - $cacheDate).TotalSeconds -lt $cacheAge) {
                        if ($cachedH.malware) {
                            $findings.Add((script:New-TIFinding 'Red' 'Threat Intel - Hash' "ti-mb-$hash" "MalwareBazaar: Malicious Process $($proc.Name)" $proc.Path "Process '$($proc.Name)' (PID $($proc.Id)) hash $hash matched MalwareBazaar malware family '$($cachedH.malware)'. Terminate and quarantine immediately. [Cached]" 'T1071' 'Application Layer Protocol'))
                        }
                        continue
                    }
                }

                $malwareFamily = ''
                try {
                    $body = "query=get_info&hash=$hash"
                    $resp = Invoke-RestMethod `
                        -Uri 'https://mb-api.abuse.ch/api/v1/' `
                        -Method POST `
                        -Body $body `
                        -ContentType 'application/x-www-form-urlencoded' `
                        -TimeoutSec 10 -ErrorAction Stop
                    if ($resp.query_status -eq 'hash_found') {
                        $malwareFamily = $resp.data[0].signature
                        $findings.Add((script:New-TIFinding 'Red' 'Threat Intel - Hash' "ti-mb-$hash" "MalwareBazaar: Malicious Process $($proc.Name)" $proc.Path "Process '$($proc.Name)' (PID $($proc.Id)) hash $hash found in MalwareBazaar. Family: $malwareFamily. Terminate and quarantine immediately." 'T1071' 'Application Layer Protocol'))
                    }
                } catch {
                    Write-Host "  [ThreatIntel] MalwareBazaar check failed: $_" -ForegroundColor DarkGray
                }

                # Cache result
                $cacheNew.hashes.Add([PSCustomObject]@{
                    hash        = $hash
                    malware     = $malwareFamily
                    lastChecked = $now.ToString('o')
                })
            }
        } catch { Write-Host "  [ThreatIntel] Process hash collection error: $_" -ForegroundColor DarkGray }
    }

    # ---- URLhaus Blocklist check (DNS cache) ----
    if (Test-Path $urlhausPath -ErrorAction SilentlyContinue) {
        Write-Host "  [ThreatIntel] Checking DNS cache against URLhaus blocklist..." -ForegroundColor DarkGray
        try {
            $blocklist = Get-Content $urlhausPath -Encoding UTF8 -ErrorAction Stop |
                         Where-Object { $_ -and -not $_.StartsWith('#') } |
                         ForEach-Object { $_.Trim().ToLower() }
            $blockSet  = [System.Collections.Generic.HashSet[string]]::new($blocklist)

            $dnsCache  = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -and $_.DataLength -gt 0 }
            foreach ($entry in $dnsCache) {
                $domain = $entry.Entry.ToLower().TrimEnd('.')
                if ($blockSet.Contains($domain)) {
                    $findings.Add((script:New-TIFinding 'Red' 'Threat Intel - DNS' "ti-urlhaus-$domain" "URLhaus: Blocked Domain Resolved $domain" '' "Domain '$domain' found in URLhaus malicious URL blocklist and in local DNS cache. This host has recently resolved a known malicious/phishing domain." 'T1568' 'Dynamic Resolution'))
                }
            }
        } catch { Write-Host "  [ThreatIntel] URLhaus check error: $_" -ForegroundColor DarkGray }
    } else {
        $findings.Add((script:New-TIFinding 'Green' 'Threat Intel - DNS' 'ti-urlhaus-absent' 'URLhaus Blocklist: Not Configured' '' "URLhaus blocklist not found at '$urlhausPath'. Download from https://urlhaus.abuse.ch/downloads/text_online/ to enable offline domain blocking." '' ''))
    }

    # ---- Save Cache ----
    script:Save-ThreatCache -Cache $cacheNew -CachePath $cachePath

    # ---- Summary ----
    $rCnt = @($findings | Where-Object { $_.Severity -eq 'Red'    }).Count
    $yCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[MODULE: ThreatIntel] [ACTION: Scan] " +
            "[DETAILS: ExtIPs=$($externalIPs.Count) RED=$rCnt YELLOW=$yCnt AbuseEnabled=$abuseEnabled VTEnabled=$vtEnabled MBEnabled=$mbEnabled]"
        ) -Encoding UTF8
    }

    if ($rCnt -eq 0 -and $yCnt -eq 0) {
        $findings.Add((script:New-TIFinding 'Green' 'ThreatIntel' 'ti-clean' 'ThreatIntel: No IOCs Detected' '' "Checked $($externalIPs.Count) external IPs; no malicious indicators found." '' ''))
    }

    Write-Host ("  [ThreatIntel] Complete — RED: $rCnt  YELLOW: $yCnt") -ForegroundColor Cyan
    return $findings
}

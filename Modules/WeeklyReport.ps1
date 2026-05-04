<#
.SYNOPSIS
    WeeklyReport.ps1 - Weekly security summary report with risk scoring and trend analysis.
.DESCRIPTION
    Provides:
      Get-RiskScore    - Computes a 0-100 risk score from findings using MITRE-weighted severity.
      Get-RiskLevel    - Maps a score to a risk level (LOW / MEDIUM / HIGH / CRITICAL).
      New-WeeklyReport - Generates a full HTML weekly report with:
                           Executive summary (total threats, resolved, pending, week-over-week deltas)
                           Risk Score (0-100) weighted by severity + MITRE technique category
                           SVG trend chart of risk scores (pure HTML5, no CDN dependencies)
                           Top 5 MITRE ATT&CK techniques triggered this week
                           New software / services / users vs. baseline
                           Quarantine activity summary
                           Auto-generated recommended actions
                         Report saved to C:\QuietMonitor\Reports\Weekly\
                         Old reports auto-purged after retentionDays (default 90).

    Data source: scan_summary_*.json files written by Run-SecuritySuite.ps1 after each scan.

    MITRE ATT&CK references:
      Multiple techniques inherited from underlying scan findings.
      Risk weighting: Credential (T1003/T1078/T1110) = 2.5x; Persistence = 1.6x;
                      Lateral/Network = 1.5x; Execution = 1.3x; Others = 1x
.OUTPUTS
    Get-RiskScore:  [int] 0-100
    New-WeeklyReport: [string] full path of the generated HTML file
#>

# ============================================================
# Get-RiskScore
# Returns a 0-100 risk score from an array of findings.
# Called by Run-SecuritySuite.ps1 after each full scan.
# ============================================================
function Get-RiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    # MITRE technique -> severity weight multiplier
    # Higher multiplier = more serious technique category
    $mitreWeights = @{
        # Credential Access (very high risk)
        'T1003'     = 2.5;  'T1003.001' = 2.5
        'T1110'     = 2.2;  'T1555' = 2.2
        # Privilege Escalation / Defense Evasion
        'T1134'     = 2.0;  'T1548' = 2.0; 'T1484' = 2.0; 'T1562' = 2.0
        # Account Manipulation
        'T1078'     = 1.9;  'T1098' = 1.9
        # Process Injection / Memory
        'T1055'     = 1.8
        # Persistence
        'T1547'     = 1.6;  'T1543' = 1.6; 'T1546' = 1.6; 'T1053' = 1.6
        # Lateral Movement / C2
        'T1021'     = 1.5;  'T1021.002' = 1.5; 'T1071' = 1.5
        # Execution / LOLBin
        'T1059'     = 1.3;  'T1204' = 1.3; 'T1218' = 1.3; 'T1569' = 1.3
        # Masquerading / Discovery
        'T1036'     = 1.2;  'T1049' = 1.1
    }

    $rawScore = 0.0
    foreach ($f in $Findings) {
        $base = switch ($f.Severity) {
            'Red'    { 10.0 }
            'Yellow' { 3.0  }
            default  { 0.0  }
        }
        if ($base -eq 0) { continue }

        $mult = 1.0
        if ($f.MitreId -and $f.MitreId.Trim()) {
            $tid = $f.MitreId.Trim()
            if     ($mitreWeights.ContainsKey($tid))                  { $mult = $mitreWeights[$tid] }
            elseif ($tid -match '\.') {
                $parent = $tid.Split('.')[0]
                if ($mitreWeights.ContainsKey($parent))               { $mult = $mitreWeights[$parent] }
            }
        }
        $rawScore += $base * $mult
    }

    # Volume bonus: many Red findings escalates score faster
    $redCount = @($Findings | Where-Object { $_.Severity -eq 'Red' }).Count
    if ($redCount -gt 10) { $rawScore += 20 }
    elseif ($redCount -gt 5) { $rawScore += 10 }

    return [Math]::Min(100, [int][Math]::Round($rawScore))
}

# ============================================================
# Get-RiskLevel
# ============================================================
function Get-RiskLevel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Score)

    if ($Score -ge 81) { return [PSCustomObject]@{ Level = 'CRITICAL'; Color = '#dc3545'; ConsoleColor = 'Red'    } }
    if ($Score -ge 51) { return [PSCustomObject]@{ Level = 'HIGH';     Color = '#fd7e14'; ConsoleColor = 'Red'    } }
    if ($Score -ge 21) { return [PSCustomObject]@{ Level = 'MEDIUM';   Color = '#ffc107'; ConsoleColor = 'Yellow' } }
    return              [PSCustomObject]@{ Level = 'LOW';      Color = '#28a745'; ConsoleColor = 'Green'  }
}

# ============================================================
# Internal: build SVG trend line chart (no CDN)
# ============================================================
function Build-SvgTrendChart {
    param([int[]]$Scores, [string[]]$Labels)

    $w = 580; $h = 200; $padL = 42; $padR = 12; $padT = 10; $padB = 36
    $chartW = $w - $padL - $padR
    $chartH = $h - $padT - $padB
    $n = $Scores.Count

    # Grid lines
    $gridLines = ''
    foreach ($pct in 0,25,50,75,100) {
        $y = $padT + $chartH - [int]($pct * $chartH / 100)
        $gridLines += "<line x1='$padL' y1='$y' x2='$($padL+$chartW)' y2='$y' stroke='#30363d' stroke-dasharray='3 3'/>"
        $gridLines += "<text x='$($padL - 4)' y='$($y + 4)' fill='#8b949e' font-size='9' text-anchor='end'>$pct</text>"
    }

    # Polyline points
    $pts = ''
    $areaPath = "M $padL $($padT + $chartH)"
    for ($i = 0; $i -lt $n; $i++) {
        $x = if ($n -le 1) { $padL + $chartW / 2 } else { $padL + [int]($i * $chartW / ($n - 1)) }
        $y = $padT + $chartH - [int]($Scores[$i] * $chartH / 100)
        $pts += "$x,$y "
        $areaPath += " L $x $y"
    }
    $areaPath += " L $($padL + $chartW) $($padT + $chartH) Z"
    $pts = $pts.Trim()

    # Label ticks
    $ticks = ''
    for ($i = 0; $i -lt $n; $i++) {
        $x = if ($n -le 1) { $padL + $chartW / 2 } else { $padL + [int]($i * $chartW / ($n - 1)) }
        $lbl = if ($i -lt $Labels.Count) { $Labels[$i] } else { '' }
        $ticks += "<text x='$x' y='$($h - 6)' fill='#8b949e' font-size='9' text-anchor='middle'>$lbl</text>"
    }

    return @"
<svg width="$w" height="$h" xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
  <rect width="$w" height="$h" fill="transparent"/>
  $gridLines
  <line x1='$padL' y1='$padT' x2='$padL' y2='$($padT+$chartH)' stroke='#30363d'/>
  <line x1='$padL' y1='$($padT+$chartH)' x2='$($padL+$chartW)' y2='$($padT+$chartH)' stroke='#30363d'/>
  <path d='$areaPath' fill='rgba(218,54,51,0.12)' stroke='none'/>
  <polyline points='$pts' fill='none' stroke='rgba(218,54,51,0.85)' stroke-width='2.5' stroke-linejoin='round'/>
  $( if ($pts) {
       $ptArr = $pts -split '\s+' | Where-Object { $_ -match ',' }
       ($ptArr | ForEach-Object {
           $xy = $_ -split ','
           "<circle cx='$($xy[0])' cy='$($xy[1])' r='4' fill='#da3633' stroke='#0d1117' stroke-width='1.5'/>"
       }) -join ''
   } )
  $ticks
</svg>
"@
}

# ============================================================
# Internal: ASCII console trend chart
# ============================================================
function Get-ASCIITrendChart {
    param([int[]]$Scores, [string[]]$Labels)

    $rows = 8
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("  Risk Score Trend")

    for ($r = $rows; $r -ge 0; $r--) {
        $threshold = [int]($r * 100 / $rows)
        $line = "  {0,3} |" -f $threshold
        for ($c = 0; $c -lt $Scores.Count; $c++) {
            $col = [int][Math]::Round($Scores[$c] * $rows / 100)
            if ($col -eq $r) { $line += " * " }
            elseif ($col -gt $r) { $line += " | " }
            else { $line += "   " }
        }
        [void]$sb.AppendLine($line)
    }
    [void]$sb.Append("    0 +-")
    [void]$sb.AppendLine(("---" * [Math]::Max(1, $Scores.Count)))

    if ($Labels.Count -gt 0) {
        $labelLine = "       "
        foreach ($lbl in $Labels) {
            $short = if ($lbl.Length -gt 3) { $lbl.Substring($lbl.Length - 3) } else { $lbl.PadLeft(3) }
            $labelLine += $short + " "
        }
        [void]$sb.AppendLine($labelLine)
    }
    return $sb.ToString()
}

# ============================================================
# New-WeeklyReport
# ============================================================
function New-WeeklyReport {
    [CmdletBinding()]
    param(
        [string]$ReportPath   = 'C:\QuietMonitor\Reports',
        [string]$AuditLog     = 'C:\QuietMonitor\Logs\audit.log',
        [string]$SettingsFile = ''
    )

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # ---- Paths ----
    $weeklyPath = Join-Path $ReportPath 'Weekly'
    if (-not (Test-Path $weeklyPath)) { New-Item -ItemType Directory -Path $weeklyPath -Force | Out-Null }

    # ---- Settings ----
    $retentionDays = 90
    $emailEnabled  = $false
    if (-not $SettingsFile) {
        $SettingsFile = 'C:\QuietMonitor\Config\settings.json'
        if (-not (Test-Path $SettingsFile)) {
            $SettingsFile = Join-Path (Split-Path $PSCommandPath -Parent) '..\Config\settings.json'
        }
    }
    if (Test-Path $SettingsFile) {
        try {
            $cfg = Get-Content $SettingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($cfg.weeklyReport.retentionDays) { $retentionDays = [int]$cfg.weeklyReport.retentionDays }
            if ($cfg.weeklyReport.email)         { $emailEnabled  = [bool]$cfg.weeklyReport.email }
        } catch {}
    }

    $now       = Get-Date
    $fileStamp = $now.ToString('yyyyMMdd_HHmmss')
    $dateStamp = $now.ToString('yyyy-MM-dd')

    # ---- Load scan summaries ----
    $thisWeek = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lastWeek = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (Test-Path $ReportPath) {
        Get-ChildItem -Path $ReportPath -Filter 'scan_*_summary.json' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | ForEach-Object {
                try {
                    $s = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    $age = ($now - [datetime]$s.timestamp).TotalDays
                    if ($age -le 7)         { $thisWeek.Add($s) }
                    elseif ($age -le 14)    { $lastWeek.Add($s) }
                } catch {}
            }
    }

    # ---- Aggregate this week ----
    $twRed     = [int]($thisWeek | ForEach-Object { [int]$_.findings.red }    | Measure-Object -Sum).Sum
    $twYellow  = [int]($thisWeek | ForEach-Object { [int]$_.findings.yellow } | Measure-Object -Sum).Sum
    $twRiskAvg = if ($thisWeek.Count -gt 0) { [int](($thisWeek | ForEach-Object { [int]$_.riskScore } | Measure-Object -Average).Average) } else { 0 }
    $twRiskMax = if ($thisWeek.Count -gt 0) { [int](($thisWeek | ForEach-Object { [int]$_.riskScore } | Measure-Object -Maximum).Maximum) } else { 0 }

    # ---- Aggregate last week ----
    $lwRed     = [int]($lastWeek | ForEach-Object { [int]$_.findings.red } | Measure-Object -Sum).Sum
    $lwRiskAvg = if ($lastWeek.Count -gt 0) { [int](($lastWeek | ForEach-Object { [int]$_.riskScore } | Measure-Object -Average).Average) } else { 0 }

    # ---- Deltas ----
    $redDelta  = $twRed - $lwRed
    $riskDelta = $twRiskAvg - $lwRiskAvg

    function Format-Delta ([int]$d) {
        if ($d -gt 0) { return "+$d &#x25B2;" }
        if ($d -lt 0) { return "$d &#x25BC;" }
        return "0 &#x25AC;"
    }

    # ---- Top 5 MITRE ----
    $mitreCount = @{}
    foreach ($s in $thisWeek) {
        if ($s.mitreTechniques) {
            foreach ($t in $s.mitreTechniques) {
                if ($t -and $t.Trim()) {
                    if (-not $mitreCount.ContainsKey($t)) { $mitreCount[$t] = 0 }
                    $mitreCount[$t]++
                }
            }
        }
    }
    $top5 = $mitreCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5

    # ---- Quarantine activity this week ----
    $qCount = 0
    $qFiles = @()
    $qPath  = 'C:\QuietMonitor\Quarantine\quarantine_manifest.json'
    if (Test-Path $qPath) {
        try {
            $qm = Get-Content $qPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $wkQ = @($qm | Where-Object { -not $_.Removed -and ([datetime]$_.Timestamp) -gt $now.AddDays(-7) })
            $qCount = $wkQ.Count
            $qFiles = @($wkQ | Select-Object -First 8 | ForEach-Object { $_.OriginalPath })
        } catch {}
    }

    # ---- New items vs baseline ----
    $newSW   = @($thisWeek | ForEach-Object { if ($_.newSoftware) { $_.newSoftware } } | Sort-Object -Unique)
    $newSvc  = @($thisWeek | ForEach-Object { if ($_.newServices) { $_.newServices } } | Sort-Object -Unique)
    $newUsr  = @($thisWeek | ForEach-Object { if ($_.newUsers)    { $_.newUsers }    } | Sort-Object -Unique)

    # ---- Trend data (last 10 scans, sorted oldest-first) ----
    $sorted = @($thisWeek | Sort-Object { [datetime]$_.timestamp } | Select-Object -Last 10)
    $tScores = @($sorted | ForEach-Object { [int]$_.riskScore })
    $tLabels = @($sorted | ForEach-Object { ([datetime]$_.timestamp).ToString('MM/dd') })
    if ($tScores.Count -eq 0) { $tScores = @(0); $tLabels = @('--') }

    # ---- Risk level ----
    $riskInfo  = Get-RiskLevel -Score $twRiskMax
    $riskLevel = $riskInfo.Level
    $riskColor = $riskInfo.Color

    # ---- Recommendations ----
    $recs = [System.Collections.Generic.List[string]]::new()
    if ($twRed -gt 0)      { $recs.Add("IMMEDIATE: Investigate and remediate $twRed RED-severity threat(s) detected this week.") }
    if ($qCount -gt 0)     { $recs.Add("Review $qCount quarantined file(s) — confirm correct classification and investigate root cause.") }
    if ($riskDelta -gt 15) { $recs.Add("Risk score rose $riskDelta points vs. last week. Investigate the root cause of increased threat detections.") }
    if ($newUsr.Count -gt 0)  { $recs.Add("New user accounts detected: [$($newUsr -join ', ')]. Verify each account is authorized.") }
    if ($newSvc.Count -gt 0)  { $recs.Add("New services detected: [$($newSvc -join ', ')]. Validate they are expected and signed.") }
    if ($newSW.Count -gt 0)   { $recs.Add("$($newSW.Count) new software package(s) detected vs. baseline. Review for unauthorized installations.") }
    if ($mitreCount.Keys | Where-Object { $_ -match 'T1003|T1055|T1134' }) {
        $recs.Add("Credential/injection techniques detected. Enable Credential Guard (if supported), review LSASS access controls.")
    }
    if ($recs.Count -eq 0) { $recs.Add("No critical actions required. Continue routine monitoring and keep baselines current.") }

    # ---- Build HTML components ----
    $svgChart = Build-SvgTrendChart -Scores $tScores -Labels $tLabels

    $mitreRows = ''
    foreach ($m in $top5) {
        $techUrl = "https://attack.mitre.org/techniques/$($m.Name.Replace('.','/'))"
        $mitreRows += "<tr><td><a href='$techUrl' style='color:#58a6ff' target='_blank'><code>$($m.Name)</code></a></td><td>$($m.Value)</td></tr>"
    }
    if (-not $mitreRows) { $mitreRows = "<tr><td colspan='2' style='color:#8b949e'>No MITRE-tagged findings this week</td></tr>" }

    $qRows = if ($qFiles.Count -gt 0) {
        ($qFiles | ForEach-Object { "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($_))</code></td></tr>" }) -join ''
    } else { "<tr><td style='color:#8b949e'>No quarantine activity this week</td></tr>" }

    $recItems = ($recs | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join ''

    $newItemsHtml = ''
    if ($newSW.Count -gt 0)  { $newItemsHtml += "<p><strong style='color:#c9d1d9'>New Software ($($newSW.Count)):</strong> $([System.Web.HttpUtility]::HtmlEncode($newSW -join ', '))</p>" }
    if ($newSvc.Count -gt 0) { $newItemsHtml += "<p><strong style='color:#c9d1d9'>New Services ($($newSvc.Count)):</strong> $([System.Web.HttpUtility]::HtmlEncode($newSvc -join ', '))</p>" }
    if ($newUsr.Count -gt 0) { $newItemsHtml += "<p><strong style='color:#c9d1d9'>New Users ($($newUsr.Count)):</strong> $([System.Web.HttpUtility]::HtmlEncode($newUsr -join ', '))</p>" }
    if (-not $newItemsHtml)  { $newItemsHtml = "<p style='color:#8b949e'>No new software, services, or users detected vs. baseline this week.</p>" }

    $redDeltaFmt  = Format-Delta $redDelta
    $riskDeltaFmt = Format-Delta $riskDelta

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>QuietMonitor Weekly Report - $dateStamp</title>
  <style>
    :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;
          --red:#da3633;--yellow:#d29922;--green:#3fb950;--blue:#58a6ff}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:var(--bg);color:var(--text);font-size:13px;line-height:1.5}
    header{background:var(--panel);border-bottom:1px solid var(--border);padding:20px 32px}
    header h1{font-size:20px;font-weight:700;color:var(--blue)}
    .meta{margin-top:6px;color:var(--muted);font-size:11px}
    .meta span{margin-right:20px}
    .container{padding:20px 32px;max-width:1400px}
    .grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
    .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
    .card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px 22px}
    .card h3{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:10px;border-left:3px solid var(--blue);padding-left:8px}
    .big-num{font-size:34px;font-weight:700}
    .sub{font-size:11px;color:var(--muted);margin-top:3px}
    .risk-badge{display:inline-block;padding:4px 14px;border-radius:4px;font-weight:700;font-size:16px;background:$riskColor;color:#fff}
    table{width:100%;border-collapse:collapse}
    th,td{padding:9px 11px;border-bottom:1px solid var(--border);font-size:12px}
    th{font-weight:600;color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.8px;background:#1c2128}
    tr:last-child td{border-bottom:none}
    .rec-list{list-style:none;padding:0}
    .rec-list li{padding:9px 12px;border-left:3px solid var(--blue);margin-bottom:6px;background:rgba(88,166,255,.04);border-radius:0 4px 4px 0;font-size:12px}
    footer{margin-top:36px;padding:14px 32px;border-top:1px solid var(--border);color:var(--muted);font-size:11px}
    code{font-family:Consolas,monospace;font-size:11px}
  </style>
</head>
<body>
<header>
  <h1>&#x1F4C8; QuietMonitor Weekly Security Report</h1>
  <div class="meta">
    <span>&#x1F4BB; <b>Host:</b> $env:COMPUTERNAME</span>
    <span>&#x1F4C5; <b>Week ending:</b> $dateStamp</span>
    <span>&#x1F50D; <b>Scans this week:</b> $($thisWeek.Count)</span>
    <span>&#x23F1; <b>Generated:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
  </div>
</header>
<div class="container">

  <!-- KPI Row -->
  <div class="grid-4">
    <div class="card">
      <h3>Peak Risk Score</h3>
      <div><span class="risk-badge">$twRiskMax / 100</span></div>
      <div class="sub">$riskLevel &bull; Avg this week: $twRiskAvg &bull; WoW: $riskDeltaFmt</div>
    </div>
    <div class="card">
      <h3>RED Threats This Week</h3>
      <div class="big-num" style="color:var(--red)">$twRed</div>
      <div class="sub">vs Last Week: $redDeltaFmt</div>
    </div>
    <div class="card">
      <h3>YELLOW Suspicious</h3>
      <div class="big-num" style="color:var(--yellow)">$twYellow</div>
      <div class="sub">WoW Risk Avg: $lwRiskAvg &rarr; $twRiskAvg</div>
    </div>
    <div class="card">
      <h3>Quarantined This Week</h3>
      <div class="big-num" style="color:var(--blue)">$qCount</div>
      <div class="sub">Files isolated in quarantine</div>
    </div>
  </div>

  <!-- Chart + MITRE -->
  <div class="grid-2">
    <div class="card">
      <h3>&#x1F4C9; Risk Score Trend (Recent Scans)</h3>
      $svgChart
    </div>
    <div class="card">
      <h3>&#x1F3AF; Top 5 MITRE ATT&amp;CK Techniques</h3>
      <table>
        <thead><tr><th>Technique ID</th><th>Detections</th></tr></thead>
        <tbody>$mitreRows</tbody>
      </table>
    </div>
  </div>

  <!-- New Items + Quarantine -->
  <div class="grid-2">
    <div class="card">
      <h3>&#x1F195; New Items vs Baseline This Week</h3>
      $newItemsHtml
    </div>
    <div class="card">
      <h3>&#x1F512; Quarantine Activity (Last 7 Days)</h3>
      <table>
        <thead><tr><th>Quarantined File Path</th></tr></thead>
        <tbody>$qRows</tbody>
      </table>
    </div>
  </div>

  <!-- Recommendations -->
  <div class="card">
    <h3>&#x1F6A8; Recommended Actions</h3>
    <ul class="rec-list">$recItems</ul>
  </div>

</div>
<footer>
  QuietMonitor Security Suite Weekly Report &bull; $dateStamp &bull; $env:COMPUTERNAME &bull;
  $(if ($AuditLog) { "Audit log: $AuditLog" })
</footer>
</body>
</html>
"@

    $reportFile = Join-Path $weeklyPath "WeeklyReport_${fileStamp}.html"
    [System.IO.File]::WriteAllText($reportFile, $html, [System.Text.Encoding]::UTF8)

    # ---- Console output ----
    Write-Host ""
    Write-Host "  [WeeklyReport] Week of $dateStamp" -ForegroundColor Cyan
    Write-Host ("  Peak Risk Score : {0}/100 [{1}]" -f $twRiskMax, $riskLevel) -ForegroundColor $riskInfo.ConsoleColor
    Write-Host ("  RED Threats     : {0} (Last Week: {1}, Delta: {2:+0;-0;0})" -f $twRed, $lwRed, $redDelta) -ForegroundColor White
    Write-Host ""
    Write-Host (Get-ASCIITrendChart -Scores $tScores -Labels $tLabels) -ForegroundColor Gray
    Write-Host "  Recommended Actions:" -ForegroundColor Yellow
    foreach ($rec in $recs) { Write-Host "    - $rec" -ForegroundColor White }
    Write-Host ""

    # ---- Auto-purge ----
    $cutoff = $now.AddDays(-$retentionDays)
    Get-ChildItem -Path $weeklyPath -Filter '*.html' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            Write-Host "  [WeeklyReport] Purged: $($_.Name)" -ForegroundColor DarkGray
        }

    if ($AuditLog) {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: WeeklyReport] [ACTION: Generate] " +
            "[DETAILS: Report='$reportFile' RiskPeak=$twRiskMax Level=$riskLevel RedThreats=$twRed Scans=$($thisWeek.Count)]"
        ) -Encoding UTF8
    }

    return $reportFile
}

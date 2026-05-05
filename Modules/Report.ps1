<#
.SYNOPSIS
    Report.ps1 - Generates a color-coded HTML security report from scan findings.
.DESCRIPTION
    Produces a self-contained HTML file (no external CDN or assets) with:
      - Executive summary cards: GREEN / YELLOW / RED counts
      - Detailed findings table with per-row color coding
      - SHA256 hashes for flagged files
      - Scan metadata: hostname, date/time, operator
      - Severity legend
    Report is saved to C:\QuietMonitor\Reports\SecurityReport_<timestamp>.html

    ThreatLocker Note: This module writes files only to C:\QuietMonitor\Reports\.
    Sign with: Set-AuthenticodeSignature .\Modules\Report.ps1 -Certificate $cert
.OUTPUTS
    [string] - Full path to the generated HTML report file.
#>

function New-SecurityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [string]$ReportPath,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }

    $timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $fileStamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostname    = $env:COMPUTERNAME
    $operator    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $reportFile  = Join-Path $ReportPath "SecurityReport_${fileStamp}.html"

    $redCount    = @($Findings | Where-Object { $_.Severity -eq 'Red'    }).Count
    $yellowCount = @($Findings | Where-Object { $_.Severity -eq 'Yellow' }).Count
    $greenCount  = @($Findings | Where-Object { $_.Severity -eq 'Green'  }).Count
    $totalCount  = $Findings.Count

    $overallStatus = if ($redCount -gt 0) { 'THREAT DETECTED' }
                     elseif ($yellowCount -gt 0) { 'SUSPICIOUS - REVIEW REQUIRED' }
                     else { 'CLEAN' }

    $overallColor = if ($redCount -gt 0) { '#dc3545' }
                    elseif ($yellowCount -gt 0) { '#ffc107' }
                    else { '#28a745' }

    # Build findings rows HTML
    $rowsHtml = [System.Text.StringBuilder]::new()
    # Sort: Red first, then Yellow, then Green
    $sortedFindings = @(
        @($Findings | Where-Object { $_.Severity -eq 'Red' })
        @($Findings | Where-Object { $_.Severity -eq 'Yellow' })
        @($Findings | Where-Object { $_.Severity -eq 'Green' })
    )

    foreach ($f in $sortedFindings) {
        $rowClass = switch ($f.Severity) {
            'Red'    { 'row-red' }
            'Yellow' { 'row-yellow' }
            'Green'  { 'row-green' }
            default  { '' }
        }
        $severityBadge = switch ($f.Severity) {
            'Red'    { '<span class="badge badge-red">&#x2716; THREAT</span>' }
            'Yellow' { '<span class="badge badge-yellow">&#x26A0; SUSPICIOUS</span>' }
            'Green'  { '<span class="badge badge-green">&#x2714; CLEAN</span>' }
            default  { $f.Severity }
        }

        $safeDetails = [System.Web.HttpUtility]::HtmlEncode($f.Detail)
        $safeName    = [System.Web.HttpUtility]::HtmlEncode($f.Title)
        $safePath    = [System.Web.HttpUtility]::HtmlEncode($f.Path)
        $safeHash    = ''
        $safeModule  = [System.Web.HttpUtility]::HtmlEncode($f.Module)
        $safeCategory= [System.Web.HttpUtility]::HtmlEncode($f.Category)
        $safeAction  = [System.Web.HttpUtility]::HtmlEncode($f.ActionTaken)
        $safeTime    = ''
        $safeMitre   = if ($f.MitreId -and $f.MitreId.Trim()) { [System.Web.HttpUtility]::HtmlEncode("$($f.MitreId): $($f.MitreName)") } else { '' }
        $mitreTechId = if ($f.MitreId -and $f.MitreId.Trim()) { $f.MitreId.Replace('.', '/') } else { '' }

        [void]$rowsHtml.AppendLine(@"
        <tr class="$rowClass">
            <td>$severityBadge</td>
            <td><code>$safeModule</code></td>
            <td>$safeCategory</td>
            <td><strong>$safeName</strong></td>
            <td class="detail-cell">$safeDetails</td>
            <td class="hash-cell"><code>$safeHash</code></td>
            <td class="path-cell"><code>$safePath</code></td>
            <td>$(if ($safeAction) { "<em>$safeAction</em>" } else { '&mdash;' })</td>
            <td class="ts-cell">$safeTime</td>
            <td class="mitre-cell">$(if ($safeMitre) { "<a href='https://attack.mitre.org/techniques/$mitreTechId/' class='mitre-link' target='_blank'>$safeMitre</a>" } else { '&mdash;' })</td>
        </tr>
"@)
    }

    # Load System.Web for HtmlEncode (built-in .NET)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # Build ATT&CK Navigator layer v4 JSON (saved alongside the HTML report)
    $navigatorFileName = "ATTACKLayer_${fileStamp}.json"
    $navigatorFile     = Join-Path $ReportPath $navigatorFileName

    $mitreFindings = @($Findings | Where-Object { $_.MitreId -and $_.MitreId.Trim() })
    $mitreGrouped  = $mitreFindings | Group-Object MitreId

    $navTechniques = @(foreach ($group in $mitreGrouped) {
        $mitreId  = $group.Name
        $count    = $group.Count
        $names    = ($group.Group | ForEach-Object { $_.Title }) -join '; '
        $hasRed   = @($group.Group | Where-Object { $_.Severity -eq 'Red' }).Count -gt 0
        $color    = if ($hasRed) { '#ff4444' } else { '#ffaa44' }
        [PSCustomObject]@{
            techniqueID           = $mitreId
            score                 = $count
            color                 = $color
            comment               = $names.Substring(0, [Math]::Min(200, $names.Length))
            enabled               = $true
            metadata              = @()
            showSubtechniques     = $false
        }
    })

    $navLayer = [ordered]@{
        name        = "QuietMonitor - $hostname - $timestamp"
        versions    = [ordered]@{ attack = '14'; navigator = '4.9'; layer = '4.5' }
        domain      = 'enterprise-attack'
        description = "ATT&CK Navigator layer generated by QuietMonitor Security Suite on $hostname at $timestamp"
        filters     = [ordered]@{ platforms = @('Windows') }
        sorting     = 3
        layout      = [ordered]@{ layout = 'side'; aggregateFunction = 'sum'; showID = $true; showName = $true; showAggregateScores = $false; countUnscored = $false }
        hideDisabled = $false
        techniques  = $navTechniques
        gradient    = [ordered]@{ colors = @('#ffffff','#ff4444'); minValue = 0; maxValue = 10 }
        legendItems = @()
        metadata    = @()
        showTacticRowBackground       = $false
        tacticRowBackground           = '#dddddd'
        selectTechniquesAcrossTactics = $true
        selectSubtechniquesWithParent = $false
    }
    $navigatorJson = $navLayer | ConvertTo-Json -Depth 10

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuietMonitor Security Report - $hostname - $timestamp</title>
    <style>
        :root {
            --bg-dark:    #0d1117;
            --bg-panel:   #161b22;
            --bg-table:   #1c2128;
            --border:     #30363d;
            --text-main:  #c9d1d9;
            --text-muted: #8b949e;
            --red:        #da3633;
            --red-dim:    rgba(218,54,51,0.15);
            --yellow:     #d29922;
            --yellow-dim: rgba(210,153,34,0.15);
            --green:      #3fb950;
            --green-dim:  rgba(63,185,80,0.12);
            --blue:       #58a6ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, monospace;
            background: var(--bg-dark);
            color: var(--text-main);
            font-size: 13px;
            line-height: 1.5;
        }
        header {
            background: var(--bg-panel);
            border-bottom: 1px solid var(--border);
            padding: 24px 32px;
        }
        header h1 { font-size: 22px; font-weight: 700; color: var(--blue); letter-spacing: 0.5px; }
        header .meta { margin-top: 8px; color: var(--text-muted); font-size: 12px; }
        header .meta span { margin-right: 24px; }
        .overall-status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 14px;
            background: $overallColor;
            color: #fff;
            margin-top: 12px;
        }
        .container { padding: 24px 32px; max-width: 1600px; }
        /* Summary cards */
        .summary-row {
            display: flex;
            gap: 16px;
            margin-bottom: 28px;
            flex-wrap: wrap;
        }
        .card {
            flex: 1;
            min-width: 160px;
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px 24px;
            text-align: center;
        }
        .card-count { font-size: 40px; font-weight: 700; line-height: 1; }
        .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; color: var(--text-muted); }
        .card-red    { border-color: var(--red);    background: rgba(218,54,51,0.08); }
        .card-yellow { border-color: var(--yellow); background: rgba(210,153,34,0.08); }
        .card-green  { border-color: var(--green);  background: rgba(63,185,80,0.08); }
        .card-total  { border-color: var(--blue);   background: rgba(88,166,255,0.06); }
        .card-red    .card-count { color: var(--red); }
        .card-yellow .card-count { color: var(--yellow); }
        .card-green  .card-count { color: var(--green); }
        .card-total  .card-count { color: var(--blue); }
        /* Table */
        .section-title {
            font-size: 15px;
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text-main);
            border-left: 3px solid var(--blue);
            padding-left: 10px;
        }
        .table-wrap {
            overflow-x: auto;
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        table { width: 100%; border-collapse: collapse; }
        thead tr { background: var(--bg-table); }
        th {
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        tr:last-child td { border-bottom: none; }
        tr.row-red    { background: var(--red-dim); }
        tr.row-yellow { background: var(--yellow-dim); }
        tr.row-green  { background: var(--green-dim); }
        tr:hover { filter: brightness(1.08); }
        .detail-cell { max-width: 320px; word-wrap: break-word; white-space: normal; }
        .hash-cell   { max-width: 200px; word-break: break-all; color: var(--text-muted); font-size: 11px; }
        .path-cell   { max-width: 240px; word-break: break-all; color: var(--text-muted); font-size: 11px; }
        .ts-cell     { white-space: nowrap; color: var(--text-muted); font-size: 11px; }
        .mitre-cell  { white-space: nowrap; font-size: 11px; }
        .mitre-link  { color: var(--blue); text-decoration: none; }
        .mitre-link:hover { text-decoration: underline; }
        code { font-family: 'Consolas', 'Courier New', monospace; font-size: 11px; }
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }
        .badge-red    { background: var(--red);    color: #fff; }
        .badge-yellow { background: var(--yellow); color: #000; }
        .badge-green  { background: var(--green);  color: #000; }
        footer {
            margin-top: 40px;
            padding: 16px 32px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 11px;
        }
        .legend {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }
        .legend-title { font-weight: 600; margin-bottom: 8px; }
        .legend-items { display: flex; gap: 24px; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
    </style>
</head>
<body>
<header>
    <h1>&#x1F6E1; QuietMonitor Security Suite Report</h1>
    <div class="meta">
        <span>&#x1F4BB; <strong>Host:</strong> $hostname</span>
        <span>&#x1F552; <strong>Scan Time:</strong> $timestamp</span>
        <span>&#x1F464; <strong>Operator:</strong> $operator</span>
    </div>
    <div class="overall-status">$overallStatus</div>
</header>

<div class="container">

    <!-- Summary Cards -->
    <div class="summary-row">
        <div class="card card-red">
            <div class="card-count">$redCount</div>
            <div class="card-label">&#x2716; Threats (RED)</div>
        </div>
        <div class="card card-yellow">
            <div class="card-count">$yellowCount</div>
            <div class="card-label">&#x26A0; Suspicious (YELLOW)</div>
        </div>
        <div class="card card-green">
            <div class="card-count">$greenCount</div>
            <div class="card-label">&#x2714; Clean (GREEN)</div>
        </div>
        <div class="card card-total">
            <div class="card-count">$totalCount</div>
            <div class="card-label">Total Findings</div>
        </div>
    </div>

    <!-- Legend -->
    <div class="legend">
        <div class="legend-title">Severity Legend</div>
        <div class="legend-items">
            <div class="legend-item"><span class="badge badge-red">&#x2716; THREAT</span> Confirmed threat or critical indicator - action required</div>
            <div class="legend-item"><span class="badge badge-yellow">&#x26A0; SUSPICIOUS</span> Requires manual review - may be legitimate</div>
            <div class="legend-item"><span class="badge badge-green">&#x2714; CLEAN</span> Whitelisted or no anomalies detected</div>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="section-title">Detailed Findings</div>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Module</th>
                    <th>Category</th>
                    <th>Name / Identifier</th>
                    <th>Details</th>
                    <th>SHA256 Hash</th>
                    <th>Path</th>
                    <th>Action Taken</th>
                    <th>Timestamp</th>
                    <th>MITRE ATT&amp;CK</th>
                </tr>
            </thead>
            <tbody>
                $($rowsHtml.ToString())
            </tbody>
        </table>
    </div>

</div>

<footer>
    Generated by QuietMonitor Security Suite &bull; $timestamp &bull;
    Report: $reportFile &bull;
    Audit log: $AuditLog &bull;
    <a href='$navigatorFileName' class='mitre-link' target='_blank'>&#128506; ATT&amp;CK Navigator Layer ($navigatorFileName)</a>
</footer>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($reportFile, $html, [System.Text.Encoding]::UTF8)

    # Save ATT&CK Navigator layer JSON
    if ($navigatorJson) {
        [System.IO.File]::WriteAllText($navigatorFile, $navigatorJson, [System.Text.Encoding]::UTF8)
    }

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
        "[MODULE: Report] [ACTION: GenerateReport] " +
        "[DETAILS: Report='$reportFile' Findings: RED=$redCount YELLOW=$yellowCount GREEN=$greenCount]"
    ) -Encoding UTF8

    return $reportFile
}

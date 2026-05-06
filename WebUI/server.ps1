<#
.SYNOPSIS
    server.ps1 - Lightweight PowerShell HTTP listener for the QuietMonitor WebUI.
.DESCRIPTION
    Listens on http://localhost:8080 and provides:
      GET  /api/scan            -> latest_scan.json
      GET  /api/history         -> scan_history.json
      GET  /api/quarantine      -> quarantine_manifest.json
      GET  /api/log?lines=N     -> last N lines of audit.log
      GET  /api/status          -> QuietMonitor service status via NSSM
      POST /api/scan/run        -> triggers Run-SecuritySuite.ps1 -ScanOnly as background job
      POST /api/quarantine      -> quarantine a file by path
      POST /api/quarantine/restore -> restore quarantined item by index
      POST /api/quarantine/delete  -> permanently delete quarantined item by index
      GET  /                    -> serves WebUI\index.html
      GET  /static/<file>       -> serves files from WebUI\

    Run:  PowerShell -ExecutionPolicy Bypass -File "C:\QuietMonitor\WebUI\server.ps1"
    Stop: Ctrl+C or close the window.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Paths ──────────────────────────────────────────────────────
$base         = 'C:\QuietMonitor'
$webUIDir     = Join-Path $base 'WebUI'
$latestScan   = Join-Path $base 'Reports\latest_scan.json'
$historyFile  = Join-Path $base 'Reports\scan_history.json'
$quarManifest = Join-Path $base 'Quarantine\quarantine_manifest.json'
$auditLog     = Join-Path $base 'Logs\audit.log'
$nssmExe      = Join-Path $base 'Tools\nssm.exe'
$svcName      = 'QuietMonitorSvc'
$suiteScript  = Join-Path $base 'Run-SecuritySuite.ps1'
$quarDir      = Join-Path $base 'Quarantine'

$prefix = 'http://localhost:8080/'

# ── MIME types ────────────────────────────────────────────────
$mimeMap = @{
    '.html' = 'text/html; charset=utf-8'
    '.css'  = 'text/css'
    '.js'   = 'application/javascript'
    '.json' = 'application/json; charset=utf-8'
    '.ico'  = 'image/x-icon'
    '.png'  = 'image/png'
    '.svg'  = 'image/svg+xml'
    '.txt'  = 'text/plain; charset=utf-8'
}

# ── Helper: send response ──────────────────────────────────────
function Send-Response {
    param(
        [System.Net.HttpListenerResponse]$Resp,
        [string]$Body,
        [int]$Status = 200,
        [string]$ContentType = 'application/json; charset=utf-8'
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Resp.StatusCode        = $Status
    $Resp.ContentType       = $ContentType
    $Resp.ContentLength64   = $bytes.Length
    $Resp.Headers.Add('Access-Control-Allow-Origin',  '*')
    $Resp.Headers.Add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    $Resp.Headers.Add('Access-Control-Allow-Headers', 'Content-Type')
    $Resp.OutputStream.Write($bytes, 0, $bytes.Length)
    $Resp.OutputStream.Close()
}

function Send-Error {
    param([System.Net.HttpListenerResponse]$Resp, [int]$Code, [string]$Msg)
    Send-Response -Resp $Resp -Status $Code -Body "{`"error`":`"$Msg`"}"
}

function Send-File {
    param([System.Net.HttpListenerResponse]$Resp, [string]$Path)
    $ext   = [System.IO.Path]::GetExtension($Path).ToLower()
    $mime  = if ($mimeMap.ContainsKey($ext)) { $mimeMap[$ext] } else { 'application/octet-stream' }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $Resp.StatusCode      = 200
    $Resp.ContentType     = $mime
    $Resp.ContentLength64 = $bytes.Length
    $Resp.Headers.Add('Access-Control-Allow-Origin', '*')
    $Resp.OutputStream.Write($bytes, 0, $bytes.Length)
    $Resp.OutputStream.Close()
}

function Read-Body {
    param([System.Net.HttpListenerRequest]$Req)
    if (-not $Req.HasEntityBody) { return $null }
    $reader = [System.IO.StreamReader]::new($Req.InputStream, $Req.ContentEncoding)
    $body   = $reader.ReadToEnd()
    $reader.Close()
    return $body
}

function Get-ServiceStatus {
    if (Test-Path $nssmExe) {
        try {
            $out = & $nssmExe status $svcName 2>&1
            return ($out -join '').Trim()
        } catch { }
    }
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) { return $svc.Status.ToString() }
    } catch { }
    return 'Unknown'
}

# ── Quarantine helpers ─────────────────────────────────────────
function Read-QuarantineManifest {
    if (-not (Test-Path $quarManifest)) { return @() }
    try {
        $raw = Get-Content $quarManifest -Raw -Encoding UTF8
        $parsed = $raw | ConvertFrom-Json
        return if ($parsed -is [array]) { $parsed } else { @($parsed) }
    } catch { return @() }
}

function Save-QuarantineManifest {
    param($Items)
    $json = $Items | ConvertTo-Json -Depth 5
    Set-Content $quarManifest -Value $json -Encoding UTF8
}

# ── Start listener ─────────────────────────────────────────────
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
try {
    $listener.Start()
} catch {
    Write-Host "ERROR: Could not start HTTP listener on $prefix" -ForegroundColor Red
    Write-Host "  Is another process already using port 8080?" -ForegroundColor Yellow
    Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkGray
    exit 1
}

Write-Host ""
Write-Host "  QuietMonitor WebUI Server" -ForegroundColor Cyan
Write-Host "  Listening on: http://localhost:8080" -ForegroundColor Green
Write-Host "  Open browser: http://localhost:8080" -ForegroundColor White
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

try {
    while ($listener.IsListening) {
        $ctx  = $listener.GetContext()
        $req  = $ctx.Request
        $resp = $ctx.Response
        $url  = $req.Url.LocalPath.TrimEnd('/')
        $meth = $req.HttpMethod

        Write-Host "  [$meth] $url" -ForegroundColor DarkGray

        # OPTIONS pre-flight (CORS)
        if ($meth -eq 'OPTIONS') {
            $resp.StatusCode = 204
            $resp.Headers.Add('Access-Control-Allow-Origin', '*')
            $resp.Headers.Add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            $resp.Headers.Add('Access-Control-Allow-Headers', 'Content-Type')
            $resp.OutputStream.Close()
            continue
        }

        # ── GET /api/scan ──────────────────────────────────────
        if ($meth -eq 'GET' -and $url -eq '/api/scan') {
            if (Test-Path $latestScan) {
                $json = Get-Content $latestScan -Raw -Encoding UTF8
                Send-Response -Resp $resp -Body $json
            } else {
                Send-Response -Resp $resp -Status 404 -Body '{"error":"No scan data found. Run a scan first."}'
            }
            continue
        }

        # ── GET /api/history ──────────────────────────────────
        if ($meth -eq 'GET' -and $url -eq '/api/history') {
            if (Test-Path $historyFile) {
                $json = Get-Content $historyFile -Raw -Encoding UTF8
                Send-Response -Resp $resp -Body $json
            } else {
                Send-Response -Resp $resp -Body '[]'
            }
            continue
        }

        # ── GET /api/quarantine ───────────────────────────────
        if ($meth -eq 'GET' -and $url -eq '/api/quarantine') {
            $items = Read-QuarantineManifest
            Send-Response -Resp $resp -Body ($items | ConvertTo-Json -Depth 5)
            continue
        }

        # ── GET /api/log ──────────────────────────────────────
        if ($meth -eq 'GET' -and $url -eq '/api/log') {
            $lines = 200
            $qs = $req.QueryString
            if ($qs['lines']) { try { $lines = [int]$qs['lines'] } catch { } }
            $lines = [Math]::Max(10, [Math]::Min($lines, 5000))
            if (Test-Path $auditLog) {
                $content = Get-Content $auditLog -Encoding UTF8 -ErrorAction SilentlyContinue
                if ($null -eq $content) { $content = @() }
                $arr = @($content)
                $tail = if ($arr.Count -le $lines) { $arr } else { $arr[($arr.Count - $lines)..($arr.Count - 1)] }
                $text = $tail -join "`n"
                Send-Response -Resp $resp -Body $text -ContentType 'text/plain; charset=utf-8'
            } else {
                Send-Response -Resp $resp -Body '' -ContentType 'text/plain; charset=utf-8'
            }
            continue
        }

        # ── GET /api/status ───────────────────────────────────
        if ($meth -eq 'GET' -and $url -eq '/api/status') {
            $status = Get-ServiceStatus
            $json = "{`"service`":`"$svcName`",`"status`":`"$status`"}"
            Send-Response -Resp $resp -Body $json
            continue
        }

        # ── POST /api/scan/run ────────────────────────────────
        if ($meth -eq 'POST' -and $url -eq '/api/scan/run') {
            if (Test-Path $suiteScript) {
                $null = Start-Job -ScriptBlock {
                    param($script)
                    & powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File $script -ScanOnly
                } -ArgumentList $suiteScript
                Send-Response -Resp $resp -Body '{"status":"started","message":"Scan job launched in background."}'
            } else {
                Send-Error -Resp $resp -Code 404 -Msg 'Run-SecuritySuite.ps1 not found'
            }
            continue
        }

        # ── POST /api/quarantine (quarantine a file) ──────────
        if ($meth -eq 'POST' -and $url -eq '/api/quarantine') {
            $body = Read-Body -Req $req
            try {
                $data = $body | ConvertFrom-Json
                $path = $data.path
                if (-not $path -or -not (Test-Path $path)) {
                    Send-Error -Resp $resp -Code 400 -Msg 'File not found'
                    continue
                }
                if (-not (Test-Path $quarDir)) { New-Item -ItemType Directory -Path $quarDir -Force | Out-Null }
                $sha256 = (Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $qName  = [System.IO.Path]::GetFileName($path) + '.quarantine'
                $qDest  = Join-Path $quarDir $qName
                Move-Item -Path $path -Destination $qDest -Force
                $items = Read-QuarantineManifest
                $items += [PSCustomObject]@{
                    OriginalPath  = $path
                    QuarantinePath= $qDest
                    SHA256        = $sha256
                    Reason        = 'Manual via WebUI'
                    QuarantineDate= (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Status        = 'Quarantined'
                }
                Save-QuarantineManifest -Items $items
                Send-Response -Resp $resp -Body '{"status":"quarantined"}'
            } catch {
                Send-Error -Resp $resp -Code 500 -Msg $_.Exception.Message
            }
            continue
        }

        # ── POST /api/quarantine/restore ──────────────────────
        if ($meth -eq 'POST' -and $url -eq '/api/quarantine/restore') {
            $body = Read-Body -Req $req
            try {
                $data  = $body | ConvertFrom-Json
                $index = [int]$data.index
                $items = @(Read-QuarantineManifest)
                if ($index -lt 0 -or $index -ge $items.Count) {
                    Send-Error -Resp $resp -Code 404 -Msg 'Item not found'; continue
                }
                $item = $items[$index]
                $qPath = $item.QuarantinePath
                $orig  = $item.OriginalPath
                if (Test-Path $qPath) {
                    $destDir = Split-Path $orig -Parent
                    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                    Move-Item -Path $qPath -Destination $orig -Force
                }
                # Remove from manifest
                $newItems = @($items | Where-Object { $_ -ne $item })
                Save-QuarantineManifest -Items $newItems
                Send-Response -Resp $resp -Body '{"status":"restored"}'
            } catch {
                Send-Error -Resp $resp -Code 500 -Msg $_.Exception.Message
            }
            continue
        }

        # ── POST /api/quarantine/delete ───────────────────────
        if ($meth -eq 'POST' -and $url -eq '/api/quarantine/delete') {
            $body = Read-Body -Req $req
            try {
                $data  = $body | ConvertFrom-Json
                $index = [int]$data.index
                $items = @(Read-QuarantineManifest)
                if ($index -lt 0 -or $index -ge $items.Count) {
                    Send-Error -Resp $resp -Code 404 -Msg 'Item not found'; continue
                }
                $item = $items[$index]
                $qPath = $item.QuarantinePath
                if (Test-Path $qPath) { Remove-Item $qPath -Force }
                $newItems = @($items | Where-Object { $_ -ne $item })
                Save-QuarantineManifest -Items $newItems
                Send-Response -Resp $resp -Body '{"status":"deleted"}'
            } catch {
                Send-Error -Resp $resp -Code 500 -Msg $_.Exception.Message
            }
            continue
        }

        # ── GET / or /index.html ──────────────────────────────
        if ($meth -eq 'GET' -and ($url -eq '' -or $url -eq '/' -or $url -eq '/index.html')) {
            $htmlPath = Join-Path $webUIDir 'index.html'
            if (Test-Path $htmlPath) {
                Send-File -Resp $resp -Path $htmlPath
            } else {
                Send-Error -Resp $resp -Code 404 -Msg 'index.html not found'
            }
            continue
        }

        # ── GET static files ──────────────────────────────────
        if ($meth -eq 'GET') {
            $rel = $url.TrimStart('/')
            # Security: prevent path traversal
            if ($rel -match '\.\.' -or $rel -match '[:\\]') {
                Send-Error -Resp $resp -Code 403 -Msg 'Forbidden'
                continue
            }
            $filePath = Join-Path $webUIDir $rel
            if (Test-Path $filePath -PathType Leaf) {
                Send-File -Resp $resp -Path $filePath
            } else {
                Send-Error -Resp $resp -Code 404 -Msg "Not found: $rel"
            }
            continue
        }

        # ── Fallback ──────────────────────────────────────────
        Send-Error -Resp $resp -Code 405 -Msg 'Method not allowed'
    }
}
catch [System.Net.HttpListenerException] {
    # Normal shutdown (Ctrl+C)
}
finally {
    if ($listener.IsListening) { $listener.Stop() }
    $listener.Close()
    Write-Host "`n  Server stopped." -ForegroundColor DarkGray
}

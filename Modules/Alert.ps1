<#
.SYNOPSIS
    Alert.ps1 - Sends security alerts via email, Windows Event Log, and optional webhook.
.DESCRIPTION
    Three alert channels are supported (all configurable in Config\settings.json):
      1. Email via .NET SmtpClient (supports modern TLS better than Send-MailMessage)
      2. Windows Event Log (custom source "QuietMonitor" in Application log)
      3. HTTP POST webhook for integration with dashboards (optional)

    All channels are attempted independently - failure of one does not block others.
    Alert content includes findings summary, severity counts, and top threat details.

    ThreatLocker Note: This module sends network traffic (SMTP/HTTP). Ensure your
    ThreatLocker policy permits outbound connections on the configured SMTP port
    and webhook URL if used.
    Sign with: Set-AuthenticodeSignature .\Modules\Alert.ps1 -Certificate $cert
.OUTPUTS
    None. Writes results to console and audit log.
#>

function Send-SecurityAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [Parameter(Mandatory)]
        [PSCustomObject]$Settings,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $currentUser   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $hostname      = $env:COMPUTERNAME
    $timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $redFindings   = @($Findings | Where-Object { $_.Severity -eq 'Red' })
    $yellowFindings= @($Findings | Where-Object { $_.Severity -eq 'Yellow' })

    $alertSummary  = "QuietMonitor Alert | Host: $hostname | RED: $($redFindings.Count) | YELLOW: $($yellowFindings.Count) | Time: $timestamp"

    # Build human-readable findings text for email/webhook body
    $findingsText = [System.Text.StringBuilder]::new()
    [void]$findingsText.AppendLine("=== Threat Findings - $hostname ===")
    [void]$findingsText.AppendLine("Scan Time : $timestamp")
    [void]$findingsText.AppendLine("Operator  : $currentUser")
    [void]$findingsText.AppendLine("")
    [void]$findingsText.AppendLine("[ RED - $($redFindings.Count) THREAT(S) ]")
    foreach ($f in $redFindings) {
        [void]$findingsText.AppendLine("  Module  : $($f.Module)")
        [void]$findingsText.AppendLine("  Name    : $($f.Title)")
        [void]$findingsText.AppendLine("  Details : $($f.Detail)")
        if ($f.Path)  { [void]$findingsText.AppendLine("  Path    : $($f.Path)") }
        [void]$findingsText.AppendLine("")
    }
    [void]$findingsText.AppendLine("[ YELLOW - $($yellowFindings.Count) SUSPICIOUS ]")
    foreach ($f in $yellowFindings) {
        [void]$findingsText.AppendLine("  [$($f.Module)] $($f.Title): $($f.Detail)")
    }

    $bodyText = $findingsText.ToString()

    # -----------------------------------------------------------------------
    # Channel 1: Windows Event Log
    # -----------------------------------------------------------------------
    try {
        $evtSource  = $Settings.EventLog.Source
        $evtLogName = $Settings.EventLog.LogName

        # Create the custom event source if it doesn't exist
        if (-not [System.Diagnostics.EventLog]::SourceExists($evtSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($evtSource, $evtLogName)
        }

        # Determine event type based on highest severity
        $evtType  = if ($redFindings.Count -gt 0) {
            [System.Diagnostics.EventLogEntryType]::Error
        } elseif ($yellowFindings.Count -gt 0) {
            [System.Diagnostics.EventLogEntryType]::Warning
        } else {
            [System.Diagnostics.EventLogEntryType]::Information
        }

        $evtId = if ($redFindings.Count -gt 0) { 1001 } elseif ($yellowFindings.Count -gt 0) { 1002 } else { 1000 }

        # Truncate to 31,839 chars (Event Log message limit)
        $evtMsg = if ($bodyText.Length -gt 31000) { $bodyText.Substring(0, 31000) + "`n[...truncated]" } else { $bodyText }

        Write-EventLog -LogName $evtLogName -Source $evtSource -EntryType $evtType `
            -EventId $evtId -Message $evtMsg

        Write-Host "    [+] Alert written to Windows Event Log ($evtLogName / $evtSource, ID: $evtId)" -ForegroundColor Green

        Add-Content -Path $AuditLog -Value (
            "[$timestamp] [USER: $currentUser] [MODULE: Alert] [ACTION: EventLogWrite] " +
            "[DETAILS: EventID=$evtId Type=$evtType Source=$evtSource]"
        ) -Encoding UTF8
    } catch {
        Write-Warning "    Event log alert failed: $($_.Exception.Message)"
    }

    # -----------------------------------------------------------------------
    # Channel 2: Email via .NET SmtpClient
    # -----------------------------------------------------------------------
    $smtpCfg = $Settings.SMTP
    if ($smtpCfg.Server -and $smtpCfg.Server -ne 'smtp.yourdomain.com' -and
        $smtpCfg.From -and $smtpCfg.To) {
        try {
            $smtp = New-Object System.Net.Mail.SmtpClient($smtpCfg.Server, $smtpCfg.Port)
            $smtp.EnableSsl          = [bool]$smtpCfg.UseSsl
            $smtp.DeliveryMethod     = [System.Net.Mail.SmtpDeliveryMethod]::Network
            $smtp.UseDefaultCredentials = $false

            if ($smtpCfg.Username -and $smtpCfg.Username -ne '') {
                if ($smtpCfg.PasswordEncrypted -and $smtpCfg.PasswordEncrypted -ne '') {
                    # Decrypt DPAPI-protected password (machine-specific)
                    $securePass = ConvertTo-SecureString -String $smtpCfg.PasswordEncrypted -ErrorAction SilentlyContinue
                    if ($securePass) {
                        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
                        $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                        $smtp.Credentials = New-Object System.Net.NetworkCredential($smtpCfg.Username, $plainPass)
                        $plainPass = $null
                    }
                }
            }

            $mailMsg            = New-Object System.Net.Mail.MailMessage
            $mailMsg.From       = $smtpCfg.From
            $mailMsg.To.Add($smtpCfg.To)
            $mailMsg.Subject    = "[QuietMonitor] Security Alert - $hostname - RED:$($redFindings.Count) YELLOW:$($yellowFindings.Count)"
            $mailMsg.Body       = $bodyText
            $mailMsg.IsBodyHtml = $false
            $mailMsg.Priority   = if ($redFindings.Count -gt 0) {
                [System.Net.Mail.MailPriority]::High
            } else {
                [System.Net.Mail.MailPriority]::Normal
            }

            $smtp.Send($mailMsg)
            $smtp.Dispose()
            $mailMsg.Dispose()

            Write-Host "    [+] Email alert sent to $($smtpCfg.To)" -ForegroundColor Green
            Add-Content -Path $AuditLog -Value (
                "[$timestamp] [USER: $currentUser] [MODULE: Alert] [ACTION: EmailSent] " +
                "[DETAILS: To=$($smtpCfg.To) Server=$($smtpCfg.Server)]"
            ) -Encoding UTF8
        } catch {
            Write-Warning "    Email alert failed: $($_.Exception.Message)"
            Add-Content -Path $AuditLog -Value (
                "[$timestamp] [USER: $currentUser] [MODULE: Alert] [ACTION: EmailFailed] " +
                "[DETAILS: $($_.Exception.Message)]"
            ) -Encoding UTF8
        }
    } else {
        Write-Host "    [i] Email alert skipped - SMTP not configured in settings.json" -ForegroundColor Gray
    }

    # -----------------------------------------------------------------------
    # Channel 3: Webhook (HTTP POST)
    # -----------------------------------------------------------------------
    $webhookCfg = $Settings.Webhook
    if ($webhookCfg.Enabled -eq $true -and $webhookCfg.Url -and $webhookCfg.Url -ne '') {
        try {
            $payload = [PSCustomObject]@{
                hostname    = $hostname
                timestamp   = $timestamp
                operator    = $currentUser
                severity    = if ($redFindings.Count -gt 0) { 'red' } else { 'yellow' }
                redCount    = $redFindings.Count
                yellowCount = $yellowFindings.Count
                summary     = $alertSummary
                findings    = @($Findings | Where-Object { $_.Severity -in 'Red','Yellow' } | Select-Object Module, Severity, Category, Title, Detail, Path)
            }

            $jsonBody = $payload | ConvertTo-Json -Depth 5 -Compress

            $headers = @{ 'Content-Type' = 'application/json' }
            if ($webhookCfg.AuthHeader -and $webhookCfg.AuthHeader -ne '') {
                $headers['Authorization'] = $webhookCfg.AuthHeader
            }

            $response = Invoke-RestMethod -Method POST -Uri $webhookCfg.Url `
                -Body $jsonBody -Headers $headers -TimeoutSec 15 -ErrorAction Stop

            Write-Host "    [+] Webhook POST sent to $($webhookCfg.Url)" -ForegroundColor Green
            Add-Content -Path $AuditLog -Value (
                "[$timestamp] [USER: $currentUser] [MODULE: Alert] [ACTION: WebhookSent] " +
                "[DETAILS: URL=$($webhookCfg.Url)]"
            ) -Encoding UTF8
        } catch {
            Write-Warning "    Webhook alert failed: $($_.Exception.Message)"
            Add-Content -Path $AuditLog -Value (
                "[$timestamp] [USER: $currentUser] [MODULE: Alert] [ACTION: WebhookFailed] " +
                "[DETAILS: $($_.Exception.Message)]"
            ) -Encoding UTF8
        }
    }
}

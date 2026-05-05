<#
.SYNOPSIS
    TaskAudit.ps1 - Audits scheduled tasks for non-Microsoft and suspicious entries.
.DESCRIPTION
    Enumerates all scheduled tasks, filters out tasks authored by Microsoft or located
    in standard Windows paths, and flags tasks with suspicious execution paths such as
    temp directories, encoded commands, LOLBin wrappers, or missing/unsigned executables.

    ThreatLocker Note: This module is read-only. No system modifications are made.
    Sign with: Set-AuthenticodeSignature .\Modules\TaskAudit.ps1 -Certificate $cert
.OUTPUTS
    [System.Collections.Generic.List[PSCustomObject]] - List of finding objects.
#>

function Invoke-TaskAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Patterns indicating high-risk task action paths
    $suspiciousPathPatterns = @(
        '\\temp\\', '\\tmp\\', '\\appdata\\roaming\\', '\\appdata\\local\\temp\\',
        '\\downloads\\', '\\desktop\\', '\\public\\', '\\recycle',
        '%temp%', '%appdata%', '%localappdata%'
    )

    $lolbins = @(
        'cmd\.exe', 'powershell\.exe', 'pwsh\.exe', 'wscript\.exe', 'cscript\.exe',
        'mshta\.exe', 'regsvr32\.exe', 'rundll32\.exe', 'msiexec\.exe', 'wmic\.exe',
        'certutil\.exe', 'bitsadmin\.exe', 'msbuild\.exe', 'installutil\.exe',
        'regasm\.exe', 'regsvcs\.exe', 'cmstp\.exe', 'xwizard\.exe', 'forfiles\.exe',
        'pcalua\.exe', 'bash\.exe', 'scriptrunner\.exe'
    )

    # Encoded command flag patterns
    $encodedPatterns = @(
        '-[Ee]nc(odedcommand)?', '-[Ee]c ', 'FromBase64String', 'iex\s*\(', 'invoke-expression'
    )

    try {
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

        $nonMicrosoftTasks  = 0
        $suspiciousCount    = 0

        foreach ($task in $allTasks) {
            $taskPath    = $task.TaskPath
            $taskName    = $task.TaskName
            $taskAuthor  = ''
            $taskDescription = ''
            try {
                $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                $taskAuthor      = $task.Principal.UserId
                $taskDescription = $task.Description
            } catch {}

            # Try to get author from XML
            $xmlAuthor = ''
            try {
                $xml = [xml]($task | Export-ScheduledTask -ErrorAction SilentlyContinue)
                $xmlAuthor = $xml.Task.RegistrationInfo.Author
            } catch {}

            $effectiveAuthor = if ($xmlAuthor) { $xmlAuthor } else { $taskAuthor }

            # Skip Microsoft tasks in standard paths
            $isMicrosoftPath   = $taskPath -match '^\\Microsoft\\'
            $isMicrosoftAuthor = $effectiveAuthor -match 'Microsoft'

            if ($isMicrosoftPath -and $isMicrosoftAuthor) { continue }

            # Also skip if task path is in trusted task paths whitelist
            $isTrustedPath = $false
            foreach ($trusted in $Whitelist.TrustedTaskPaths) {
                # Check each action's Execute path
                foreach ($action in $task.Actions) {
                    $actExec = try { $action.Execute } catch { $null }
                    if ($actExec -and $actExec.StartsWith($trusted, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $isTrustedPath = $true
                        break
                    }
                }
                if ($isTrustedPath) { break }
            }

            $nonMicrosoftTasks++

            # Analyze each action in the task
            foreach ($action in $task.Actions) {
                $actionType = $action.CimClass.CimClassName
                $execPath   = ''
                $arguments  = ''

                if ($actionType -eq 'MSFT_TaskExecAction') {
                    $execPath  = $action.Execute
                    $arguments = $action.Arguments
                } elseif ($actionType -eq 'MSFT_TaskComHandlerAction') {
                    $execPath = "COM Handler: $($action.ClassId)"
                }

                $sha256      = 'N/A'
                $fullExePath = $execPath
                # Resolve environment variables
                try { $fullExePath = [System.Environment]::ExpandEnvironmentVariables($execPath) } catch {}

                if ($fullExePath -and (Test-Path $fullExePath -ErrorAction SilentlyContinue)) {
                    try { $sha256 = (Get-FileHash -Path $fullExePath -Algorithm SHA256).Hash }
                    catch { $sha256 = 'HashError' }
                }

                $severity = 'Yellow'
                $details  = "Non-Microsoft scheduled task. Author: '$effectiveAuthor'. Path: $taskPath$taskName"

                if ($isTrustedPath) {
                    $severity = 'Yellow'
                    $details  = "Non-Microsoft task with trusted executable path. Review manually. Author: '$effectiveAuthor'"
                }

                # Escalate to Red on suspicious path
                $execLower = ($execPath + ' ' + $arguments).ToLower()
                foreach ($pat in $suspiciousPathPatterns) {
                    if ($execLower -match [regex]::Escape($pat)) {
                        $severity = 'Red'
                        $details  = "Task executes from suspicious path: $execPath $arguments"
                        break
                    }
                }

                # Escalate to Red on LOLBin with suspicious arguments
                if ($severity -ne 'Red') {
                    foreach ($lol in $lolbins) {
                        if ($execLower -match $lol) {
                            # LOLBin tasks with non-empty arguments are suspicious
                            if ($arguments -and $arguments.Trim() -ne '') {
                                $severity = 'Red'
                                $details  = "Task uses LOLBin ($($execPath | Split-Path -Leaf)) with arguments: $arguments"
                            }
                            break
                        }
                    }
                }

                # Escalate to Red on encoded/obfuscated commands
                if ($severity -ne 'Red') {
                    foreach ($enc in $encodedPatterns) {
                        if ($execLower -match $enc -or ($arguments -and $arguments.ToLower() -match $enc)) {
                            $severity = 'Red'
                            $details  = "Task contains encoded/obfuscated command: $arguments"
                            break
                        }
                    }
                }

                if ($severity -eq 'Red') { $suspiciousCount++ }

                $findings.Add([PSCustomObject]@{
                    Module      = 'TaskAudit'
                    Severity    = $severity
                    Category    = 'Scheduled Task'
                    Title       = $taskName
                    Path        = $fullExePath
                    Detail          = $details
                    MitreId     = 'T1053.005'
                    MitreName   = 'Scheduled Task/Job: Scheduled Task'
                    ActionTaken = ''
                })
            }
        }

        if ($nonMicrosoftTasks -eq 0) {
            $findings.Add([PSCustomObject]@{
                Module      = 'TaskAudit'
                Severity    = 'Green'
                Category    = 'Scheduled Task'
                Title       = 'Task Audit'
                Path        = ''
                Detail          = "All $($allTasks.Count) scheduled tasks are Microsoft-signed or trusted."
                MitreId     = 'T1053.005'
                MitreName   = 'Scheduled Task/Job: Scheduled Task'
                ActionTaken = ''
            })
        }

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: TaskAudit] [ACTION: Scan] " +
            "[DETAILS: Total tasks: $($allTasks.Count); Non-Microsoft: $nonMicrosoftTasks; Suspicious/Red: $suspiciousCount]"
        ) -Encoding UTF8

    } catch {
        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [MODULE: TaskAudit] [STATUS: ERROR] [DETAILS: $($_.Exception.Message)]"
        ) -Encoding UTF8
        throw
    }

    return $findings
}

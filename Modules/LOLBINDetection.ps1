<#
.SYNOPSIS
    LOLBINDetection.ps1 - Detects Living-off-the-Land Binary abuse via parent-child process analysis.
.DESCRIPTION
    Identifies known LOLBins (certutil, mshta, regsvr32, rundll32, wscript, cscript,
    powershell, cmd, msiexec, bitsadmin, installutil, regasm, regsvcs, odbcconf,
    ieexec, appsync, msbuild, cmstp, xwizard, syncappvpublishingserver) running with
    suspicious parent processes, suspicious command-line arguments, or from non-standard
    paths.

    Detection approach:
      1. Enumerate all processes via WMI Win32_Process to get full command-line + parent PID
      2. For each known LOLBin found, check:
         - Parent process: is it a known-bad spawner (Office apps, browsers, etc.)?
         - Command-line: does it contain encoded/obfuscated payloads?
         - Execution path: is it from a non-standard location (not System32/SysWOW64)?
      3. Flag with appropriate severity and MITRE tag

    MITRE ATT&CK:
      T1218 - Signed Binary Proxy Execution
      T1059 - Command and Scripting Interpreter
      T1036 - Masquerading

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-LOLBINDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Known LOLBins to watch -------------------------------------------------
    # Key = executable name (lower), Value = MITRE technique + description
    $lolbins = @{
        'certutil.exe'      = @{ Mitre = 'T1218'; Desc = 'CertUtil can download files, decode base64, and install certificates' }
        'mshta.exe'         = @{ Mitre = 'T1218'; Desc = 'MSHTA executes HTA files - commonly abused for script execution' }
        'regsvr32.exe'      = @{ Mitre = 'T1218'; Desc = 'RegSvr32 can bypass AppLocker and execute remote COM scriptlets' }
        'rundll32.exe'      = @{ Mitre = 'T1218'; Desc = 'RunDLL32 executes DLL exports - abused for code execution' }
        'wscript.exe'       = @{ Mitre = 'T1059'; Desc = 'WScript executes VBScript/JScript files' }
        'cscript.exe'       = @{ Mitre = 'T1059'; Desc = 'CScript executes VBScript/JScript files' }
        'msiexec.exe'       = @{ Mitre = 'T1218'; Desc = 'MSIExec can install from remote URLs' }
        'bitsadmin.exe'     = @{ Mitre = 'T1218'; Desc = 'BITSAdmin can download files and execute commands' }
        'installutil.exe'   = @{ Mitre = 'T1218'; Desc = 'InstallUtil bypasses AppLocker using .NET serialization' }
        'regasm.exe'        = @{ Mitre = 'T1218'; Desc = 'RegAsm executes arbitrary .NET assemblies' }
        'regsvcs.exe'       = @{ Mitre = 'T1218'; Desc = 'RegSvcs executes arbitrary .NET assemblies' }
        'odbcconf.exe'      = @{ Mitre = 'T1218'; Desc = 'ODBCConf can load a DLL via REGSVR option' }
        'msbuild.exe'       = @{ Mitre = 'T1218'; Desc = 'MSBuild executes inline C# code from XML project files' }
        'cmstp.exe'         = @{ Mitre = 'T1218'; Desc = 'CMSTP can bypass UAC and AppLocker via INF files' }
        'xwizard.exe'       = @{ Mitre = 'T1218'; Desc = 'XWizard.exe can proxy execution of DLLs via COM' }
        'ieexec.exe'        = @{ Mitre = 'T1218'; Desc = 'IEExec downloads and executes .NET applications' }
        'syncappvpublishingserver.exe' = @{ Mitre = 'T1218'; Desc = 'Sync App-V Publishing Server can run arbitrary scripts' }
        'appsyncpublishingserver.exe'  = @{ Mitre = 'T1218'; Desc = 'App-V sync helper can run arbitrary PowerShell' }
        'wmic.exe'          = @{ Mitre = 'T1218'; Desc = 'WMIC executes WQL and process commands; supports remote execution' }
        'forfiles.exe'      = @{ Mitre = 'T1218'; Desc = 'ForFiles can execute arbitrary commands on matching files' }
        'pcalua.exe'        = @{ Mitre = 'T1218'; Desc = 'Program Compatibility Assistant can run executables' }
        'bash.exe'          = @{ Mitre = 'T1059'; Desc = 'WSL Bash can execute Linux binaries and bypass Windows defenses' }
    }

    # Parent processes that should NOT be spawning LOLBins
    $suspiciousParents = @(
        'winword', 'excel', 'powerpnt', 'outlook', 'msaccess', 'mspub', 'onenote',
        'acrord32', 'foxit', 'chrome', 'firefox', 'iexplore', 'msedge', 'opera',
        'safari', 'thunderbird', 'teams', 'slack', 'discord',
        'wscript', 'cscript', 'mshta', 'wmiprvse'
    )

    # Command-line patterns indicating likely abuse
    $suspiciousCmdPatterns = @(
        '(?i)-enc(odedcommand)?[\s]+[A-Za-z0-9+/]{20,}',    # PS encoded command
        '(?i)/decode',                                         # certutil decode
        '(?i)/urlcache',                                       # certutil download
        '(?i)scrobj\.dll',                                     # COM scriptlet (regsvr32 bypass)
        '(?i)http[s]?://',                                     # Remote URL in args
        '(?i)\\\\[a-z0-9]{1,20}\\[a-z$]',                    # UNC path (lateral movement)
        '(?i)/i:http',                                         # msiexec remote install
        '(?i)-s\s+[a-z0-9_]+:',                               # regsvr32 scriptlet protocol
        '(?i)javascript:',                                     # inline JS execution
        '(?i)vbscript:',                                       # inline VBS execution
        '(?i)FromBase64String',                                # PS base64 decode
        '(?i)IEX|Invoke-Expression',                           # PS execution
        '(?i)DownloadString|DownloadFile|WebClient',           # PS download
        '(?i)bypass',                                          # execution policy bypass
        '(?i)-w(indowstyle)?\s+hid(den)?',                    # hidden window
        '(?i)-nop(rofile)?'                                    # no profile (common in attacks)
    )

    # Standard system paths - LOLBins running from elsewhere are suspicious
    $systemPaths = @(
        [System.Environment]::GetFolderPath('System'),
        [System.Environment]::GetFolderPath('SystemX86'),
        (Join-Path $env:WINDIR 'SysWOW64'),
        (Join-Path $env:WINDIR 'System32')
    ) | ForEach-Object { $_.ToLowerInvariant() }

    # --- Query all processes with parent info via WMI ---------------------------
    $wmiProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue

    if (-not $wmiProcesses) {
        Write-Warning "LOLBINDetection: Could not enumerate processes via WMI."
        return $findings
    }

    # Build PID -> process info map for fast parent lookups
    $pidMap = @{}
    foreach ($p in $wmiProcesses) {
        $pidMap[$p.ProcessId] = $p
    }

    $flaggedPids = @{}  # Track already-flagged PIDs to avoid duplicate findings

    foreach ($proc in $wmiProcesses) {
        $exeName = [System.IO.Path]::GetFileName($proc.ExecutablePath).ToLowerInvariant()

        if (-not $lolbins.ContainsKey($exeName)) { continue }
        if ($flaggedPids.ContainsKey($proc.ProcessId)) { continue }

        $lolInfo  = $lolbins[$exeName]
        $cmdLine  = $proc.CommandLine
        $exePath  = $proc.ExecutablePath
        $severity = 'Yellow'
        $reasons  = [System.Collections.Generic.List[string]]::new()

        # Check 1: Running from non-standard path
        $isSystemPath = $false
        if ($exePath) {
            $exeDir = [System.IO.Path]::GetDirectoryName($exePath).ToLowerInvariant()
            foreach ($sp in $systemPaths) {
                if ($exeDir -eq $sp) { $isSystemPath = $true; break }
            }
        }
        if (-not $isSystemPath -and $exePath) {
            $severity = 'Red'
            $reasons.Add("Non-standard path: $exePath")
        }

        # Check 2: Suspicious parent
        $parentName = ''
        if ($proc.ParentProcessId -and $pidMap.ContainsKey([int]$proc.ParentProcessId)) {
            $parentProc = $pidMap[[int]$proc.ParentProcessId]
            $parentName = [System.IO.Path]::GetFileNameWithoutExtension($parentProc.Name).ToLowerInvariant()

            if ($suspiciousParents -contains $parentName) {
                $severity = 'Red'
                $reasons.Add("Spawned by suspicious parent: $parentName (PID $($proc.ParentProcessId))")
            }
        }

        # Check 3: Suspicious command-line arguments
        if ($cmdLine) {
            foreach ($pattern in $suspiciousCmdPatterns) {
                if ($cmdLine -match $pattern) {
                    $severity = 'Red'
                    $reasons.Add("Suspicious argument pattern: $($Matches[0].Substring(0, [Math]::Min(60, $Matches[0].Length)))")
                    break
                }
            }
        }

        # Only flag if we have actual reasons (avoid noisy whitelisted LOLBins with no indicators)
        if ($reasons.Count -eq 0) {
            # LOLBin running from standard path with no suspicious args/parent = Yellow informational
            $reasons.Add("LOLBin running (no additional indicators detected)")
        }

        $mitreTechnique = $lolInfo.Mitre
        $mitreNames = @{
            'T1218' = 'Signed Binary Proxy Execution'
            'T1059' = 'Command and Scripting Interpreter'
        }

        $findings.Add([PSCustomObject]@{
            Module      = 'LOLBINDetection'
            Severity    = $severity
            Category    = 'LOLBin Abuse'
            Title       = "$($proc.Name) [PID $($proc.ProcessId)]"
            Path        = $exePath
            Detail          = "$($lolInfo.Desc) | Parent: $parentName (PID $($proc.ParentProcessId)) | Reasons: $($reasons -join '; ') | CmdLine: $(if ($cmdLine) { $cmdLine.Substring(0, [Math]::Min(200, $cmdLine.Length)) } else { 'N/A' })"
            ActionTaken = ''
            MitreId     = $mitreTechnique
            MitreName   = $mitreNames[$mitreTechnique]
        })

        $flaggedPids[$proc.ProcessId] = $true

        if ($severity -eq 'Red') {
            Add-Content -Path $AuditLog -Value (
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
                "[MODULE: LOLBINDetection] [ACTION: LOLBinAbuse] " +
                "[DETAILS: LOLBin='$exeName' PID=$($proc.ProcessId) Parent='$parentName' Reasons='$($reasons -join '; ')']"
            ) -Encoding UTF8
        }
    }

    $redCnt    = @($findings | Where-Object { $_.Severity -eq 'Red' }).Count
    $yellowCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
        "[MODULE: LOLBINDetection] [ACTION: Scan] " +
        "[DETAILS: LOLBins detected - RED:$redCnt YELLOW:$yellowCnt]"
    ) -Encoding UTF8

    return $findings
}

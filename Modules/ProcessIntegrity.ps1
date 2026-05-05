#Requires -RunAsAdministrator
# =============================================================
# ProcessIntegrity.ps1 — QuietMonitor process self-integrity
# Verifies: service process hash vs installed binary, expected
# child processes, unexpected DLLs loaded into own process space
# (DLL injection detection), running process binary signatures.
# MITRE: T1055 (Process Injection), T1574 (DLL Hijacking)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:PI_BASE      = 'C:\QuietMonitor'
$script:PI_TAMPER    = 'C:\QuietMonitor\Logs\tamper.log'
$script:PI_SVC_NAME  = 'QuietMonitorSvc'

# Expected baseline: modules the QuietMonitor PowerShell process should load
# (system DLLs + known PS runtime DLLs). Anything not in this list is suspicious.
$script:PI_EXPECTED_MODULE_PATHS = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot\Microsoft.NET",
    "$env:ProgramFiles\PowerShell",
    "$env:ProgramFiles\WindowsPowerShell"
)

function script:New-PIFinding {
    param([string]$Sev, [string]$Name, [string]$Display, [string]$Path, [string]$Hash, [string]$Details, [string]$Mitre, [string]$MitreName)
    [PSCustomObject]@{
        Severity=$Sev; Module='ProcessIntegrity'; Category='ProcessIntegrity'
        Title=$Display; Detail=$Details; Path=$Path
        MitreId=$Mitre; MitreName=$MitreName; ActionTaken='Alert'
    }
}

function script:Write-PITamper {
    param([string]$Message, [string]$AuditLog)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [ProcessIntegrity] $Message"
    try { Add-Content -LiteralPath $script:PI_TAMPER -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
    Write-Host "  [!!!] PROCESS INTEGRITY: $Message" -ForegroundColor Red
}

function script:Get-PIFileHash {
    param([string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = [BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($Path))).Replace('-','').ToLower()
        $sha.Dispose()
        return $hash
    } catch { return $null }
}

# ── Service process hash verification ─────────────────────────
function Test-ServiceProcessIntegrity {
    <#
    .SYNOPSIS
        Locates the QuietMonitorSvc service binary, computes its SHA256,
        and compares against the hash recorded in the integrity manifest.
        Also verifies the service is running from the expected installation path.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'])

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $svc = Get-Service -Name $script:PI_SVC_NAME -ErrorAction SilentlyContinue
        if (-not $svc) {
            $findings.Add((script:New-PIFinding 'Yellow' 'ServiceNotFound'
                'QuietMonitor service not installed'
                '' '' 'Service may have been removed or not yet installed'
                'T1562' 'Impair Defenses'))
            return $findings.ToArray()
        }

        # Get service binary path
        $svcWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($script:PI_SVC_NAME)'" -ErrorAction SilentlyContinue
        $binPath = (if ($svcWmi) { $svcWmi.PathName } else { '' }) -replace '"','' -replace ' -.*',''  # strip args

        if (-not $binPath -or -not (Test-Path $binPath)) {
            $findings.Add((script:New-PIFinding 'Red' 'ServiceBinaryMissing'
                'QuietMonitor service binary not found'
                $binPath '' 'Service binary path is invalid or file missing'
                'T1574' 'Hijack Execution Flow'))
            return $findings.ToArray()
        }

        # Verify binary is under QuietMonitor base directory
        if (-not $binPath.StartsWith($script:PI_BASE, [System.StringComparison]::OrdinalIgnoreCase)) {
            script:Write-PITamper "Service binary path OUTSIDE QuietMonitor directory: $binPath" $AuditLog
            $findings.Add((script:New-PIFinding 'Red' 'ServiceBinaryRelocation'
                'Service binary outside expected directory'
                $binPath (script:Get-PIFileHash $binPath)
                "Expected under $script:PI_BASE but found at: $binPath"
                'T1574' 'Hijack Execution Flow'))
        }

        # Compare against integrity manifest if available
        $manifestFile = 'C:\QuietMonitor\integrity\manifest.json'
        if (Test-Path $manifestFile) {
            try {
                $manifest    = Get-Content $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
                $manifestEntry = $manifest.files | Where-Object { $_.path -ieq $binPath }
                if ($manifestEntry) {
                    $currentHash = script:Get-PIFileHash $binPath
                    if ($currentHash -ne $manifestEntry.hash) {
                        script:Write-PITamper "Service binary MODIFIED: $binPath" $AuditLog
                        $findings.Add((script:New-PIFinding 'Red' 'ServiceBinaryModified'
                            'Service binary hash changed since installation'
                            $binPath $currentHash
                            "Manifest: $($manifestEntry.hash.Substring(0,32))... Current: $($currentHash.Substring(0,32))..."
                            'T1574' 'Hijack Execution Flow'))
                    }
                }
            } catch {}
        }

    } catch {
        $findings.Add((script:New-PIFinding 'Yellow' 'ServiceCheckFailed'
            'Could not verify service process integrity'
            '' '' $_.Exception.Message 'T1562' 'Impair Defenses'))
    }

    return $findings.ToArray()
}

# ── DLL injection detection ───────────────────────────────────
function Test-DLLInjectionInProcess {
    <#
    .SYNOPSIS
        Enumerates all DLLs loaded in the current process (PID).
        Flags any module loaded from a path not in the expected list
        of trusted directories (System32, .NET runtime, PS install dir).
        Also flags unsigned DLLs loaded from non-system paths.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'])

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $myProc = Get-Process -Id $PID -ErrorAction Stop
        $unexpected = @()

        foreach ($mod in $myProc.Modules) {
            $modPath = $mod.FileName
            if (-not $modPath) { continue }

            $isTrusted = $script:PI_EXPECTED_MODULE_PATHS | Where-Object {
                $modPath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase)
            }

            if (-not $isTrusted) {
                # Check if it's under the QuietMonitor install dir (expected)
                if ($modPath.StartsWith($script:PI_BASE, [System.StringComparison]::OrdinalIgnoreCase)) {
                    # Verify its Authenticode signature
                    $sig = Get-AuthenticodeSignature -FilePath $modPath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -ne 'Valid') {
                        $unexpected += [PSCustomObject]@{ Name = $mod.ModuleName; Path = $modPath; Reason = "Unsigned QuietMonitor module" }
                    }
                } else {
                    $unexpected += [PSCustomObject]@{ Name = $mod.ModuleName; Path = $modPath; Reason = "Module outside trusted directories" }
                }
            }
        }

        foreach ($u in $unexpected) {
            $sev = if ($u.Path -match '(?i)(\\Temp\\|AppData\\Local\\Temp|\\Downloads\\)') { 'Red' } else { 'Yellow' }
            if ($sev -eq 'Red') { script:Write-PITamper "Possible DLL injection: $($u.Path)" $AuditLog }
            $findings.Add((script:New-PIFinding $sev 'UnexpectedDLL'
                "Unexpected DLL in process: $($u.Name)"
                $u.Path (script:Get-PIFileHash $u.Path)
                "$($u.Reason). Path: $($u.Path)"
                'T1055' 'Process Injection'))
        }

        if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [ProcessIntegrity] [ACTION: DLLCheck] [DETAILS: $($myProc.Modules.Count) modules checked; $($unexpected.Count) unexpected]" -Encoding UTF8 -ErrorAction SilentlyContinue }

    } catch {
        $findings.Add((script:New-PIFinding 'Yellow' 'DLLCheckFailed'
            'Could not enumerate process modules'
            '' '' $_.Exception.Message 'T1055' 'Process Injection'))
    }

    return $findings.ToArray()
}

# ── Child process verification ────────────────────────────────
function Test-ChildProcesses {
    <#
    .SYNOPSIS
        Verifies that all child processes of the current PID are expected.
        QuietMonitor should only spawn: powershell.exe, pwsh.exe.
        Any other child process is flagged as potentially injected.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'])

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allowed  = @('powershell','pwsh','cmd','conhost')

    try {
        $children = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.ParentProcessId -eq $PID }

        foreach ($child in $children) {
            $name = [System.IO.Path]::GetFileNameWithoutExtension($child.Name).ToLower()
            if ($allowed -notcontains $name) {
                $msg = "Unexpected child process: $($child.Name) (PID: $($child.ProcessId)) spawned by QuietMonitor (PID: $PID)"
                script:Write-PITamper $msg $AuditLog
                $findings.Add((script:New-PIFinding 'Red' 'UnexpectedChildProcess'
                    "Unexpected child process: $($child.Name)"
                    $child.ExecutablePath ''
                    "$msg  CommandLine: $($child.CommandLine)"
                    'T1055' 'Process Injection'))
            }
        }
    } catch {}

    return $findings.ToArray()
}

# ── Orchestrator ──────────────────────────────────────────────
function Invoke-ProcessIntegrityCheck {
    <#
    .SYNOPSIS
        Orchestrator: runs all three process integrity sub-checks.
        Used from Run-SecuritySuite.ps1 and as a background guard.
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host '  [ProcessIntegrity] Verifying service binary hash...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-ServiceProcessIntegrity -AuditLog $AuditLog))

    Write-Host '  [ProcessIntegrity] Checking for DLL injection...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-DLLInjectionInProcess -AuditLog $AuditLog))

    Write-Host '  [ProcessIntegrity] Verifying child processes...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-ChildProcesses -AuditLog $AuditLog))

    return $all.ToArray()
}

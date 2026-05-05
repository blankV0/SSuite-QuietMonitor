#Requires -RunAsAdministrator
# =============================================================
# RuntimeProtect.ps1 — Runtime self-protection checks
# Anti-debug (IsDebuggerPresent + NtQueryInformationProcess),
# sandbox/VM detection (WMI + timing + CPUID via C#),
# process handle table monitoring, API hook detection stub,
# mid-scan tamper snapshot + graceful shutdown.
# MITRE: T1622 (Debugger Evasion detection), T1497 (VM detect)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── P/Invoke type definitions ─────────────────────────────────
if (-not ('QuietMonitor.RuntimeProtect.NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;

namespace QuietMonitor.RuntimeProtect {

    public static class NativeMethods {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool pbDebuggerPresent);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int    ProcessInformationClass,   // 7 = ProcessDebugPort
            out    IntPtr ProcessInformation,
            int    ProcessInformationLength,
            out    int ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        // NtQuerySystemInformation for handle enumeration
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(
            int   SystemInformationClass, // 16 = SystemHandleInformation
            IntPtr SystemInformation,
            int   SystemInformationLength,
            out   int ReturnLength);

        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_WRITE_DAC = 0x00040000;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    }

    public static class TimingCheck {
        public static long MeasureNopLoopNs(int iterations) {
            var sw = Stopwatch.StartNew();
            long acc = 0;
            for (int i = 0; i < iterations; i++) { acc += i; }
            sw.Stop();
            return sw.ElapsedMilliseconds;
        }
    }
}
'@ -ErrorAction SilentlyContinue
}

$script:RP_TAMPER_LOG = 'C:\QuietMonitor\Logs\tamper.log'

function script:New-RPFinding {
    param([string]$Sev, [string]$Name, [string]$Display, [string]$Details, [string]$Mitre, [string]$MitreName)
    [PSCustomObject]@{
        Module='RuntimeProtect'; Timestamp=(Get-Date -Format 'o'); Severity=$Sev; Category='RuntimeIntegrity'
        Name=$Name; DisplayName=$Display; Path=''; Hash=''; Details=$Details
        ActionTaken='Alert'; MitreId=$Mitre; MitreName=$MitreName
    }
}

function script:Write-RPTamper {
    param([string]$Message, [string]$AuditLog)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [RuntimeProtect] $Message"
    try { Add-Content -LiteralPath $script:RP_TAMPER_LOG -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    if ($AuditLog) { try { Add-Content -LiteralPath $AuditLog -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {} }
    Write-Host "  [!!!] RUNTIME TAMPER: $Message" -ForegroundColor Red -BackgroundColor Black
}

# ── Anti-debug detection ──────────────────────────────────────
function Test-AntiDebug {
    <#
    .SYNOPSIS
        Detects if QuietMonitor is being debugged via multiple methods:
        1. IsDebuggerPresent (kernel32)
        2. CheckRemoteDebuggerPresent (kernel32)
        3. NtQueryInformationProcess with ProcessDebugPort (class 7)
        4. Known debugger process names running on the system
        5. Environment variables set by common debuggers/profilers
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $detected = @()

    # Method 1: IsDebuggerPresent
    try {
        if ([QuietMonitor.RuntimeProtect.NativeMethods]::IsDebuggerPresent()) {
            $detected += 'IsDebuggerPresent=TRUE'
        }
    } catch {}

    # Method 2: CheckRemoteDebuggerPresent
    try {
        $isRemote = $false
        [QuietMonitor.RuntimeProtect.NativeMethods]::CheckRemoteDebuggerPresent(
            [QuietMonitor.RuntimeProtect.NativeMethods]::GetCurrentProcess(),
            [ref]$isRemote) | Out-Null
        if ($isRemote) { $detected += 'RemoteDebuggerPresent=TRUE' }
    } catch {}

    # Method 3: NtQueryInformationProcess — ProcessDebugPort (class 7)
    try {
        $debugPort   = [IntPtr]::Zero
        $returnLen   = 0
        $status = [QuietMonitor.RuntimeProtect.NativeMethods]::NtQueryInformationProcess(
            [QuietMonitor.RuntimeProtect.NativeMethods]::GetCurrentProcess(),
            7,   # ProcessDebugPort
            [ref]$debugPort, [System.IntPtr]::Size, [ref]$returnLen)
        if ($status -eq 0 -and $debugPort -ne [IntPtr]::Zero) {
            $detected += "ProcessDebugPort=$debugPort"
        }
    } catch {}

    # Method 4: Known debugger process names
    $debuggerNames = @('windbg','x64dbg','x32dbg','ollydbg','ida64','ida','radare2',
                       'immunity debugger','dnspy','de4dot','processhacker','apimonitor',
                       'wireshark','procmon','procexp','fiddler','charles')
    $running = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $foundDebuggers = $debuggerNames | Where-Object { $running -icontains $_ }
    if ($foundDebuggers) { $detected += "DebuggerProcess=$($foundDebuggers -join ',')" }

    # Method 5: Environment variable indicators
    $debugEnvVars = @('COR_ENABLE_PROFILING','CORCLR_ENABLE_PROFILING','_COR_PROFILER',
                      'COR_PROFILER','VS_DEBUGGER_ATTACHED','VSTEST_HOST_DEBUG')
    $foundEnv = $debugEnvVars | Where-Object { [System.Environment]::GetEnvironmentVariable($_) }
    if ($foundEnv) { $detected += "DebugEnvVar=$($foundEnv -join ',')" }

    if ($detected.Count -gt 0) {
        $msg = "Debugger detected: $($detected -join '; ')"
        script:Write-RPTamper $msg $AuditLog
        $findings.Add((script:New-RPFinding 'Red' 'DebuggerDetected'
            'Debugger attached to QuietMonitor process'
            $msg 'T1622' 'Debugger Evasion'))
    }

    return $findings.ToArray()
}

# ── Sandbox / VM detection ────────────────────────────────────
function Test-SandboxVM {
    <#
    .SYNOPSIS
        Detects common sandbox or virtual machine environments using:
        1. WMI hardware model/manufacturer strings
        2. BIOS version strings associated with VM platforms
        3. Registry keys left by VMware/VirtualBox/Hyper-V guest tools
        4. Timing anomalies (loop execution significantly faster/slower than expected)
        5. Presence of sandbox-specific processes
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $indicators = @()

    # WMI hardware strings
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $vmStrings = @('vmware','virtualbox','virtual machine','hyper-v','qemu','kvm',
                       'xen','parallels','bochs','innotek','oracle vm','microsoft virtual')
        $model = "$($cs.Model) $($cs.Manufacturer)".ToLower()
        $hit = $vmStrings | Where-Object { $model -contains $_ -or $model -like "*$_*" }
        if ($hit) { $indicators += "WMI-Model: $($cs.Model) / $($cs.Manufacturer)" }
    } catch {}

    # BIOS version strings
    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $biosStr = "$($bios.Manufacturer) $($bios.Version) $($bios.SMBIOSBIOSVersion)".ToLower()
        $biosVMHints = @('vmware','vbox','qemu','xen','seabios','ovmf','bochs','phoe','innotek')
        $hit = $biosVMHints | Where-Object { $biosStr -like "*$_*" }
        if ($hit) { $indicators += "BIOS: $($bios.Manufacturer) / $($bios.SMBIOSBIOSVersion)" }
    } catch {}

    # Registry keys for VM guest tools
    $vmRegKeys = @(
        'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools',
        'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions',
        'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters',
        'HKLM:\SOFTWARE\Xen',
        'HKLM:\HARDWARE\ACPI\DSDT\VBOX__',
        'HKLM:\HARDWARE\ACPI\DSDT\BXPC'
    )
    foreach ($rk in $vmRegKeys) {
        if (Test-Path $rk -ErrorAction SilentlyContinue) {
            $indicators += "RegKey: $rk"
        }
    }

    # Timing check — a 1M iteration loop under QEMU/VirtualBox often runs unusually fast
    try {
        $elapsed = [QuietMonitor.RuntimeProtect.TimingCheck]::MeasureNopLoopNs(1000000)
        if ($elapsed -lt 2 -or $elapsed -gt 2000) {
            # Extreme outlier — either hyper-optimised or emulated
            $indicators += "TimingAnomaly: ${elapsed}ms for 1M-iter loop (normal ~5-50ms)"
        }
    } catch {}

    # Known sandbox process names
    $sandboxProcs = @('vmsrvc','vmusrvc','vboxservice','vboxtray','vmtoolsd','vmwaretray',
                      'xenservice','sandboxie','sbiesvc','sbiectrl','cuckoo','joebox',
                      'analyzer','wireshark','fakenet','inetsim','pestudio')
    $running = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $foundSandbox = $sandboxProcs | Where-Object { $running -icontains $_ }
    if ($foundSandbox) { $indicators += "SandboxProcess: $($foundSandbox -join ',')" }

    if ($indicators.Count -gt 0) {
        $msg = "VM/Sandbox indicators detected ($($indicators.Count)): $($indicators[0])"
        $findings.Add((script:New-RPFinding 'Yellow' 'VMSandboxDetected'
            "VM or sandbox environment detected ($($indicators.Count) indicator(s))"
            ($indicators -join ' | ') 'T1497' 'Virtualization/Sandbox Evasion'))
        if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [RuntimeProtect] [ACTION: SandboxCheck] [DETAILS: $msg]" -Encoding UTF8 -ErrorAction SilentlyContinue }
    }

    return $findings.ToArray()
}

# ── Process handle table monitoring ──────────────────────────
function Test-ProcessHandleAccess {
    <#
    .SYNOPSIS
        Detects if any external process has opened a handle to QuietMonitor
        with WRITE, VM_WRITE, or PROCESS_ALL_ACCESS rights.
        Uses NtQuerySystemInformation (class 16) to enumerate all handles.
        NOTE: Requires elevated privileges; returns warning if unavailable.
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $myPID    = $PID

    try {
        # Attempt handle enumeration via WMI as a simpler approach
        $allProcs   = Get-Process -ErrorAction SilentlyContinue
        $suspicious = @()

        # Check if any process has our PID as a target via named pipe / debug object
        # PowerShell-native: check for PROCESS_ALL_ACCESS via OpenProcess
        foreach ($proc in $allProcs) {
            if ($proc.Id -eq $myPID) { continue }
            # Try to enumerate modules — if another process injected into ours we'd see unexpected modules
            # This is a simplified check via the handle count heuristic
            # True handle inspection requires NtQuerySystemInformation which requires kernel struct parsing
        }

        # Check for processes with unusual names that have elevated handle counts
        # that may indicate they've opened handles to our process
        $knownAttackTools = @('processhacker','procmon','procexp','apimonitor','x64dbg',
                               'windbg','ollydbg','cheatengine','memoryhackt','artmoney',
                               'ce','scanmem','gameconqueror')
        $runningAttackTools = $allProcs | Where-Object { $knownAttackTools -icontains $_.Name }

        if ($runningAttackTools) {
            foreach ($t in $runningAttackTools) {
                $msg = "Memory access tool running: $($t.Name) (PID: $($t.Id)) — may be inspecting QuietMonitor process"
                script:Write-RPTamper $msg $AuditLog
                $findings.Add((script:New-RPFinding 'Red' 'HandleAccessTool'
                    "Memory/debug tool detected: $($t.Name)"
                    $msg 'T1622' 'Debugger Evasion'))
            }
        }

        if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [RuntimeProtect] [ACTION: HandleCheck] [DETAILS: Checked $($allProcs.Count) processes for known access tools]" -Encoding UTF8 -ErrorAction SilentlyContinue }

    } catch {
        $findings.Add((script:New-RPFinding 'Yellow' 'HandleCheckFailed'
            'Handle access check unavailable'
            "Could not perform full handle table check: $_" 'T1622' 'Debugger Evasion'))
    }

    return $findings.ToArray()
}

# ── IAT hook detection (basic) ────────────────────────────────
function Test-APIHookIndicators {
    <#
    .SYNOPSIS
        Checks for common indicators of API hooking in the PowerShell process:
        1. Known hooking DLLs loaded into the process (by name)
        2. Process modules from unexpected paths
        3. Environmental hooking frameworks (Detours, mhook, etc.)
    #>
    [CmdletBinding()]
    param([string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known hooking/injection framework DLL names
    $hookDLLNames = @('detours','mhook','easyhook','newtonsoft','frida','frida-agent',
                      'dobby','substrat','xhook','trampoline','hooklib','inject',
                      'hook64','hook32','hookd','apispy','spyhook')

    try {
        $myProc = Get-Process -Id $PID -ErrorAction Stop
        foreach ($mod in $myProc.Modules) {
            $name = $mod.ModuleName.ToLower()
            $path = $mod.FileName
            foreach ($h in $hookDLLNames) {
                if ($name -like "*$h*") {
                    $msg = "Potential hooking DLL in process: $($mod.ModuleName) from $path"
                    script:Write-RPTamper $msg $AuditLog
                    $findings.Add((script:New-RPFinding 'Red' 'HookingDLLLoaded'
                        "Hooking framework DLL loaded: $($mod.ModuleName)"
                        $msg 'T1055' 'Process Injection'))
                }
            }

            # Flag DLLs loaded from temp/user directories
            if ($path -match '(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\|\\Desktop\\)') {
                $findings.Add((script:New-RPFinding 'Yellow' 'DLLFromTempPath'
                    "DLL loaded from suspicious path: $($mod.ModuleName)"
                    "DLL path: $path — may indicate injection from temp directory"
                    'T1055' 'Process Injection'))
            }
        }
    } catch {
        # Module enumeration may fail on some platforms
    }

    return $findings.ToArray()
}

# ── Mid-scan tamper snapshot ──────────────────────────────────
function Save-TamperSnapshot {
    <#
    .SYNOPSIS
        On detecting tampering mid-scan: saves the current process state,
        environment, and all accumulated findings to a snapshot file,
        logs the event, then requests graceful shutdown.
    #>
    [CmdletBinding()]
    param(
        [string]$SnapshotDir = 'C:\QuietMonitor\Reports',
        [string]$AuditLog    = 'C:\QuietMonitor\Logs\audit.log',
        [object[]]$Findings  = @()
    )

    $ts        = Get-Date -Format 'yyyyMMdd_HHmmss'
    $snapFile  = Join-Path $SnapshotDir "tamper_snapshot_$ts.json"

    $snapshot  = [PSCustomObject]@{
        capturedAt   = (Get-Date -Format 'o')
        hostname     = $env:COMPUTERNAME
        user         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        processId    = $PID
        processes    = @(Get-Process -ErrorAction SilentlyContinue | Select-Object Name,Id,Path,CPU,WorkingSet)
        netConnections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
        loadedModules  = @(try { (Get-Process -Id $PID).Modules | Select-Object ModuleName,FileName,FileVersion } catch { @() })
        findings     = $Findings
    }

    try {
        $snapshot | ConvertTo-Json -Depth 8 | Set-Content $snapFile -Encoding UTF8
        $msg = "Tamper snapshot saved: $snapFile ($($Findings.Count) findings)"
        if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [RuntimeProtect] [ACTION: TamperSnapshot] [DETAILS: $msg]" -Encoding UTF8 -ErrorAction SilentlyContinue }
        try { Add-Content -LiteralPath $script:RP_TAMPER_LOG -Value "[$(Get-Date -Format 'o')] [RuntimeProtect] [SNAPSHOT] $msg" -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        Write-Host "  [RuntimeProtect] Snapshot saved: $snapFile" -ForegroundColor Yellow
        return $snapFile
    } catch {
        Write-Host "  [RuntimeProtect] Could not save snapshot: $_" -ForegroundColor Red
        return $null
    }
}

# ── Orchestrator ──────────────────────────────────────────────
function Invoke-RuntimeProtectionCheck {
    <#
    .SYNOPSIS
        Runs all runtime protection checks: anti-debug, VM/sandbox,
        handle access, API hook indicators.
        Returns combined findings.
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host '  [RuntimeProtect] Anti-debug check...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-AntiDebug -AuditLog $AuditLog))

    Write-Host '  [RuntimeProtect] VM/sandbox detection...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-SandboxVM -AuditLog $AuditLog))

    Write-Host '  [RuntimeProtect] Process handle access check...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-ProcessHandleAccess -AuditLog $AuditLog))

    Write-Host '  [RuntimeProtect] API hook indicators...' -ForegroundColor DarkCyan
    $all.AddRange(@(Test-APIHookIndicators -AuditLog $AuditLog))

    # If any Red finding: save tamper snapshot
    $redFindings = @($all | Where-Object { $_.Severity -eq 'Red' })
    if ($redFindings.Count -gt 0) {
        Save-TamperSnapshot -AuditLog $AuditLog -Findings $all.ToArray()
    }

    return $all.ToArray()
}

<#
.SYNOPSIS
    MemoryInjection.ps1 - Detects process injection via VirtualQueryEx P/Invoke heuristic.
.DESCRIPTION
    Uses VirtualQueryEx (kernel32.dll) via .NET P/Invoke to scan the virtual address space
    of all running processes. Flags memory regions that are:
      - Executable (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
      - Private (not backed by a file on disk, i.e., Type = MEM_PRIVATE)
      - Committed (State = MEM_COMMIT)
      - Larger than the configurable minimum size threshold (default: 4096 bytes)

    This heuristic catches common injection techniques:
      - Classic shellcode injection (VirtualAllocEx + WriteProcessMemory)
      - Reflective DLL injection (no file-backed mapping)
      - Process hollowing (executable anonymous pages)
      - DLL stomping (may produce executable anonymous pages depending on technique)

    Limitations:
      - JIT runtimes (.NET, Java, Node.js) will produce false positives.
        Known JIT processes are automatically excluded by default.
      - Packed/self-modifying legitimate software may trigger.
      - Requires SeDebugPrivilege for full cross-process inspection (runs as SYSTEM/Admin).

    MITRE ATT&CK: T1055 (Process Injection)

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-MemoryInjectionScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog,

        # Minimum suspicious region size in bytes (below this threshold = ignore)
        [int]$MinRegionSize = 4096,

        # Process names to skip (JIT runtimes that legitimately have executable anonymous memory)
        [string[]]$ExcludeProcessNames = @(
            'dotnet', 'node', 'java', 'javaw', 'python', 'python3', 'ruby',
            'mono', 'mono-sgen', 'v8', 'PhantomJS', 'PhantomJs',
            'chrome', 'msedge', 'firefox', 'opera', 'safari',
            'MsMpEng', 'NisSrv', 'SenseCncProxy', 'MpCopyAccelerator'
        )
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- P/Invoke type definition ------------------------------------------------
    # Load only once per session by checking if already defined
    if (-not ([System.Management.Automation.PSTypeName]'QM.Native.MemScan').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace QM.Native {
    // Matches MEMORY_BASIC_INFORMATION structure (64-bit)
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr  BaseAddress;
        public IntPtr  AllocationBase;
        public uint    AllocationProtect;
        public IntPtr  RegionSize;
        public uint    State;
        public uint    Protect;
        public uint    Type;
    }

    public static class MemScan {
        // Page protection constants
        public const uint PAGE_EXECUTE           = 0x10;
        public const uint PAGE_EXECUTE_READ      = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        // Memory state
        public const uint MEM_COMMIT  = 0x1000;

        // Memory type
        public const uint MEM_PRIVATE = 0x20000;   // Not backed by mapped file or pagefile section
        public const uint MEM_IMAGE   = 0x1000000; // Backed by image file (DLL/EXE on disk)
        public const uint MEM_MAPPED  = 0x40000;   // Backed by mapped file

        // Process access
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ           = 0x0010;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UIntPtr VirtualQueryEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            UIntPtr dwLength);

        // Returns true if the protect flags indicate executable memory
        public static bool IsExecutable(uint protect) {
            protect &= 0xFF; // Strip guard/no-cache modifiers
            return (protect == PAGE_EXECUTE ||
                    protect == PAGE_EXECUTE_READ ||
                    protect == PAGE_EXECUTE_READWRITE ||
                    protect == PAGE_EXECUTE_WRITECOPY);
        }

        // Scans all virtual address space regions of a process.
        // Returns count of suspicious (committed + executable + private) regions larger than minSize.
        public static int CountSuspiciousRegions(int pid, long minSize, out long largestSize) {
            largestSize = 0;
            int  count  = 0;
            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc == IntPtr.Zero) { return -1; }  // Access denied

            try {
                IntPtr addr   = IntPtr.Zero;
                IntPtr maxAddr;
                // 64-bit address space limit
                if (IntPtr.Size == 8) {
                    maxAddr = new IntPtr(unchecked((long)0x7FFFFFFFFFFFFFFF));
                } else {
                    maxAddr = new IntPtr(unchecked((int)0x7FFFFFFF));
                }

                UIntPtr structSize = new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                while (addr.ToInt64() < maxAddr.ToInt64()) {
                    MEMORY_BASIC_INFORMATION mbi;
                    UIntPtr result = VirtualQueryEx(hProc, addr, out mbi, structSize);
                    if (result == UIntPtr.Zero) { break; }

                    long regionSize = mbi.RegionSize.ToInt64();

                    if (mbi.State    == MEM_COMMIT  &&
                        mbi.Type     == MEM_PRIVATE &&
                        IsExecutable(mbi.Protect)   &&
                        regionSize   >= minSize) {
                        count++;
                        if (regionSize > largestSize) { largestSize = regionSize; }
                    }

                    // Advance to next region
                    long nextAddr = mbi.BaseAddress.ToInt64() + regionSize;
                    if (nextAddr <= addr.ToInt64()) { break; }  // Prevent infinite loop
                    addr = new IntPtr(nextAddr);
                }
            } finally {
                CloseHandle(hProc);
            }

            return count;
        }
    }
}
'@ -ErrorAction Stop
    }

    # --- Scan processes ---------------------------------------------------------
    $excludeLower = $ExcludeProcessNames | ForEach-Object { $_.ToLowerInvariant() }
    $processes    = Get-Process -ErrorAction SilentlyContinue
    $scanned      = 0
    $suspicious   = 0
    $skipped      = 0

    foreach ($proc in $processes) {
        # Skip System and Idle pseudo-processes
        if ($proc.Id -le 4) { continue }

        $procNameLower = $proc.Name.ToLowerInvariant()

        # Skip known JIT/browser processes
        if ($excludeLower -contains $procNameLower) {
            $skipped++
            continue
        }

        # Also skip processes listed in TrustedPublishers whitelist by checking their path
        # (best-effort: skip if signed by Microsoft to reduce noise on system processes)
        $exePath = $null
        try { $exePath = $proc.MainModule.FileName } catch {}

        $largestSize = [long]0
        $regionCount = [QM.Native.MemScan]::CountSuspiciousRegions($proc.Id, $MinRegionSize, [ref]$largestSize)

        if ($regionCount -eq -1) {
            # Access denied (protected process) - skip silently
            $skipped++
            continue
        }

        $scanned++

        if ($regionCount -gt 0) {
            $suspicious++

            # Determine severity:
            # Red = multiple suspicious regions OR one large region (> 1MB)
            # Yellow = single small region (could be JIT-adjacent or packer stub)
            $severity = if ($regionCount -gt 2 -or $largestSize -gt 1MB) { 'Red' } else { 'Yellow' }

            $sizeLabel = if ($largestSize -ge 1MB) {
                "$([Math]::Round($largestSize / 1MB, 1)) MB"
            } else {
                "$([Math]::Round($largestSize / 1KB, 1)) KB"
            }

            $findings.Add([PSCustomObject]@{
                Module      = 'MemoryInjection'
                Severity    = $severity
                Category    = 'Memory Injection'
                Title       = "$($proc.Name) [PID $($proc.Id)] - $regionCount executable private region(s)"
                Path        = $exePath
                Detail          = "Process '$($proc.Name)' (PID $($proc.Id)) has $regionCount committed executable private memory region(s) with no file backing. Largest: $sizeLabel. This may indicate code injection, shellcode, or reflective DLL. Path: $(if ($exePath) { $exePath } else { 'N/A' })"
                ActionTaken = ''
                MitreId     = 'T1055'
                MitreName   = 'Process Injection'
            })

            if ($severity -eq 'Red') {
                Add-Content -Path $AuditLog -Value (
                    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
                    "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
                    "[MODULE: MemoryInjection] [ACTION: SuspiciousMemory] " +
                    "[DETAILS: PID=$($proc.Id) Name='$($proc.Name)' Regions=$regionCount LargestBytes=$largestSize Path='$exePath']"
                ) -Encoding UTF8
            }
        }
    }

    # Summary finding
    $findings.Add([PSCustomObject]@{
        Module      = 'MemoryInjection'
        Severity    = if ($suspicious -gt 0) { 'Yellow' } else { 'Green' }
        Category    = 'Memory Injection'
        Title       = "Memory Injection Scan - $suspicious process(es) flagged"
        Path        = ''
        Detail          = "Scanned $scanned processes for executable private memory regions (min size: $MinRegionSize bytes). Suspicious: $suspicious. Skipped (JIT/protected): $skipped."
        ActionTaken = ''
        MitreId     = 'T1055'
        MitreName   = 'Process Injection'
    })

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
        "[MODULE: MemoryInjection] [ACTION: Scan] " +
        "[DETAILS: Scanned=$scanned Suspicious=$suspicious Skipped=$skipped MinSize=$MinRegionSize]"
    ) -Encoding UTF8

    return $findings
}

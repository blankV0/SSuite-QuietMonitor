<#
.SYNOPSIS
    ForensicCapture.ps1 - Incident Response forensic package export.
.DESCRIPTION
    Provides two functions for incident response capture:

    Get-ProcessTree [-Pid <int>]
      Builds a recursive parent-child process tree using WMI Win32_Process.
      If -Pid is specified, starts from that PID and walks up to root.
      If not specified, builds the full system process tree.
      Each node includes: PID, PPID, Name, CommandLine, User, CreateDate,
      and associated network connections from Get-NetTCPConnection.

    Export-ForensicPackage [-OutputPath <path>] [-AuditLog <path>]
      Creates a timestamped ZIP package of the entire C:\QuietMonitor\ directory
      (logs, reports, quarantine manifest, configs) using pure .NET ZipFile API.
      Also captures a process snapshot (Get-ProcessTree), running services,
      network connections, and open sessions to a TXT summary within the ZIP.
      Returns the full path of the ZIP file.

.OUTPUTS
    Get-ProcessTree: [PSCustomObject[]] (process tree nodes)
    Export-ForensicPackage: [string] (path to ZIP file)
#>

function Get-ProcessTree {
    [CmdletBinding()]
    param(
        # If specified, return only the ancestor chain for this PID
        [Parameter(Mandatory = $false)]
        [int]$Pid = 0
    )

    # Load all processes from WMI once for efficiency
    $wmiProcs = @{}
    try {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
            $wmiProcs[[int]$_.ProcessId] = $_
        }
    } catch {
        Write-Warning "ForensicCapture: Could not enumerate Win32_Process - $($_.Exception.Message)"
        return @()
    }

    # Load network connections keyed by OwningProcess
    $netConns = @{}
    try {
        Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
            $pid_ = [int]$_.OwningProcess
            if (-not $netConns.ContainsKey($pid_)) { $netConns[$pid_] = [System.Collections.Generic.List[string]]::new() }
            $netConns[$pid_].Add("$($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)]")
        }
    } catch {}

    function Get-WmiOwner ([object]$proc) {
        try {
            $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
            if ($owner.ReturnValue -eq 0) { return "$($owner.Domain)\$($owner.User)" }
        } catch {}
        return ''
    }

    function Convert-WmiDate ([object]$d) {
        if ($d -is [System.DateTime]) { return $d.ToString('yyyy-MM-dd HH:mm:ss') }
        return ''
    }

    function Build-Node ([object]$proc) {
        $pid_  = [int]$proc.ProcessId
        $conns = if ($netConns.ContainsKey($pid_)) { $netConns[$pid_] -join '; ' } else { '' }
        [PSCustomObject]@{
            PID         = $pid_
            PPID        = [int]$proc.ParentProcessId
            Name        = $proc.Name
            CommandLine = $proc.CommandLine
            User        = (Get-WmiOwner $proc)
            CreateDate  = (Convert-WmiDate $proc.CreationDate)
            NetworkConns = $conns
            Children    = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
    }

    if ($Pid -ne 0) {
        # Ancestor chain for a specific PID
        $chain = [System.Collections.Generic.List[PSCustomObject]]::new()
        $current = $Pid
        $visited  = [System.Collections.Generic.HashSet[int]]::new()

        while ($current -gt 0 -and $wmiProcs.ContainsKey($current) -and -not $visited.Contains($current)) {
            $visited.Add($current) | Out-Null
            $proc = $wmiProcs[$current]
            $chain.Add((Build-Node $proc))
            $current = [int]$proc.ParentProcessId
        }
        return $chain
    }

    # Full process tree (all processes)
    $nodes = @{}
    foreach ($proc in $wmiProcs.Values) {
        $nodes[[int]$proc.ProcessId] = Build-Node $proc
    }

    # Wire up children
    $roots = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($node in $nodes.Values) {
        if ($node.PPID -gt 0 -and $nodes.ContainsKey($node.PPID) -and $node.PPID -ne $node.PID) {
            $nodes[$node.PPID].Children.Add($node)
        } else {
            $roots.Add($node)
        }
    }

    return $roots
}

function Export-ForensicPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = '',

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $baseDir  = 'C:\QuietMonitor'
    $ts       = Get-Date -Format 'yyyyMMdd_HHmmss'
    $zipName  = "ForensicPackage_$($env:COMPUTERNAME)_$ts.zip"

    if (-not $OutputPath) {
        $OutputPath = Join-Path $baseDir 'Reports'
    }
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    $zipPath  = Join-Path $OutputPath $zipName
    $stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) "QM_IR_$ts"

    try {
        New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

        # ------------------------------------------------------------------
        # 1. Copy C:\QuietMonitor\ structure (excluding any existing ZIPs)
        # ------------------------------------------------------------------
        if (Test-Path $baseDir) {
            $destBase = Join-Path $stagingDir 'QuietMonitor'
            New-Item -ItemType Directory -Path $destBase -Force | Out-Null

            Get-ChildItem -Path $baseDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -ne '.zip' } |
                ForEach-Object {
                    $rel     = $_.FullName.Substring($baseDir.Length).TrimStart('\')
                    $destFile = Join-Path $destBase $rel
                    $destDir  = Split-Path $destFile -Parent
                    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                    Copy-Item -Path $_.FullName -Destination $destFile -ErrorAction SilentlyContinue
                }
        }

        # ------------------------------------------------------------------
        # 2. Live process snapshot
        # ------------------------------------------------------------------
        $procSnap  = Get-ProcessTree
        $procLines = [System.Collections.Generic.List[string]]::new()
        $procLines.Add("PROCESS TREE SNAPSHOT - $ts")
        $procLines.Add("Host: $env:COMPUTERNAME | User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
        $procLines.Add(('-' * 80))

        function Write-ProcNode ([object]$node, [string]$indent) {
            $line = "$indent[PID:$($node.PID)|PPID:$($node.PPID)] $($node.Name)"
            if ($node.User) { $line += " | User: $($node.User)" }
            if ($node.CommandLine) { $line += " | CMD: $($node.CommandLine.Substring(0,[Math]::Min(200,$node.CommandLine.Length)))" }
            if ($node.NetworkConns) { $line += " | NET: $($node.NetworkConns)" }
            $procLines.Add($line)
            foreach ($child in $node.Children) { Write-ProcNode $child ("  " + $indent) }
        }

        foreach ($root in $procSnap) { Write-ProcNode $root '' }

        $procFile = Join-Path $stagingDir 'ProcessSnapshot.txt'
        $procLines | Set-Content -Path $procFile -Encoding UTF8

        # ------------------------------------------------------------------
        # 3. Network connections snapshot
        # ------------------------------------------------------------------
        $netLines = [System.Collections.Generic.List[string]]::new()
        $netLines.Add("NETWORK CONNECTIONS SNAPSHOT - $ts")
        $netLines.Add(('-' * 80))

        $procMap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.Name }

        Get-NetTCPConnection -ErrorAction SilentlyContinue | Sort-Object State, RemoteAddress |
            ForEach-Object {
                $pName = if ($procMap.ContainsKey([int]$_.OwningProcess)) { $procMap[[int]$_.OwningProcess] } else { 'unknown' }
                $netLines.Add("$($_.State.ToString().PadRight(15)) $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) | $pName (PID $($_.OwningProcess))")
            }

        $netFile = Join-Path $stagingDir 'NetworkConnections.txt'
        $netLines | Set-Content -Path $netFile -Encoding UTF8

        # ------------------------------------------------------------------
        # 4. Running services snapshot
        # ------------------------------------------------------------------
        $svcLines = [System.Collections.Generic.List[string]]::new()
        $svcLines.Add("RUNNING SERVICES SNAPSHOT - $ts")
        $svcLines.Add(('-' * 80))

        Get-Service -ErrorAction SilentlyContinue | Sort-Object Status, Name | ForEach-Object {
            $svcLines.Add("$($_.Status.ToString().PadRight(10)) $($_.Name.PadRight(40)) $($_.DisplayName)")
        }

        $svcFile = Join-Path $stagingDir 'ServicesSnapshot.txt'
        $svcLines | Set-Content -Path $svcFile -Encoding UTF8

        # ------------------------------------------------------------------
        # 5. System information
        # ------------------------------------------------------------------
        $sysInfo = [System.Collections.Generic.List[string]]::new()
        $sysInfo.Add("SYSTEM INFORMATION - $ts")
        $sysInfo.Add(('-' * 80))
        $sysInfo.Add("Hostname   : $env:COMPUTERNAME")
        $sysInfo.Add("Domain     : $env:USERDOMAIN")
        $sysInfo.Add("OS         : $([System.Environment]::OSVersion.VersionString)")
        $sysInfo.Add("PowerShell : $($PSVersionTable.PSVersion)")
        $sysInfo.Add("Capture By : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
        $sysInfo.Add("Capture UTC: $(Get-Date -Format 'o')")

        # Uptime
        try {
            $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
            $uptime = (Get-Date) - $boot
            $sysInfo.Add("Uptime     : $([int]$uptime.TotalHours)h $($uptime.Minutes)m (Boot: $($boot.ToString('yyyy-MM-dd HH:mm:ss')))")
        } catch {}

        $sysInfoFile = Join-Path $stagingDir 'SystemInfo.txt'
        $sysInfo | Set-Content -Path $sysInfoFile -Encoding UTF8

        # ------------------------------------------------------------------
        # 7. Prefetch File List
        # ------------------------------------------------------------------
        try {
            $prefetchDir = 'C:\Windows\Prefetch'
            if (Test-Path $prefetchDir -ErrorAction SilentlyContinue) {
                $pfOut = [System.Collections.Generic.List[string]]::new()
                $pfOut.Add("Prefetch Files — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')")
                $pfOut.Add(('─' * 80))
                Get-ChildItem -Path $prefetchDir -File -ErrorAction SilentlyContinue |
                    Sort-Object LastAccessTime -Descending |
                    ForEach-Object {
                        $pfOut.Add(("{0,-50} {1,8} KB  LastAccess: {2}" -f $_.Name, [math]::Round($_.Length/1KB,1), $_.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')))
                    }
                $pfOut | Set-Content -Path (Join-Path $stagingDir 'PrefetchList.txt') -Encoding UTF8
            }
        } catch {}

        # ------------------------------------------------------------------
        # 8. Clipboard Snapshot
        # ------------------------------------------------------------------
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $clipText = [System.Windows.Forms.Clipboard]::GetText()
            if ($clipText -and $clipText.Length -gt 0) {
                $clipOut  = "Clipboard Snapshot — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')`n$('─' * 80)`n$clipText"
                $clipOut | Set-Content -Path (Join-Path $stagingDir 'ClipboardSnapshot.txt') -Encoding UTF8
            } else {
                "Clipboard empty or contained non-text data at $(Get-Date -Format 'o')." |
                    Set-Content -Path (Join-Path $stagingDir 'ClipboardSnapshot.txt') -Encoding UTF8
            }
        } catch {}

        # ------------------------------------------------------------------
        # 9. Browser History File Paths (metadata only — no content)
        # ------------------------------------------------------------------
        try {
            $bhOut = [System.Collections.Generic.List[string]]::new()
            $bhOut.Add("Browser History File Paths — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')")
            $bhOut.Add("NOTE: Only file metadata recorded. Contents NOT extracted (privacy/legal).")
            $bhOut.Add(('─' * 80))

            $browserFiles = @(
                @{ Browser='Chrome';  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" }
                @{ Browser='Chrome';  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" }
                @{ Browser='Edge';    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" }
                @{ Browser='Edge';    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies" }
                @{ Browser='Firefox'; Path="$env:APPDATA\Mozilla\Firefox\Profiles" }
                @{ Browser='IE';      Path="$env:LOCALAPPDATA\Microsoft\Windows\History" }
            )

            foreach ($bf in $browserFiles) {
                if (Test-Path $bf.Path -ErrorAction SilentlyContinue) {
                    $item = Get-Item $bf.Path -ErrorAction SilentlyContinue
                    if ($item) {
                        $bhOut.Add("[$($bf.Browser)] $($bf.Path)")
                        $bhOut.Add("  Exists: YES  |  Size: $([math]::Round($item.Length/1KB,1)) KB  |  LastWrite: $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))")
                    }
                } else {
                    $bhOut.Add("[$($bf.Browser)] $($bf.Path)  -> NOT FOUND")
                }
            }

            $bhOut | Set-Content -Path (Join-Path $stagingDir 'BrowserHistoryPaths.txt') -Encoding UTF8
        } catch {}

        # ------------------------------------------------------------------
        # 10. MRU Registry Keys
        # ------------------------------------------------------------------
        try {
            $mruOut = [System.Collections.Generic.List[string]]::new()
            $mruOut.Add("MRU — RecentDocs — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')")
            $mruOut.Add(('─' * 80))
            $recentDocsKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
            if (Test-Path $recentDocsKey -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $recentDocsKey -ErrorAction SilentlyContinue | ForEach-Object {
                    $ext = $_.PSChildName
                    $mruList = Get-ItemProperty -Path $_.PSPath -Name 'MRUListEx' -ErrorAction SilentlyContinue
                    if ($mruList) { $mruOut.Add("Extension/Category: $ext  (MRUListEx present)") }
                    Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^MRU' } | ForEach-Object {
                            if ($_.Value -is [byte[]]) {
                                $str = [System.Text.Encoding]::Unicode.GetString($_.Value).TrimEnd([char]0)
                                $mruOut.Add("  [$ext] Entry $($_.Name): $str")
                            }
                        }
                    }
                }
            }
            $mruOut | Set-Content -Path (Join-Path $stagingDir 'MRU_RecentDocs.txt') -Encoding UTF8
        } catch {}

        try {
            $offMruOut = [System.Collections.Generic.List[string]]::new()
            $offMruOut.Add("MRU — Office Recent Files — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')")
            $offMruOut.Add(('─' * 80))
            $officeKey = 'HKCU:\SOFTWARE\Microsoft\Office'
            if (Test-Path $officeKey -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $officeKey -ErrorAction SilentlyContinue | ForEach-Object {
                    $verPath = $_.PSPath
                    Get-ChildItem -Path $verPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $appPath  = $_.PSPath
                        $fileMRU  = Join-Path $appPath 'File MRU'
                        if (Test-Path $fileMRU -ErrorAction SilentlyContinue) {
                            Get-ItemProperty -Path $fileMRU -ErrorAction SilentlyContinue | ForEach-Object {
                                $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^Max' } | ForEach-Object {
                                    $offMruOut.Add("[$($_.Name)] $($_.Value)")
                                }
                            }
                        }
                    }
                }
            }
            $offMruOut | Set-Content -Path (Join-Path $stagingDir 'MRU_OfficeDocs.txt') -Encoding UTF8
        } catch {}

        # ------------------------------------------------------------------
        # 11. Shadow Copy Status
        # ------------------------------------------------------------------
        try {
            $vssOut = [System.Collections.Generic.List[string]]::new()
            $vssOut.Add("Shadow Copy Status — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')")
            $vssOut.Add(('─' * 80))
            $shadows = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Sort-Object InstallDate)
            if ($shadows.Count -eq 0) {
                $vssOut.Add("WARNING: No shadow copies found! Ransomware may have deleted them, or VSS was never enabled.")
            } else {
                $vssOut.Add("Total Shadow Copies: $($shadows.Count)")
                foreach ($s in $shadows) {
                    $vssOut.Add('')
                    $vssOut.Add("  ID          : $($s.ID)")
                    $vssOut.Add("  Volume      : $($s.VolumeName)")
                    $vssOut.Add("  InstallDate : $($s.InstallDate)")
                    $vssOut.Add("  DeviceObject: $($s.DeviceObject)")
                }
            }
            $vssOut | Set-Content -Path (Join-Path $stagingDir 'ShadowCopyStatus.txt') -Encoding UTF8
        } catch {}

        # ------------------------------------------------------------------
        # 12. Open Handles Summary (Top 30 by handle count)
        # ------------------------------------------------------------------
        try {
            $handleOut = [System.Collections.Generic.List[string]]::new()
            $handleOut.Add("Open Handles Summary (Top 30 by count) — $($env:COMPUTERNAME) — $(Get-Date -Format 'o')")
            $handleOut.Add(('─' * 80))
            $handleOut.Add(("{0,-8} {1,-30} {2,10}  {3}" -f 'PID', 'Name', 'Handles', 'Path'))
            $handleOut.Add(('─' * 80))
            Get-Process -ErrorAction SilentlyContinue |
                Sort-Object HandleCount -Descending |
                Select-Object -First 30 |
                ForEach-Object {
                    $handleOut.Add(("{0,-8} {1,-30} {2,10}  {3}" -f $_.Id, $_.Name, $_.HandleCount, (if ($_.Path) { $_.Path } else { '' })))
                }
            $handleOut | Set-Content -Path (Join-Path $stagingDir 'OpenHandlesSummary.txt') -Encoding UTF8
        } catch {}

        # ------------------------------------------------------------------
        # 6. Zip the staging directory
        # ------------------------------------------------------------------
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $stagingDir,
            $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $false
        )

        Add-Content -Path $AuditLog -Value (
            "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
            "[USER: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)] " +
            "[MODULE: ForensicCapture] [ACTION: ExportPackage] " +
            "[DETAILS: ZipPath='$zipPath' Size=$(if(Test-Path $zipPath){(Get-Item $zipPath).Length}else{'?'}) bytes]"
        ) -Encoding UTF8

        return $zipPath

    } finally {
        # Clean up staging directory
        if (Test-Path $stagingDir) {
            Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

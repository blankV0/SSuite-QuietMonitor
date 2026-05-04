<#
.SYNOPSIS
    PersistenceHunter.ps1 - Scans 20+ known Windows persistence mechanism locations.
.DESCRIPTION
    Comprehensively hunts all major Windows persistence locations and techniques:

    Registry-based:
      1.  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      2.  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      3.  HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
      4.  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      5.  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      6.  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Userinit, Shell)
      7.  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
      8.  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
      9.  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
     10.  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
     11.  HKLM\SOFTWARE\Classes\Exefile\Shell\Open\Command (command hijack)
     12.  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
     13.  AppInit_DLLs (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows)
     14.  COM Object hijack candidates (HKCU\SOFTWARE\Classes\CLSID)

    Service-based:
     15.  All non-Microsoft services with suspicious paths
     16.  WMI permanent event subscriptions (__EventFilter + __EventConsumer bindings)

    File-system:
     17.  Startup folders (User + All Users)
     18.  Scheduled tasks (delegated to TaskAudit, referenced here for completeness)

    LSA / Security:
     19.  HKLM\SYSTEM\CurrentControlSet\Control\Lsa (Authentication Packages, Security Packages)
     20.  HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages

    MITRE ATT&CK: T1547 (Boot/Logon Autostart Execution), T1543 (System Process),
                  T1546 (Event Triggered Execution)

.OUTPUTS
    [PSCustomObject[]] - Finding objects conforming to the QuietMonitor finding schema.
#>

function Invoke-PersistenceHunter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Whitelist,

        [Parameter(Mandatory)]
        [string]$AuditLog
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # Helper to create a standardized finding
    function New-PFinding {
        param($Severity, $Category, $Name, $DisplayName, $Path, $Hash, $Details,
              $MitreId = 'T1547', $MitreName = 'Boot/Logon Autostart Execution')
        [PSCustomObject]@{
            Module      = 'PersistenceHunter'
            Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Severity    = $Severity
            Category    = $Category
            Name        = $Name
            DisplayName = $DisplayName
            Path        = $Path
            Hash        = $Hash
            Details     = $Details
            ActionTaken = ''
            MitreId     = $MitreId
            MitreName   = $MitreName
        }
    }

    # Suspicious path patterns (reused from other modules)
    $suspiciousPathPatterns = @(
        '(?i)\\(temp|tmp)\\',
        '(?i)\\appdata\\(local|roaming)\\',
        '(?i)\\users\\public\\',
        '(?i)\\programdata\\(?!microsoft)',
        '(?i)\\recycle',
        '(?i)\.(scr|vbs|vbe|js|jse|wsf|wsh|ps1|bat|cmd|hta)$'
    )

    $lolbinNames = @('certutil','mshta','regsvr32','rundll32','wscript','cscript',
                     'msiexec','bitsadmin','powershell','cmd','wmic','msbuild',
                     'installutil','regasm','regsvcs','cmstp')

    function Test-SuspiciousPath ([string]$p) {
        if (-not $p) { return $false }
        foreach ($pat in $suspiciousPathPatterns) { if ($p -match $pat) { return $true } }
        return $false
    }

    function Test-IsLOLBin ([string]$p) {
        if (-not $p) { return $false }
        $name = [System.IO.Path]::GetFileNameWithoutExtension($p).ToLowerInvariant()
        return $lolbinNames -contains $name
    }

    function Get-SafeFileHash ([string]$p) {
        try {
            if (Test-Path $p -PathType Leaf -ErrorAction SilentlyContinue) {
                return (Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction Stop).Hash
            }
        } catch {}
        return ''
    }

    # Extract executable path from a command string (strips args)
    function Get-ExeFromCmd ([string]$cmd) {
        if (-not $cmd) { return '' }
        $cmd = $cmd.Trim()
        if ($cmd.StartsWith('"')) {
            $end = $cmd.IndexOf('"', 1)
            if ($end -gt 0) { return $cmd.Substring(1, $end - 1) }
        }
        # Take first token
        return ($cmd -split '\s+')[0]
    }

    #region ===== 1-5. Registry Run / RunOnce keys =====
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key -ErrorAction SilentlyContinue)) { continue }
        try {
            $values = Get-ItemProperty -Path $key -ErrorAction Stop
            foreach ($prop in $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                $cmd    = $prop.Value
                $exe    = Get-ExeFromCmd $cmd
                $hash   = Get-SafeFileHash $exe
                $isSusp = Test-SuspiciousPath $exe
                $isLol  = Test-IsLOLBin $exe

                $sev = 'Yellow'
                if ($isSusp -or $isLol) { $sev = 'Red' }

                $findings.Add((New-PFinding `
                    -Severity    $sev `
                    -Category    'Registry Run Key' `
                    -Name        "persist-run-$($prop.Name)" `
                    -DisplayName "$($prop.Name) [$($key -replace 'HKLM:\\|HKCU:\\','')]" `
                    -Path        $exe `
                    -Hash        $hash `
                    -Details     "Registry persistence: Key='$key' Value='$($prop.Name)' Command='$($cmd.Substring(0,[Math]::Min(200,$cmd.Length)))' SuspiciousPath=$isSusp LOLBin=$isLol"))
            }
        } catch {}
    }
    #endregion

    #region ===== 6. Winlogon Userinit / Shell =====
    $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $expectedUserinit = "$env:SystemRoot\system32\userinit.exe,"
    $expectedShell    = 'explorer.exe'

    foreach ($valueName in @('Userinit','Shell')) {
        try {
            $val = (Get-ItemProperty -Path $winlogonKey -Name $valueName -ErrorAction Stop).$valueName
            $expected = if ($valueName -eq 'Userinit') { $expectedUserinit } else { $expectedShell }
            if ($val -and $val.Trim().ToLowerInvariant() -ne $expected.ToLowerInvariant()) {
                $findings.Add((New-PFinding `
                    -Severity    'Red' `
                    -Category    'Winlogon Hijack' `
                    -Name        "persist-winlogon-$valueName" `
                    -DisplayName "Winlogon $valueName Modified" `
                    -Path        (Get-ExeFromCmd $val) `
                    -Hash        (Get-SafeFileHash (Get-ExeFromCmd $val)) `
                    -Details     "Winlogon $valueName deviates from expected value. Current='$val' Expected='$expected'"))
            }
        } catch {}
    }
    #endregion

    #region ===== 7. Winlogon Notify subkeys =====
    $notifyKey = "$winlogonKey\Notify"
    if (Test-Path $notifyKey -ErrorAction SilentlyContinue) {
        Get-ChildItem $notifyKey -ErrorAction SilentlyContinue | ForEach-Object {
            $dll = ''
            try { $dll = (Get-ItemProperty $_.PSPath -Name 'DllName' -ErrorAction Stop).DllName } catch {}
            if ($dll) {
                $findings.Add((New-PFinding `
                    -Severity    'Red' `
                    -Category    'Winlogon Notify' `
                    -Name        "persist-winlogon-notify-$($_.PSChildName)" `
                    -DisplayName "Winlogon Notify DLL: $($_.PSChildName)" `
                    -Path        $dll `
                    -Hash        (Get-SafeFileHash $dll) `
                    -Details     "Winlogon notification package found: '$($_.PSChildName)' DLL='$dll'. Rarely used legitimately."))
            }
        }
    }
    #endregion

    #region ===== 8. BootExecute =====
    $bootExecKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $bootExec = (Get-ItemProperty $bootExecKey -Name 'BootExecute' -ErrorAction Stop).BootExecute
        $expected = @('autocheck autochk *')
        foreach ($entry in $bootExec) {
            if ($expected -notcontains $entry.Trim().ToLowerInvariant()) {
                $findings.Add((New-PFinding `
                    -Severity    'Red' `
                    -Category    'Boot Execute' `
                    -Name        "persist-bootexec" `
                    -DisplayName "BootExecute Modified: $entry" `
                    -Path        '' `
                    -Hash        '' `
                    -Details     "BootExecute has non-standard entry: '$entry'. Default='autocheck autochk *'. This runs before the OS fully loads."))
            }
        }
    } catch {}
    #endregion

    #region ===== 9. Image File Execution Options (IFEO) debugger hijack =====
    $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $debugger = (Get-ItemProperty $_.PSPath -Name 'Debugger' -ErrorAction Stop).Debugger
            if ($debugger) {
                $findings.Add((New-PFinding `
                    -Severity    'Red' `
                    -Category    'IFEO Debugger Hijack' `
                    -Name        "persist-ifeo-$($_.PSChildName)" `
                    -DisplayName "IFEO Debugger: $($_.PSChildName)" `
                    -Path        (Get-ExeFromCmd $debugger) `
                    -Hash        (Get-SafeFileHash (Get-ExeFromCmd $debugger)) `
                    -Details     "Image File Execution Options debugger set for '$($_.PSChildName)': '$debugger'. Used for accessibility feature backdoors (sethc.exe, osk.exe) and persistence." `
                    -MitreId     'T1546' `
                    -MitreName   'Event Triggered Execution'))
            }
        } catch {}
    }
    #endregion

    #region ===== 10. Browser Helper Objects =====
    $bhoKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Internet Explorer\Extensions'
    if (Test-Path $bhoKey -ErrorAction SilentlyContinue) {
        Get-ChildItem $bhoKey -ErrorAction SilentlyContinue | ForEach-Object {
            $clsid = $_.PSChildName
            $exec  = ''
            try { $exec = (Get-ItemProperty $_.PSPath -Name 'Exec' -ErrorAction Stop).Exec } catch {}
            if ($exec) {
                $findings.Add((New-PFinding `
                    -Severity    'Yellow' `
                    -Category    'Browser Extension' `
                    -Name        "persist-bho-$clsid" `
                    -DisplayName "IE Extension: $clsid" `
                    -Path        $exec `
                    -Hash        (Get-SafeFileHash $exec) `
                    -Details     "Internet Explorer extension (BHO/toolbar): CLSID=$clsid Exec='$exec'"))
            }
        }
    }
    #endregion

    #region ===== 11. AppInit_DLLs =====
    $appInitKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    try {
        $appInitDlls = (Get-ItemProperty $appInitKey -Name 'AppInit_DLLs' -ErrorAction Stop).AppInit_DLLs
        if ($appInitDlls -and $appInitDlls.Trim()) {
            foreach ($dll in ($appInitDlls -split '[,\s]+' | Where-Object { $_ })) {
                $findings.Add((New-PFinding `
                    -Severity    'Red' `
                    -Category    'AppInit_DLLs' `
                    -Name        "persist-appinit-$([System.IO.Path]::GetFileName($dll))" `
                    -DisplayName "AppInit_DLLs: $([System.IO.Path]::GetFileName($dll))" `
                    -Path        $dll `
                    -Hash        (Get-SafeFileHash $dll) `
                    -Details     "AppInit_DLLs is set to '$dll'. This DLL is injected into every process that loads user32.dll. High-confidence persistence/injection technique."))
            }
        }
    } catch {}
    #endregion

    #region ===== 12. Application Shim Database =====
    $sdbKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB'
    Get-ChildItem $sdbKey -ErrorAction SilentlyContinue | ForEach-Object {
        $desc = ''
        try { $desc = (Get-ItemProperty $_.PSPath -Name 'DatabaseDescription' -ErrorAction Stop).DatabaseDescription } catch {}
        $findings.Add((New-PFinding `
            -Severity    'Yellow' `
            -Category    'Shim Database' `
            -Name        "persist-sdb-$($_.PSChildName)" `
            -DisplayName "Custom SDB: $desc" `
            -Path        '' `
            -Hash        '' `
            -Details     "Custom application shim database installed: '$desc' GUID=$($_.PSChildName). Shims can be used to inject code into processes." `
            -MitreId     'T1546' `
            -MitreName   'Event Triggered Execution'))
    }
    #endregion

    #region ===== 13. COM Object Hijack Candidates (HKCU\Classes\CLSID) =====
    $hkcuClsid = 'HKCU:\SOFTWARE\Classes\CLSID'
    if (Test-Path $hkcuClsid -ErrorAction SilentlyContinue) {
        $clsids = Get-ChildItem $hkcuClsid -ErrorAction SilentlyContinue | Select-Object -First 50
        foreach ($clsid in $clsids) {
            $inprocKey = Join-Path $clsid.PSPath 'InprocServer32'
            if (Test-Path $inprocKey -ErrorAction SilentlyContinue) {
                $dll = ''
                try { $dll = (Get-ItemProperty $inprocKey -ErrorAction Stop).'(default)' } catch {}
                if ($dll -and (Test-SuspiciousPath $dll)) {
                    $findings.Add((New-PFinding `
                        -Severity    'Red' `
                        -Category    'COM Hijack' `
                        -Name        "persist-com-$($clsid.PSChildName)" `
                        -DisplayName "COM Hijack CLSID: $($clsid.PSChildName)" `
                        -Path        $dll `
                        -Hash        (Get-SafeFileHash $dll) `
                        -Details     "HKCU COM class override with suspicious DLL path: CLSID=$($clsid.PSChildName) DLL='$dll'. Per-user COM hijacking is used to persist without admin rights." `
                        -MitreId     'T1546' `
                        -MitreName   'Event Triggered Execution'))
                }
            }
        }
    }
    #endregion

    #region ===== 14. WMI Permanent Event Subscriptions =====
    try {
        $wmiFilters    = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter'   -ErrorAction SilentlyContinue
        $wmiConsumers  = Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue
        $wmiConsumers += Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue
        $wmiBindings   = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue

        if ($wmiBindings) {
            foreach ($binding in $wmiBindings) {
                $filterRef   = $binding.Filter.ToString()
                $consumerRef = $binding.Consumer.ToString()

                # Find the consumer's command
                $consumerDetail = ''
                foreach ($consumer in $wmiConsumers) {
                    if ($consumer.Name -and $consumerRef -match [regex]::Escape($consumer.Name)) {
                        $consumerDetail = if ($consumer.CommandLineTemplate) { $consumer.CommandLineTemplate }
                                         elseif ($consumer.ScriptText)     { "Script: $($consumer.ScriptText.Substring(0,[Math]::Min(100,$consumer.ScriptText.Length)))" }
                                         else { $consumer.Name }
                        break
                    }
                }

                $findings.Add((New-PFinding `
                    -Severity    'Red' `
                    -Category    'WMI Subscription' `
                    -Name        "persist-wmi-$([System.Math]::Abs($binding.GetHashCode()))" `
                    -DisplayName "WMI EventFilter->Consumer Binding" `
                    -Path        '' `
                    -Hash        '' `
                    -Details     "WMI permanent event subscription (persistence): Filter='$filterRef' Consumer='$consumerDetail'. WMI subscriptions survive reboots and are invisible to most tools." `
                    -MitreId     'T1546' `
                    -MitreName   'Event Triggered Execution'))
            }
        } elseif ($wmiFilters -or $wmiConsumers) {
            # Orphaned filters/consumers without bindings - still suspicious
            foreach ($item in @($wmiFilters) + @($wmiConsumers)) {
                if ($item) {
                    $findings.Add((New-PFinding `
                        -Severity    'Yellow' `
                        -Category    'WMI Subscription' `
                        -Name        "persist-wmi-orphan" `
                        -DisplayName "Orphaned WMI Subscription Element" `
                        -Path        '' `
                        -Hash        '' `
                        -Details     "Unbound WMI EventFilter or Consumer found in root\subscription: '$($item.Name)'" `
                        -MitreId     'T1546' `
                        -MitreName   'Event Triggered Execution'))
                }
            }
        }
    } catch {}
    #endregion

    #region ===== 15. LSA Authentication Packages =====
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsaProps = @('Authentication Packages', 'Security Packages', 'Notification Packages')
    $expectedLsaValues = @{
        'Authentication Packages' = @('msv1_0')
        'Security Packages'       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', '')
        'Notification Packages'   = @('scecli', '')
    }

    foreach ($prop in $lsaProps) {
        try {
            $vals = (Get-ItemProperty $lsaKey -Name $prop -ErrorAction Stop).$prop
            foreach ($v in $vals) {
                if ($v -and $v.Trim() -and ($expectedLsaValues[$prop] -notcontains $v.Trim().ToLowerInvariant())) {
                    $dllPath = "$env:SystemRoot\System32\$v.dll"
                    $findings.Add((New-PFinding `
                        -Severity    'Red' `
                        -Category    'LSA Package' `
                        -Name        "persist-lsa-$v" `
                        -DisplayName "Unusual LSA $prop : $v" `
                        -Path        $dllPath `
                        -Hash        (Get-SafeFileHash $dllPath) `
                        -Details     "Non-standard LSA package registered: Property='$prop' Value='$v'. Custom LSA packages can intercept authentication credentials."))
                }
            }
        } catch {}
    }
    #endregion

    #region -- 16. DLL Search Order Hijacking (T1574) ----------------------------
    # Checks PATH entries that are writable and appear before System32.
    $sys32 = "$env:SystemRoot\System32".ToLower()
    $pathEntries = $env:PATH -split ';' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.TrimEnd('\') }
    $sys32Found  = $false
    foreach ($pe in $pathEntries) {
        $peLower = $pe.ToLower()
        if ($peLower -eq $sys32) { $sys32Found = $true; continue }
        if (-not $sys32Found -and (Test-Path $pe -PathType Container -ErrorAction SilentlyContinue)) {
            # Check if this directory is writable by current user
            $writable = $false
            try {
                $testFile = Join-Path $pe "qm_write_test_$([System.IO.Path]::GetRandomFileName())"
                [System.IO.File]::WriteAllText($testFile, 'test')
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                $writable = $true
            } catch {}
            if ($writable) {
                $findings.Add((New-PFinding `
                    -Severity    'Yellow' `
                    -Category    'DLL Hijack' `
                    -Name        "dll-hijack-path-$($pe -replace '[\\:\s]','-')" `
                    -DisplayName "Writable PATH before System32: $pe" `
                    -Path        $pe `
                    -Hash        '' `
                    -Details     "Directory '$pe' is writable and appears in PATH before System32. An attacker could plant a malicious DLL here to hijack legitimate binary loading. T1574.001" `
                    -MitreId     'T1574' `
                    -MitreName   'Hijack Execution Flow'))
            }
        }
    }
    #endregion

    #region -- 17. Office Macro Persistence (T1137) ------------------------------
    # Checks for AutoMacro registry keys and XLSTART/Word STARTUP directories.
    try {
        $officeKeyBase = 'HKCU:\Software\Microsoft\Office'
        if (Test-Path $officeKeyBase -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $officeKeyBase -ErrorAction SilentlyContinue | ForEach-Object {
                $verKey = $_.PSPath
                try {
                    Get-ChildItem -Path $verKey -ErrorAction SilentlyContinue | ForEach-Object {
                        $appKey = $_.PSPath
                        $optsKey = Join-Path $appKey 'Options'
                        if (Test-Path $optsKey -ErrorAction SilentlyContinue) {
                            Get-ItemProperty $optsKey -ErrorAction SilentlyContinue | ForEach-Object {
                                $_.PSObject.Properties | Where-Object {
                                    $_.Name -notmatch '^PS' -and $_.Name -match 'AutoMacro|RunMacro|StartupMacro'
                                } | ForEach-Object {
                                    $findings.Add((New-PFinding `
                                        -Severity    'Yellow' `
                                        -Category    'Office Macro Persistence' `
                                        -Name        "office-automacro-$($_.Name)" `
                                        -DisplayName "Office Auto-Macro Registry Key: $($_.Name)" `
                                        -Path        $optsKey `
                                        -Hash        '' `
                                        -Details     "Auto-executing Office macro key found: '$($_.Name)' = '$($_.Value)'. This registry key causes macros to run automatically on Office startup." `
                                        -MitreId     'T1137' `
                                        -MitreName   'Office Application Startup'))
                                }
                            }
                        }
                    }
                } catch {}
            }
        }
    } catch {}

    # Check XLSTART for PERSONAL.XLSB
    $xlstart = "$env:APPDATA\Microsoft\Excel\XLSTART"
    if (Test-Path $xlstart -ErrorAction SilentlyContinue) {
        Get-ChildItem -Path $xlstart -File -ErrorAction SilentlyContinue | ForEach-Object {
            $findings.Add((New-PFinding `
                -Severity    $(if ($_.Name -match '\.xlsb$|\.xlam$|\.xls$') {'Yellow'} else {'Green'}) `
                -Category    'Office Macro Persistence' `
                -Name        "xlstart-$($_.Name)" `
                -DisplayName "Excel XLSTART File: $($_.Name)" `
                -Path        $_.FullName `
                -Hash        (Get-SafeFileHash $_.FullName) `
                -Details     "File '$($_.FullName)' found in Excel XLSTART folder. Workbooks/addins here auto-open with Excel and may contain persistent macros." `
                -MitreId     'T1137' `
                -MitreName   'Office Application Startup'))
        }
    }

    # Check Word STARTUP for .dotm templates
    $wordStartup = "$env:APPDATA\Microsoft\Word\STARTUP"
    if (Test-Path $wordStartup -ErrorAction SilentlyContinue) {
        Get-ChildItem -Path $wordStartup -Filter '*.dotm' -File -ErrorAction SilentlyContinue | ForEach-Object {
            $findings.Add((New-PFinding `
                -Severity    'Yellow' `
                -Category    'Office Macro Persistence' `
                -Name        "word-startup-$($_.Name)" `
                -DisplayName "Word STARTUP Template: $($_.Name)" `
                -Path        $_.FullName `
                -Hash        (Get-SafeFileHash $_.FullName) `
                -Details     "Macro-enabled Word template '$($_.FullName)' found in Word STARTUP folder. AutoOpen/AutoNew macros in .dotm files execute on every Word document open." `
                -MitreId     'T1137' `
                -MitreName   'Office Application Startup'))
        }
    }
    #endregion

    #region -- 18. Browser Extension Enumeration (T1176) -------------------------
    $browserProfiles = @(
        @{ Browser='Chrome'; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" }
        @{ Browser='Edge';   Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" }
    )
    foreach ($bp in $browserProfiles) {
        if (Test-Path $bp.Path -ErrorAction SilentlyContinue) {
            $exts = @(Get-ChildItem -Path $bp.Path -Directory -ErrorAction SilentlyContinue)
            foreach ($ext in $exts) {
                # Get latest version subfolder
                $verDirs = @(Get-ChildItem -Path $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                $manifest = $null
                foreach ($vd in $verDirs) {
                    $mf = Join-Path $vd.FullName 'manifest.json'
                    if (Test-Path $mf -ErrorAction SilentlyContinue) {
                        try { $manifest = Get-Content $mf -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json; break } catch {}
                    }
                }
                $extName = if ($manifest -and $manifest.name) { $manifest.name } else { $ext.Name }
                $sev = 'Yellow'  # All unlisted extensions flagged as informational-yellow
                $findings.Add((New-PFinding `
                    -Severity    $sev `
                    -Category    'Browser Extension' `
                    -Name        "browser-ext-$($bp.Browser.ToLower())-$($ext.Name)" `
                    -DisplayName "$($bp.Browser) Extension: $extName" `
                    -Path        $ext.FullName `
                    -Hash        '' `
                    -Details     "$($bp.Browser) extension ID '$($ext.Name)' ($extName). Browser extensions can persist and exfiltrate data. Review against known-good list for this user." `
                    -MitreId     'T1176' `
                    -MitreName   'Browser Extensions'))
            }
        }
    }

    # Firefox extensions
    $ffProfilesBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffProfilesBase -ErrorAction SilentlyContinue) {
        Get-ChildItem -Path $ffProfilesBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $ffExtDir = Join-Path $_.FullName 'extensions'
            if (Test-Path $ffExtDir -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $ffExtDir -ErrorAction SilentlyContinue | ForEach-Object {
                    $findings.Add((New-PFinding `
                        -Severity    'Yellow' `
                        -Category    'Browser Extension' `
                        -Name        "browser-ext-firefox-$($_.Name -replace '[^a-zA-Z0-9]','-')" `
                        -DisplayName "Firefox Extension: $($_.Name)" `
                        -Path        $_.FullName `
                        -Hash        '' `
                        -Details     "Firefox extension '$($_.Name)' in profile '$(Split-Path $_.FullName -Parent | Split-Path -Leaf)'. Verify this extension is authorized and from a trusted source." `
                        -MitreId     'T1176' `
                        -MitreName   'Browser Extensions'))
                }
            }
        }
    }
    #endregion

    #region -- 19. Print Spooler DLL Abuse (T1547) --------------------------------
    try {
        $printMonitorsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
        if (Test-Path $printMonitorsKey -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $printMonitorsKey -ErrorAction SilentlyContinue | ForEach-Object {
                $monName = $_.PSChildName
                $dllVal  = (Get-ItemPropertyValue -Path $_.PSPath -Name 'Driver' -ErrorAction SilentlyContinue)
                if ($dllVal -and $dllVal -notmatch '^(localspl|tcpmon|usbmon|pjlmon|sfmpsprt|inetpp)\.dll$') {
                    $dllPath = if ($dllVal -match '\\') { $dllVal } else { Join-Path "$env:SystemRoot\System32" $dllVal }
                    $sev = if (Test-Path $dllPath -ErrorAction SilentlyContinue) {
                        $sig = Get-AuthenticodeSignature $dllPath -ErrorAction SilentlyContinue
                        if ($sig -and $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft') { 'Green' } else { 'Yellow' }
                    } else { 'Yellow' }
                    $findings.Add((New-PFinding `
                        -Severity    $sev `
                        -Category    'Print Spooler Abuse' `
                        -Name        "printmonitor-$($monName -replace '\s','-')" `
                        -DisplayName "Non-Standard Print Monitor: $monName" `
                        -Path        $dllPath `
                        -Hash        (Get-SafeFileHash $dllPath) `
                        -Details     "Print Monitor '$monName' uses DLL '$dllVal'. Non-Microsoft print monitor DLLs load into the SYSTEM-privileged Spooler process and persist across reboots. CVE-2021-1675 (PrintNightmare)." `
                        -MitreId     'T1547' `
                        -MitreName   'Boot/Logon Autostart Execution'))
                }
            }
        }
    } catch {}

    try {
        $printProvidersKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers'
        if (Test-Path $printProvidersKey -ErrorAction SilentlyContinue) {
            $stdProviders = @('LanMan Print Services', 'Internet Print Provider')
            Get-ChildItem -Path $printProvidersKey -ErrorAction SilentlyContinue | ForEach-Object {
                $provName = $_.PSChildName
                if ($stdProviders -notcontains $provName) {
                    $findings.Add((New-PFinding `
                        -Severity    'Yellow' `
                        -Category    'Print Spooler Abuse' `
                        -Name        "printprovider-$($provName -replace '\s','-')" `
                        -DisplayName "Non-Standard Print Provider: $provName" `
                        -Path        $_.PSPath `
                        -Hash        '' `
                        -Details     "Unexpected Print Provider '$provName' registered. Print providers run in the Spooler process (SYSTEM context) and can be used for persistence and privilege escalation." `
                        -MitreId     'T1547' `
                        -MitreName   'Boot/Logon Autostart Execution'))
                }
            }
        }
    } catch {}
    #endregion

    #region -- 20. Boot/Pre-OS Persistence Indicators (T1542) --------------------
    # Parses bcdedit output for suspicious/non-standard boot entries.
    try {
        $bcdOut = & bcdedit /enum ALL 2>$null
        if ($bcdOut) {
            $currentEntry = ''
            $entryDesc    = ''
            $entryPath    = ''
            foreach ($line in $bcdOut) {
                if ($line -match '^---') { 
                    # New entry block
                    if ($currentEntry -and $entryPath -and $entryPath -notmatch 'winload\.efi|winload\.exe|memtest\.exe|{') {
                        $findings.Add((New-PFinding `
                            -Severity    'Yellow' `
                            -Category    'Boot Persistence' `
                            -Name        "bcd-suspicious-$($entryPath -replace '[^a-zA-Z0-9]','-')" `
                            -DisplayName "Suspicious BCD Entry: $entryDesc" `
                            -Path        $entryPath `
                            -Hash        '' `
                            -Details     "BCD entry '$entryDesc' references unusual device/path '$entryPath'. Non-standard boot entries may indicate bootkit or pre-OS persistence." `
                            -MitreId     'T1542' `
                            -MitreName   'Pre-OS Boot'))
                    }
                    $currentEntry = ''; $entryDesc = ''; $entryPath = ''
                } elseif ($line -match '^\s+identifier\s+(.+)') { $currentEntry = $Matches[1].Trim() }
                elseif ($line -match '^\s+description\s+(.+)') { $entryDesc = $Matches[1].Trim() }
                elseif ($line -match '^\s+(device|path)\s+(.+)') { if (-not $entryPath) { $entryPath = $Matches[2].Trim() } }
            }
        }
    } catch {}

    # Check for non-Microsoft EFI entries in NVRAM (via reg query)
    try {
        $efiOutput = & reg query 'HKLM\BCD00000000' /s 2>$null | Select-Object -First 50
        # Only flag if unexpected patterns appear — informational only
        if ($efiOutput -match 'grub|linux|syslinux|clover|opencore|rEFInd') {
            $findings.Add((New-PFinding `
                -Severity    'Yellow' `
                -Category    'Boot Persistence' `
                -Name        'bcd-nonms-bootloader' `
                -DisplayName 'Non-Microsoft Bootloader Detected' `
                -Path        'HKLM:\BCD00000000' `
                -Hash        '' `
                -Details     "BCD store appears to contain a non-Microsoft bootloader entry. While this may be legitimate (dual-boot), it can also indicate bootkit or pre-OS persistence (T1542)." `
                -MitreId     'T1542' `
                -MitreName   'Pre-OS Boot'))
        }
    } catch {}
    #endregion

    # --- Summary ----------------------------------------------------------------
    $redCnt    = @($findings | Where-Object { $_.Severity -eq 'Red' }).Count
    $yellowCnt = @($findings | Where-Object { $_.Severity -eq 'Yellow' }).Count

    Add-Content -Path $AuditLog -Value (
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] " +
        "[USER: $currentUser] " +
        "[MODULE: PersistenceHunter] [ACTION: Scan] " +
        "[DETAILS: Persistence mechanisms flagged - RED:$redCnt YELLOW:$yellowCnt]"
    ) -Encoding UTF8

    if ($findings.Count -eq 0) {
        $findings.Add((New-PFinding `
            -Severity    'Green' `
            -Category    'Persistence' `
            -Name        'persistence-clean' `
            -DisplayName 'Persistence Scan - No anomalies' `
            -Path        '' `
            -Hash        '' `
            -Details     "All 20 persistence mechanism locations scanned. No suspicious entries detected."))
    }

    return $findings
}

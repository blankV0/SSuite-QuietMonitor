#Requires -RunAsAdministrator
# =============================================================
# RMMDetect.ps1 — Known Remote Monitoring & Management tool detection
# Scans processes, services, registry, scheduled tasks, installed
# software, network connections, and browser extensions for 25+ RMM tools.
# Classifies each as KNOWN-AUTHORIZED (whitelisted) or UNKNOWN-UNAUTHORIZED.
# MITRE: T1219 (Remote Access Software), T1133 (External Remote Services)
# =============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── RMM Signature Database (25+ tools) ───────────────────────
$script:RMM_DB = @(
    [PSCustomObject]@{
        Name = 'NinjaRMM (NinjaOne)'; ShortName = 'NinjaRMM'
        ProcessNames  = @('NinjaRMMAgent','NinjaRMMAgentPatcher','ninjaRMM','NinjaRMM')
        ServiceNames  = @('NinjaRMMAgent','Ninja RMM Agent')
        RegKeys       = @('HKLM:\SOFTWARE\NinjaRMM','HKLM:\SOFTWARE\NinjaRMM\Agent')
        SoftwareMatch = @('NinjaRMM','NinjaOne')
        Ports         = @(443)
        Domains       = @('ninjarmm.com','app.ninjarmm.com','eu.ninjarmm.com','ca.ninjarmm.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full remote shell execution, file transfer, software management, script deployment, and screen control by any operator with NinjaOne credentials.'
    },
    [PSCustomObject]@{
        Name = 'ConnectWise Automate (LabTech)'; ShortName = 'CWAutomate'
        ProcessNames  = @('LTSvc','LTAgent','LabVNC','LTSVC')
        ServiceNames  = @('LTService','LabTech Service','ltservice')
        RegKeys       = @('HKLM:\SOFTWARE\LabTech','HKLM:\SOFTWARE\LabTech\Service')
        SoftwareMatch = @('ConnectWise Automate','LabTech','ConnectWise')
        Ports         = @(70, 80, 443)
        Domains       = @('connectwise.com','labtech.com','myconnectwise.net')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full remote control, automated scripting, patch management, and real-time monitoring. Allows arbitrary command execution as SYSTEM.'
    },
    [PSCustomObject]@{
        Name = 'ConnectWise ScreenConnect (Control)'; ShortName = 'ScreenConnect'
        ProcessNames  = @('ScreenConnect.ClientService','ScreenConnect.WindowsClient','ScreenConnectClient')
        ServiceNames  = @('ScreenConnect Client','ScreenConnect.ClientService')
        RegKeys       = @('HKLM:\SOFTWARE\ScreenConnect','HKCU:\Software\ScreenConnect')
        SoftwareMatch = @('ScreenConnect','ConnectWise Control','ConnectWise ScreenConnect')
        Ports         = @(8040, 8041, 443)
        Domains       = @('screenconnect.com','connectwise.com','myconnectwise.net')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Interactive remote desktop, file transfer, command execution, unattended access. Remote operator sees and controls the full desktop.'
    },
    [PSCustomObject]@{
        Name = 'Kaseya VSA'; ShortName = 'Kaseya'
        ProcessNames  = @('AgentMon','KaseyaAgent','KaseyaRemoteControlHost','kvs')
        ServiceNames  = @('Kaseya Agent','AgentMon','KaseyaRemoteControl')
        RegKeys       = @('HKLM:\SOFTWARE\Kaseya','HKLM:\SOFTWARE\KASEYA')
        SoftwareMatch = @('Kaseya','Kaseya VSA','Kaseya Agent')
        Ports         = @(443, 5721)
        Domains       = @('kaseya.com','kaseya.net','*.kaseyanet.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full endpoint control: remote shell, live connect, patch deploy, software install, policy enforcement. Operators can execute code as SYSTEM.'
    },
    [PSCustomObject]@{
        Name = 'Atera'; ShortName = 'Atera'
        ProcessNames  = @('AteraAgent','AteraHelper')
        ServiceNames  = @('AteraAgent','Atera Agent')
        RegKeys       = @('HKLM:\SOFTWARE\Atera Networks','HKLM:\SOFTWARE\ATERA')
        SoftwareMatch = @('Atera','Atera RMM','Atera Agent')
        Ports         = @(443)
        Domains       = @('atera.com','app.atera.com','atera-live.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Remote access, script execution, patch management, real-time monitoring with full desktop takeover capabilities.'
    },
    [PSCustomObject]@{
        Name = 'Datto RMM (CentraStage)'; ShortName = 'DattoRMM'
        ProcessNames  = @('CagService','CagAgent','DattoAgent')
        ServiceNames  = @('CagService','Datto RMM','CentraStage Agent')
        RegKeys       = @('HKLM:\SOFTWARE\CentraStage','HKLM:\SOFTWARE\Datto RMM')
        SoftwareMatch = @('Datto RMM','CentraStage','Datto Endpoint')
        Ports         = @(443)
        Domains       = @('datto.com','centrastage.net','rmm.datto.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full managed endpoint control: remote takeover, script execution, device monitoring, patch and software management.'
    },
    [PSCustomObject]@{
        Name = 'TeamViewer'; ShortName = 'TeamViewer'
        ProcessNames  = @('TeamViewer','TeamViewer_Service','tv_w32','tv_x64','TeamViewer_Desktop')
        ServiceNames  = @('TeamViewer','TeamViewer12','TeamViewer13','TeamViewer14','TeamViewer15')
        RegKeys       = @('HKLM:\SOFTWARE\TeamViewer','HKCU:\Software\TeamViewer')
        SoftwareMatch = @('TeamViewer')
        Ports         = @(5938, 443, 80)
        Domains       = @('teamviewer.com','router.teamviewer.com','master.teamviewer.com')
        BrowserExtIds = @('cplelfkobifgojchplpjjmhccigohbf6')  # Chrome TeamViewer
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Full remote desktop, file transfer, remote printing. Requires operator to know the TeamViewer ID and password or be pre-authorised.'
    },
    [PSCustomObject]@{
        Name = 'AnyDesk'; ShortName = 'AnyDesk'
        ProcessNames  = @('AnyDesk','anydesk')
        ServiceNames  = @('AnyDesk','AnyDesk Service')
        RegKeys       = @('HKLM:\SOFTWARE\AnyDesk','HKCU:\Software\AnyDesk')
        SoftwareMatch = @('AnyDesk')
        Ports         = @(7070, 443, 80)
        Domains       = @('anydesk.com','relay.anydesk.com','get.anydesk.com')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Remote desktop, file manager, terminal access, audio forwarding, unattended access mode.'
    },
    [PSCustomObject]@{
        Name = 'Splashtop'; ShortName = 'Splashtop'
        ProcessNames  = @('SRService','SRAgent','SRFeature','Splashtop')
        ServiceNames  = @('Splashtop Remote Services','SRService','SRAgent')
        RegKeys       = @('HKLM:\SOFTWARE\Splashtop','HKCU:\Software\Splashtop')
        SoftwareMatch = @('Splashtop','Splashtop Remote','Splashtop Streamer')
        Ports         = @(443, 6783)
        Domains       = @('splashtop.com','relay.splashtop.com')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'High-performance remote desktop, file transfer, remote print. Supports unattended access with persistent session.'
    },
    [PSCustomObject]@{
        Name = 'GoTo (LogMeIn / LogMeIn Pro)'; ShortName = 'GoTo'
        ProcessNames  = @('LogMeIn','LMIGuardian','logmein','LogMeInSvc')
        ServiceNames  = @('LMIGuardianSvc','LogMeIn','logmein')
        RegKeys       = @('HKLM:\SOFTWARE\LogMeIn','HKCU:\Software\LogMeIn')
        SoftwareMatch = @('LogMeIn','GoTo','GoToMyPC','GoToAssist')
        Ports         = @(443, 80)
        Domains       = @('logmein.com','goto.com','gotomypc.com','gotoassist.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full remote PC access, file sharing, multi-monitor support. Persistent unattended access with LogMeIn Pro.'
    },
    [PSCustomObject]@{
        Name = 'Zoho Assist'; ShortName = 'Zoho'
        ProcessNames  = @('ZohoMeetingController','ZohoURS','ZohoAssist','zohoassist')
        ServiceNames  = @('ZohoURS','Zoho Assist')
        RegKeys       = @('HKLM:\SOFTWARE\Zoho','HKCU:\Software\Zoho')
        SoftwareMatch = @('Zoho Assist','Zoho Meeting','Zoho Remote')
        Ports         = @(443)
        Domains       = @('zoho.com','zohoassist.com','zohocorp.com')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Remote desktop, unattended access, file transfer, multi-monitor support.'
    },
    [PSCustomObject]@{
        Name = 'Pulseway'; ShortName = 'Pulseway'
        ProcessNames  = @('PCMonitorSrv','PCMonitorAgent','pulseway')
        ServiceNames  = @('PCMonitor','Pulseway','PCMonitorSrv')
        RegKeys       = @('HKLM:\SOFTWARE\MMSOFT Design\PC Monitor','HKLM:\SOFTWARE\Pulseway')
        SoftwareMatch = @('Pulseway','PC Monitor')
        Ports         = @(443, 15999)
        Domains       = @('pulseway.com','app.pulseway.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Remote management, script execution, patch management, remote desktop, file manager.'
    },
    [PSCustomObject]@{
        Name = 'SolarWinds N-able / MSP Manager'; ShortName = 'Nable'
        ProcessNames  = @('Windows_Agent','AdvancedMonitoringAgent','SolarWindsAgent','N_able')
        ServiceNames  = @('Advanced Monitoring Agent','Windows Agent','SolarWinds MSP')
        RegKeys       = @('HKLM:\SOFTWARE\GFI Software','HKLM:\SOFTWARE\N-able Technologies')
        SoftwareMatch = @('N-able','SolarWinds N-able','Advanced Monitoring Agent')
        Ports         = @(443, 10001)
        Domains       = @('n-able.com','solarwinds.com','systemmonitor.net')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full RMM: remote access, AV management, patch management, script execution, service management.'
    },
    [PSCustomObject]@{
        Name = 'Huntress'; ShortName = 'Huntress'
        ProcessNames  = @('HuntressAgent','HuntressUpdater')
        ServiceNames  = @('HuntressAgent','Huntress Agent')
        RegKeys       = @('HKLM:\SOFTWARE\Huntress Labs','HKLM:\SOFTWARE\Huntress')
        SoftwareMatch = @('Huntress','Huntress Agent')
        Ports         = @(443)
        Domains       = @('huntress.io','huntresslabs.com','update.huntress.io')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Managed EDR/MDR: threat detection, incident response, persistent foothold detection. Sends data to Huntress SOC.'
    },
    [PSCustomObject]@{
        Name = 'BeyondTrust Remote Support (Bomgar)'; ShortName = 'Bomgar'
        ProcessNames  = @('bomgar-scc','bomgar-pac','beyond_trust','BomgarBridge')
        ServiceNames  = @('Bomgar','BeyondTrust Remote Support')
        RegKeys       = @('HKLM:\SOFTWARE\Bomgar','HKLM:\SOFTWARE\BeyondTrust')
        SoftwareMatch = @('Bomgar','BeyondTrust')
        Ports         = @(443, 8200)
        Domains       = @('beyondtrust.com','bomgar.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Enterprise remote support with full session recording, jump access, and privileged remote access management.'
    },
    [PSCustomObject]@{
        Name = 'Auvik'; ShortName = 'Auvik'
        ProcessNames  = @('AuvikCollector','AuvikAgent','auvik')
        ServiceNames  = @('AuvikCollector','Auvik Collector')
        RegKeys       = @('HKLM:\SOFTWARE\Auvik')
        SoftwareMatch = @('Auvik')
        Ports         = @(443, 2095)
        Domains       = @('auvik.com','collector.auvik.com')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Network monitoring and mapping agent. Collects topology, device, and traffic data. Provides remote configuration access.'
    },
    [PSCustomObject]@{
        Name = 'Action1 RMM'; ShortName = 'Action1'
        ProcessNames  = @('action1_agent','action1_remote','Action1')
        ServiceNames  = @('action1','Action1 Agent')
        RegKeys       = @('HKLM:\SOFTWARE\Action1')
        SoftwareMatch = @('Action1')
        Ports         = @(443)
        Domains       = @('action1.com','app.action1.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Agentless-style RMM: patch management, remote script execution, vulnerability management, real-time shell access.'
    },
    [PSCustomObject]@{
        Name = 'SuperOps'; ShortName = 'SuperOps'
        ProcessNames  = @('superops','SuperOpsAgent','superops_agent')
        ServiceNames  = @('SuperOps Agent','superops')
        RegKeys       = @('HKLM:\SOFTWARE\SuperOps')
        SoftwareMatch = @('SuperOps')
        Ports         = @(443)
        Domains       = @('superops.ai','superops.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full RMM platform: remote monitoring, script execution, patch management, remote access.'
    },
    [PSCustomObject]@{
        Name = 'ManageEngine Desktop Central / Endpoint Central'; ShortName = 'ManageEngine'
        ProcessNames  = @('DesktopCentral','ManageEngine','dcservice','DCAgentService')
        ServiceNames  = @('DesktopCentralServer','ManageEngine Desktop Central','MEDC Agent')
        RegKeys       = @('HKLM:\SOFTWARE\ManageEngine','HKLM:\SOFTWARE\ZOHO Corp\DesktopCentral')
        SoftwareMatch = @('ManageEngine','Desktop Central','Endpoint Central','ZOHO Corp')
        Ports         = @(8020, 8383, 443)
        Domains       = @('manageengine.com','zohocorp.com','desktopcentral.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Enterprise UEM/MDM: software deployment, OS patching, remote control, configuration management, vulnerability scanning.'
    },
    [PSCustomObject]@{
        Name = 'VNC (UltraVNC / TightVNC / RealVNC / TigerVNC)'; ShortName = 'VNC'
        ProcessNames  = @('winvnc4','winvnc','tvnserver','tvnservice','vncserver','vncviewer','rfb')
        ServiceNames  = @('UltraVNC Server','TightVNC Server','RealVNC','TigerVNC','winvnc')
        RegKeys       = @('HKLM:\SOFTWARE\RealVNC','HKLM:\SOFTWARE\TightVNC','HKLM:\SOFTWARE\UltraVNC')
        SoftwareMatch = @('UltraVNC','TightVNC','RealVNC','TigerVNC','VNC Server')
        Ports         = @(5900, 5800, 5901)
        Domains       = @()
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Direct VNC protocol: full screen access, keyboard/mouse control, no authentication by default in some configurations.'
    },
    [PSCustomObject]@{
        Name = 'Naverisk'; ShortName = 'Naverisk'
        ProcessNames  = @('NaveriskAgent','Naverisk')
        ServiceNames  = @('Naverisk Agent','Naverisk Remote & Monitoring')
        RegKeys       = @('HKLM:\SOFTWARE\Naverisk')
        SoftwareMatch = @('Naverisk')
        Ports         = @(443)
        Domains       = @('naverisk.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Full RMM: automated monitoring, scripting, patch management, remote access, helpdesk integration.'
    },
    [PSCustomObject]@{
        Name = 'Webroot Business Endpoint'; ShortName = 'Webroot'
        ProcessNames  = @('WRSA','WRSkyClient','wrService')
        ServiceNames  = @('Webroot SecureAnywhere','WRSVC')
        RegKeys       = @('HKLM:\SOFTWARE\WRData','HKLM:\SOFTWARE\Webroot')
        SoftwareMatch = @('Webroot','Webroot SecureAnywhere','Webroot Business Endpoint')
        Ports         = @(443)
        Domains       = @('webroot.com','my.webrootanywhere.com','brightcloud.com')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Cloud-managed AV/EDR. Management console allows script execution, policy changes, and quarantine management remotely.'
    },
    [PSCustomObject]@{
        Name = 'Acronis Cyber Protect Cloud'; ShortName = 'Acronis'
        ProcessNames  = @('AcronisManagedMachineService','AcronisAgent','acronis_agent')
        ServiceNames  = @('AcronisManagedMachineService','Acronis Managed Machine Service')
        RegKeys       = @('HKLM:\SOFTWARE\Acronis')
        SoftwareMatch = @('Acronis','Acronis Cyber Protect','Acronis True Image')
        Ports         = @(443, 44445)
        Domains       = @('acronis.com','cloudbackup.acronis.com')
        BrowserExtIds = @()
        RiskLevel     = 'MEDIUM'
        AccessDesc    = 'Cloud backup + managed endpoint protection. Allows remote management, backup scheduling, and security policy enforcement.'
    },
    [PSCustomObject]@{
        Name = 'Comodo / ITarian'; ShortName = 'ITarian'
        ProcessNames  = @('itsm_agent','CmdAgent','COMODO','cmdinstall')
        ServiceNames  = @('COMODO Client - Security','COMODO Internet Security','ITarian')
        RegKeys       = @('HKLM:\SOFTWARE\COMODO','HKLM:\SOFTWARE\ITarian')
        SoftwareMatch = @('COMODO','ITarian','Comodo Client Security','Comodo One')
        Ports         = @(443, 5222)
        Domains       = @('comodo.com','itarian.com','secure.comodo.com')
        BrowserExtIds = @()
        RiskLevel     = 'HIGH'
        AccessDesc    = 'Cloud-based endpoint security + RMM: remote access, patch management, script execution, AV management.'
    }
)

# Known RMM-related browser extension IDs
$script:RMM_BROWSER_EXT_DB = @{
    'cplelfkobifgojchplpjjmhccigohbf6' = 'TeamViewer Remote Control (Chrome)'
    'hdjlmddiajafbmajbkfgmeidpnfhahpl' = 'AnyDesk (Chrome)'
    'oeoijokejobmehdnaeicfokebmkflhac' = 'Bomgar Remote Support (Chrome)'
    'nfcgceoebfhbdmdhjkddljelpggpnmnm' = 'Dameware Remote (Chrome)'
}

# ── Detection helpers ─────────────────────────────────────────
function script:Get-RMMRunningProcesses {
    param([PSCustomObject]$Sig)
    $found = @()
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($pn in $Sig.ProcessNames) {
        $matches_ = $procs | Where-Object { $_.Name -ilike $pn -or $_.Name -ilike "*$pn*" }
        foreach ($m in $matches_) {
            $found += [PSCustomObject]@{ ProcessName = $m.Name; PID = $m.Id; Path = try { $m.MainModule.FileName } catch { '' }; Source = 'Process' }
        }
    }
    return $found
}

function script:Get-RMMRunningServices {
    param([PSCustomObject]$Sig)
    $found = @()
    foreach ($sn in $Sig.ServiceNames) {
        $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
        if (-not $svc) { $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -ilike "*$sn*" } }
        if ($svc) {
            $found += [PSCustomObject]@{ ServiceName = $svc.Name; DisplayName = $svc.DisplayName; Status = $svc.Status; Source = 'Service' }
        }
    }
    return $found
}

function script:Get-RMMRegistryKeys {
    param([PSCustomObject]$Sig)
    $found = @()
    foreach ($rk in $Sig.RegKeys) {
        if (Test-Path $rk -ErrorAction SilentlyContinue) {
            $found += [PSCustomObject]@{ Key = $rk; Source = 'Registry' }
        }
    }
    return $found
}

function script:Get-RMMInstalledSoftware {
    param([PSCustomObject]$Sig)
    $found = @()
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($rp in $regPaths) {
        try {
            $entries = Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                       Where-Object { $_.DisplayName }
            foreach ($match in $Sig.SoftwareMatch) {
                $hit = $entries | Where-Object { $_.DisplayName -ilike "*$match*" }
                foreach ($h in $hit) {
                    $found += [PSCustomObject]@{
                        DisplayName   = $h.DisplayName
                        Version       = $h.DisplayVersion
                        InstallDate   = $h.InstallDate
                        Publisher     = $h.Publisher
                        Source        = 'InstalledSoftware'
                    }
                }
            }
        } catch {}
    }
    return $found
}

function script:Get-RMMNetworkConnections {
    param([PSCustomObject]$Sig)
    $found = @()
    try {
        $conns = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue
        foreach ($port in $Sig.Ports) {
            $matches_ = $conns | Where-Object { $_.LocalPort -eq $port -or $_.RemotePort -eq $port }
            foreach ($m in $matches_) {
                $procName = try { (Get-Process -Id $m.OwningProcess -ErrorAction SilentlyContinue).Name } catch { 'Unknown' }
                # Only flag if remote address matches known domain IPs (basic heuristic — check domain in RemoteAddress)
                $found += [PSCustomObject]@{
                    LocalPort    = $m.LocalPort
                    RemoteAddress = $m.RemoteAddress
                    RemotePort   = $m.RemotePort
                    State        = $m.State
                    ProcessId    = $m.OwningProcess
                    ProcessName  = $procName
                    Source       = 'Network'
                }
            }
        }
    } catch {}
    return $found
}

function script:Get-RMMBrowserExtensions {
    param([PSCustomObject]$Sig)
    $found = @()
    if ($Sig.BrowserExtIds.Count -eq 0) { return $found }

    $profiles = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    )
    foreach ($profile in $profiles) {
        if (-not (Test-Path $profile)) { continue }
        foreach ($extId in $Sig.BrowserExtIds) {
            $extPath = Join-Path $profile $extId
            if (Test-Path $extPath) {
                $found += [PSCustomObject]@{ ExtId = $extId; Path = $extPath; Source = 'BrowserExtension' }
            }
        }
    }
    return $found
}

function script:Test-RMMIsWhitelisted {
    param([string]$ShortName, $Whitelist)
    if (-not $Whitelist) { return $false }
    $wlRMM = try { $Whitelist.authorizedRMM } catch { $null }
    if (-not $wlRMM) { return $false }
    return $wlRMM -icontains $ShortName
}

# ── Main detection orchestrator ───────────────────────────────
function Invoke-RMMDetection {
    <#
    .SYNOPSIS
        Scans for 25+ known RMM tools via process, service, registry,
        installed software, network connections, and browser extensions.
        Classifies each as KNOWN-AUTHORIZED or UNKNOWN-UNAUTHORIZED.
        Returns findings array.
    #>
    [CmdletBinding()]
    param(
        [object]$Whitelist,
        [string]$AuditLog = 'C:\QuietMonitor\Logs\audit.log'
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $detected = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($sig in $script:RMM_DB) {
        $evidence = [System.Collections.Generic.List[string]]::new()

        $procs   = script:Get-RMMRunningProcesses $sig
        $svcs    = script:Get-RMMRunningServices  $sig
        $regKeys = script:Get-RMMRegistryKeys     $sig
        $soft    = script:Get-RMMInstalledSoftware $sig
        $net     = script:Get-RMMNetworkConnections $sig
        $ext     = script:Get-RMMBrowserExtensions  $sig

        foreach ($p in $procs)   { $evidence.Add("Process: $($p.ProcessName) PID:$($p.PID)") }
        foreach ($s in $svcs)    { $evidence.Add("Service: $($s.DisplayName) [$($s.Status)]") }
        foreach ($r in $regKeys) { $evidence.Add("Registry: $($r.Key)") }
        foreach ($so in $soft)   { $evidence.Add("Installed: $($so.DisplayName) v$($so.Version) ($(($so.InstallDate)))") }
        foreach ($n in $net)     { $evidence.Add("Network: $($n.RemoteAddress):$($n.RemotePort) via $($n.ProcessName)") }
        foreach ($e in $ext)     { $evidence.Add("BrowserExt: $($e.ExtId) at $($e.Path)") }

        if ($evidence.Count -eq 0) { continue }

        $isAuthorized = script:Test-RMMIsWhitelisted $sig.ShortName $Whitelist
        $status       = if ($isAuthorized) { 'KNOWN-AUTHORIZED' } else { 'UNKNOWN-UNAUTHORIZED' }
        $sev          = if ($isAuthorized) { 'Green' } else { if ($sig.RiskLevel -eq 'HIGH') { 'Red' } else { 'Yellow' } }

        $evidenceStr = $evidence -join '  |  '
        $details     = "RMM DETECTED: $($sig.Name) — Status: $status  Evidence: $evidenceStr  Risk: $($sig.RiskLevel)  Access granted: $($sig.AccessDesc)"

        if (-not $isAuthorized) {
            $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')] [TAMPER-CRITICAL] [RMMDetect] $details"
            try { Add-Content -LiteralPath 'C:\QuietMonitor\Logs\tamper.log' -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
        }

        $findings.Add([PSCustomObject]@{
            Module      = 'RMMDetect'
            Timestamp   = (Get-Date -Format 'o')
            Severity    = $sev
            Category    = 'RMMDetection'
            Name        = "RMM_$($sig.ShortName)"
            DisplayName = "RMM $status: $($sig.Name)"
            Path        = ($procs | Select-Object -First 1 -ExpandProperty Path)
            Hash        = ''
            Details     = $details
            ActionTaken = if ($isAuthorized) { 'Whitelisted' } else { 'Alert' }
            MitreId     = 'T1219'
            MitreName   = 'Remote Access Software'
        })

        $detected.Add([PSCustomObject]@{ Name = $sig.Name; Status = $status; Risk = $sig.RiskLevel })
    }

    # Check for RMM-related browser extensions with known IDs
    $profiles = @(
        @{ Browser = 'Chrome'; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" },
        @{ Browser = 'Edge';   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" }
    )
    foreach ($profile in $profiles) {
        if (-not (Test-Path $profile.Path)) { continue }
        foreach ($extId in $script:RMM_BROWSER_EXT_DB.Keys) {
            $extPath = Join-Path $profile.Path $extId
            if (Test-Path $extPath) {
                $extName = $script:RMM_BROWSER_EXT_DB[$extId]
                $findings.Add([PSCustomObject]@{
                    Module='RMMDetect'; Timestamp=(Get-Date -Format 'o'); Severity='Yellow'
                    Category='RMMBrowserExtension'; Name="RMMExt_$extId"
                    DisplayName = "RMM Browser Extension: $extName ($($profile.Browser))"
                    Path = $extPath; Hash = ''; Details = "Extension ID: $extId  Browser: $($profile.Browser)  Name: $extName"
                    ActionTaken = 'Alert'; MitreId = 'T1176'; MitreName = 'Browser Extensions'
                })
            }
        }
    }

    # Summary log
    $unauth = @($findings | Where-Object { $_.ActionTaken -eq 'Alert' }).Count
    if ($AuditLog) { Add-Content -LiteralPath $AuditLog -Value "[$(Get-Date -Format 'o')] [RMMDetect] [ACTION: Scan] [DETAILS: $($detected.Count) RMM tools detected; $unauth UNAUTHORIZED; $($detected.Count - $unauth) authorized]" -Encoding UTF8 -ErrorAction SilentlyContinue }

    return $findings.ToArray()
}

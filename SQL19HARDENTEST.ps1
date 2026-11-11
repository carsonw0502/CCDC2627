<#
.SYNOPSIS
    Initial hardening for the "2019 MSSQL" VM (Windows Server 2019 + SQL Server 2019)
    in the 2026 Midwest Invitational CCDC. Written against the Team Pack rules.

.DESCRIPTION
    Box facts from the Team Pack:
      Internal IP  172.20.240.120   (public/NAT 172.25.<20+team#>.120)  -- DO NOT CHANGE (rule 7)
      Gateway/PA   172.20.240.254   AD 172.20.240.100   Splunk 172.20.240.20
      Scored here: MSSQL (TCP 1433, login + query), RDP (TCP 3389, authenticated),
                   SMB (TCP 445, authenticates, checks planted "SOP" files), ICMP ping.

    Rules this script is built around:
      * Rule 9  : public services must be open to ALL source IPs. No allow-listing / knife-edge.
                  Only specific malicious IPs may be blocked (-BlockIPs).
      * Rule 12 : ICMP must stay enabled. Firewall rules that break scoring are YOUR fault.
      * Rule 11 : usernames may not be changed; passwords may. Script never renames accounts.
      * Rule 10 : no snapshots/scrubs on VM -> script includes a firewall auto-revert safety net.
      * Quotient PCR: scoring only knows new passwords if you submit them on the PCR tab
                  (CSV "username,password"). The script generates that CSV for you.

.EXAMPLE
    # Recommended first pass: harden everything, generate password CSV, don't apply passwords yet
    .\Harden-MSSQL2019-MWCCDC.ps1

    # After you've checked Quotient, rotate passwords on the box, then submit the CSV to PCR immediately
    .\Harden-MSSQL2019-MWCCDC.ps1 -ApplyPasswords -SqlLogins sa

.NOTES
    Free/open-source software only (rule 10, play rules). Nothing here installs anything.
#>
[CmdletBinding()]
param(
    # Extra inbound TCP ports to keep open (e.g. a port an inject asks you to add).
    [int[]]$ExtraPorts = @(),

    # Specific attacker IPs/CIDRs to BLOCK inbound (permitted by rule 9). Never block the scoring engine.
    [string[]]$BlockIPs = @(),

    # Local accounts to skip when generating/applying new passwords.
    [string[]]$ExcludeUsers = @(),

    # SQL instance. Default instance = 'localhost'. Named instance = 'localhost\NAME'.
    [string]$SqlInstance = 'localhost',

    # SQL-auth logins to rotate (e.g. sa). Only rotate ones you will submit on the PCR tab.
    [string[]]$SqlLogins = @(),

    # Actually change the passwords on this box. Without it, only the PCR CSV is generated.
    [switch]$ApplyPasswords,

    # Require SMB signing + NTLMv2-only. Stronger, but the SMB scoring client might not cope. Test first.
    [switch]$StrictAuth,

    # Remove unknown members from local Administrators (keeps Administrator, sysadmin, current user, -ExcludeUsers).
    # Risk: a scored RDP/SMB user may rely on admin membership. Review the report first.
    [switch]$PurgeLocalAdmins,

    # Restart SQL Server at the end (enables login auditing). Causes a brief MSSQL outage.
    [switch]$RestartSql,

    # Leave the Windows Firewall alone.
    [switch]$SkipFirewall,

    # Auto-restore the ORIGINAL firewall after N minutes unless you cancel the task. 0 = off.
    [int]$SafetyRevertMinutes = 10
)

#region Setup ---------------------------------------------------------------
$ErrorActionPreference = 'Continue'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run from an elevated PowerShell prompt.'; exit 1
}

# Known topology (from Team Pack)
$ExpectedIP   = '172.20.240.120'
$GatewayIP    = '172.20.240.254'   # Palo Alto inside
$ADIP         = '172.20.240.100'
$ScoredPorts  = @(1433, 3389, 445) + $ExtraPorts

$Stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutDir = "C:\CCDC\$Stamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
# Lock the output folder to SYSTEM + Administrators (it will hold generated passwords)
icacls $OutDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Start-Transcript -Path "$OutDir\transcript.txt" | Out-Null

function Step($m) { Write-Host "`n[+] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    } catch { Warn "Registry set failed: $Path\$Name - $($_.Exception.Message)" }
}

function New-RandomPassword {
    param([int]$Length = 20)
    # No commas, quotes, backslashes or backticks: safe for the PCR CSV and T-SQL.
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#%^*-_=+'
    $all  = -join $sets
    $rng  = [Security.Cryptography.RandomNumberGenerator]::Create()
    $pick = {
        param($chars)
        $b = New-Object byte[] 4; $rng.GetBytes($b)
        $chars[[int]([BitConverter]::ToUInt32($b, 0) % [uint32]$chars.Length)]
    }
    $out = @(); foreach ($s in $sets) { $out += & $pick $s }
    while ($out.Count -lt $Length) { $out += & $pick $all }
    $out = $out | Sort-Object { $b = New-Object byte[] 4; $rng.GetBytes($b); [BitConverter]::ToUInt32($b, 0) }
    -join $out
}

Write-Host "Output directory: $OutDir" -ForegroundColor Green

# Sanity: this box's IP must not change (rule 7)
$myIPs = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
if ($myIPs -notcontains $ExpectedIP) { Warn "Expected $ExpectedIP but found: $($myIPs -join ', '). Is this the 2019 MSSQL VM?" }
#endregion

#region 1. Baseline / backups ------------------------------------------------
Step 'Backing up configuration and capturing baseline'
if (-not (Test-Path 'C:\CCDC\firewall-original.wfw')) { netsh advfirewall export 'C:\CCDC\firewall-original.wfw' | Out-Null }
netsh advfirewall export "$OutDir\firewall-before.wfw" | Out-Null
Get-Service | Select Name, DisplayName, Status, StartType | Export-Csv "$OutDir\services-before.csv" -NoTypeInformation
Get-LocalUser | Select Name, Enabled, LastLogon, PasswordLastSet | Export-Csv "$OutDir\localusers-before.csv" -NoTypeInformation
Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess,
    @{n='Process'; e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
    Sort LocalPort | Export-Csv "$OutDir\listening-before.csv" -NoTypeInformation
# NOTE: shares hold the planted SOP files the SMB check looks for. Record them, never delete/modify them.
Get-SmbShare | Select Name, Path, Description | Export-Csv "$OutDir\shares.csv" -NoTypeInformation
#endregion

#region 2. Accounts & passwords ----------------------------------------------
Step 'Local accounts: generating PCR password list'
$pcr = New-Object System.Collections.Generic.List[string]
try {
    Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin $ExcludeUsers } | ForEach-Object {
        $pw = New-RandomPassword
        $pcr.Add("$($_.Name),$pw")
        if ($ApplyPasswords) {
            try { Set-LocalUser -Name $_.Name -Password (ConvertTo-SecureString $pw -AsPlainText -Force); Write-Host "    Password CHANGED on box: $($_.Name)" }
            catch { Warn "Could not change $($_.Name): $($_.Exception.Message)" }
        }
    }
    # Disable built-ins nobody scores (does NOT rename anything - rule 11)
    foreach ($n in 'Guest', 'DefaultAccount', 'WDAGUtilityAccount') { Disable-LocalUser -Name $n -ErrorAction SilentlyContinue }
} catch { Warn "Local account handling failed: $($_.Exception.Message)" }

Step 'Auditing local Administrators group'
$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
$admins | Select Name, ObjectClass, PrincipalSource | Tee-Object -FilePath "$OutDir\local-admins-before.txt" | Format-Table -AutoSize
if ($PurgeLocalAdmins) {
    $protect = @('Administrator', 'sysadmin', 'Domain Admins', $env:USERNAME) + $ExcludeUsers
    foreach ($m in $admins) {
        if ($m.Name.Split('\')[-1] -in $protect) { continue }
        try { Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name; Write-Host "    Removed admin: $($m.Name)" }
        catch { Warn "Could not remove $($m.Name)" }
    }
}

Step 'Password policy (NO lockout: Red Team lockouts would take down scored accounts)'
net accounts /minpwlen:12 /maxpwage:90 /minpwage:0 /uniquepw:5 /lockoutthreshold:0 | Out-Null
#endregion

#region 3. Firewall ----------------------------------------------------------
if (-not $SkipFirewall) {
    Step 'Rebuilding Windows Firewall (scored ports open to ALL sources, per rule 9)'

    if ($SafetyRevertMinutes -gt 0) {
        $act = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument 'advfirewall import "C:\CCDC\firewall-original.wfw"'
        $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($SafetyRevertMinutes)
        $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'CCDC-FW-Revert' -Action $act -Trigger $trg -Principal $prn -Force | Out-Null
        Warn "SAFETY NET: original firewall returns in $SafetyRevertMinutes min. Cancel after verifying scoring:"
        Warn "  Unregister-ScheduledTask -TaskName CCDC-FW-Revert -Confirm:`$false"
    }

    netsh advfirewall reset | Out-Null
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -LogBlocked True -LogAllowed False -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 32767

    # Turn off all inbound allows except Core Networking (DHCP/DNS/ICMP-error plumbing)
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
        Where-Object { $_.DisplayGroup -ne 'Core Networking' } | Disable-NetFirewallRule

    foreach ($p in $ScoredPorts) {
        New-NetFirewallRule -DisplayName "CCDC Allow TCP $p" -Direction Inbound -Protocol TCP -LocalPort $p `
            -RemoteAddress Any -Action Allow -Profile Any | Out-Null
        Write-Host "    Allowed inbound TCP $p from ANY"
    }
    # ICMP must remain enabled (rule 12)
    New-NetFirewallRule -DisplayName 'CCDC Allow ICMPv4 Echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'CCDC Allow ICMPv6 Echo' -Direction Inbound -Protocol ICMPv6 -IcmpType 128 -Action Allow -Profile Any | Out-Null

    # Block only specific, known-malicious sources (explicitly allowed by rule 9)
    if ($BlockIPs.Count -gt 0) {
        New-NetFirewallRule -DisplayName 'CCDC Block Attackers' -Direction Inbound -Action Block -RemoteAddress $BlockIPs -Profile Any | Out-Null
        Write-Host "    Blocking inbound from: $($BlockIPs -join ', ')"
    }
} else { Warn 'Skipping firewall changes.' }
#endregion

#region 4. Network / credential hardening ------------------------------------
Step 'Hardening SMB, NTLM, name resolution, credential theft (scoring-safe defaults)'
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force -ErrorAction SilentlyContinue

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if ($StrictAuth) {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
    Set-Reg $lsa 'LmCompatibilityLevel' 5
    Warn 'StrictAuth ON: if SMB scoring drops, undo with: Set-SmbServerConfiguration -RequireSecuritySignature $false -Force'
} else {
    Set-Reg $lsa 'LmCompatibilityLevel' 3          # clients send NTLMv2 only; stays compatible with the scorer
}
Set-Reg $lsa 'NoLMHash' 1
Set-Reg $lsa 'RestrictAnonymous' 1
Set-Reg $lsa 'RestrictAnonymousSAM' 1
Set-Reg $lsa 'EveryoneIncludesAnonymous' 0
Set-Reg $lsa 'RunAsPPL' 1                            # LSA protection (needs reboot; reboot only if allowed)
$lan = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
Set-Reg $lan 'RestrictNullSessAccess' 1
Set-Reg $lan 'NullSessionPipes' @() 'MultiString'
Set-Reg $lan 'NullSessionShares' @() 'MultiString'

Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' '2' 'String'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' 0
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1

# Zerologon
$nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
Set-Reg $nl 'FullSecureChannelProtection' 1
Set-Reg $nl 'RequireSignOrSeal' 1
Set-Reg $nl 'SealSecureChannel' 1
Set-Reg $nl 'SignSecureChannel' 1

# LLMNR / mDNS / NetBIOS / WPAD (poisoning/relay)
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 0
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
    ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -ErrorAction SilentlyContinue }
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 1

Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fAllowToGetHelp' 0

# RDP: NLA is the 2019 default; enforce it, but leave security layer/encryption at defaults (scorer compatibility)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCdm' 1
#endregion

#region 5. Services ----------------------------------------------------------
Step 'Disabling unneeded services (RDP, SMB, SQL, WinRM, DNS client, Netlogon left alone)'
$disable = @('Spooler', 'RemoteRegistry', 'TlntSvr', 'SNMP', 'SNMPTRAP', 'FTPSVC', 'W3SVC', 'SharedAccess',
             'ssdpsrv', 'upnphost', 'Browser', 'bthserv', 'icssvc', 'lltdsvc', 'RasMan', 'RemoteAccess',
             'XblAuthManager', 'XblGameSave', 'MapsBroker', 'lfsvc', 'WMPNetworkSvc', 'WinHttpAutoProxySvc')
# SQL Browser is only needed for named instances
if ($SqlInstance -notmatch '\\') { $disable += 'SQLBrowser' }
foreach ($s in $disable) {
    if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
        Stop-Service $s -Force -ErrorAction SilentlyContinue
        Set-Service  $s -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "    Disabled: $s"
    }
}
foreach ($f in 'TelnetClient', 'TFTP', 'SimpleTCP', 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2') {
    Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
}
#endregion

#region 6. Defender & ASR ----------------------------------------------------
Step 'Enabling Defender protections and ASR rules'
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
        -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled
    $mp = Get-MpPreference
    foreach ($x in @($mp.ExclusionPath)) { if ($x) { Remove-MpPreference -ExclusionPath $x -ErrorAction SilentlyContinue } }
    foreach ($x in @($mp.ExclusionProcess)) { if ($x) { Remove-MpPreference -ExclusionProcess $x -ErrorAction SilentlyContinue } }
    foreach ($x in @($mp.ExclusionExtension)) { if ($x) { Remove-MpPreference -ExclusionExtension $x -ErrorAction SilentlyContinue } }
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 0

    # id -> action (1 = block, 2 = audit). PSExec/WMI rule is audit-only to avoid surprising a scoring/ops tool.
    $asr = [ordered]@{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 1   # vulnerable signed drivers
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 1   # LSASS credential theft
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 1   # obfuscated scripts
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 1   # webshell creation on servers
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 2   # PSExec/WMI process creation (audit)
    }
    foreach ($id in $asr.Keys) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $asr[$id] -ErrorAction SilentlyContinue }
    Update-MpSignature -ErrorAction SilentlyContinue
    Start-MpScan -ScanType QuickScan -AsJob | Out-Null
} catch { Warn "Defender config issue: $($_.Exception.Message)" }
#endregion

#region 7. Logging (feeds your incident reports; consider a free Splunk UF -> 172.20.240.20) ----
Step 'Enabling auditing and PowerShell logging'
auditpol /set /category:"Logon/Logoff","Account Logon","Account Management","Detailed Tracking","Policy Change","Privilege Use","System" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File Share","Registry","SAM" /success:enable /failure:enable | Out-Null
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String'
foreach ($log in 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational') { wevtutil sl $log /ms:268435456 2>$null }
#endregion

#region 8. Persistence / compromise hunt (REPORT ONLY - nothing deleted) -----
Step 'Collecting persistence indicators -> report files (Red Team may already be in)'
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$runKeys | ForEach-Object { "--- $_"; Get-ItemProperty $_ -ErrorAction SilentlyContinue | Out-String } | Out-File "$OutDir\report-runkeys.txt"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue |
    Out-File "$OutDir\report-startup-folders.txt"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskName -ne 'CCDC-FW-Revert' } |
    Select TaskName, TaskPath, State, @{n='Run'; e={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}} |
    Format-List | Out-File "$OutDir\report-scheduled-tasks.txt"
Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch 'System32|Program Files|SysWOW64|Microsoft\.NET|SQL' } |
    Select Name, State, StartName, PathName | Format-List | Out-File "$OutDir\report-suspicious-services.txt"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
    ForEach-Object { $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger; if ($d) { "$($_.PSChildName) -> $d" } } |
    Out-File "$OutDir\report-ifeo.txt"
foreach ($f in 'sethc', 'utilman', 'osk', 'narrator', 'magnify') {
    Get-Item "C:\Windows\System32\$f.exe" -ErrorAction SilentlyContinue |
        Select Name, Length, @{n='Sig'; e={(Get-AuthenticodeSignature $_.FullName).Status}} | Out-File "$OutDir\report-accessibility-binaries.txt" -Append
}
foreach ($c in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
    Get-CimInstance -Namespace root\subscription -ClassName $c -ErrorAction SilentlyContinue | Out-File "$OutDir\report-wmi-persistence.txt" -Append
}
Get-NetTCPConnection | Where-Object { $_.State -in 'Listen', 'Established' } |
    Select State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{n='Process'; e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
    Sort State, LocalPort | Export-Csv "$OutDir\report-network.csv" -NoTypeInformation
Get-Content "$env:windir\System32\drivers\etc\hosts" | Out-File "$OutDir\report-hosts.txt"
Get-ChildItem C:\Users\*\AppData\Local\Temp, C:\Windows\Temp, C:\ProgramData -Include *.exe, *.dll, *.ps1, *.bat, *.vbs -Recurse -Force -ErrorAction SilentlyContinue |
    Select FullName, Length, LastWriteTime | Export-Csv "$OutDir\report-temp-executables.csv" -NoTypeInformation
#endregion

#region 9. SQL Server 2019 ---------------------------------------------------
Step "Hardening SQL Server ($SqlInstance)"
$sqlcmd = (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue).Source
if (-not $sqlcmd) {
    $sqlcmd = Get-ChildItem 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE',
                            'C:\Program Files\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE' -ErrorAction SilentlyContinue |
              Select -First 1 -ExpandProperty FullName
}
$sqlOK = $false
if (-not $sqlcmd) {
    Warn 'sqlcmd.exe not found. Skipping SQL hardening (run the T-SQL by hand in SSMS).'
} else {
    $baseArgs = @('-S', $SqlInstance, '-E', '-b', '-W')
    foreach ($try in @(@('-C'), @())) {            # newer sqlcmd needs -C for self-signed certs; older rejects it
        & $sqlcmd @($baseArgs + $try) -Q 'SELECT 1' *> $null
        if ($LASTEXITCODE -eq 0) { $baseArgs += $try; $sqlOK = $true; break }
    }
    if (-not $sqlOK) { Warn 'Cannot connect to SQL with Windows auth. Is your account a sysadmin? Check -SqlInstance.' }
}

function Invoke-Sql {
    param([string]$Query, [string]$OutFile)
    $a = $baseArgs + @('-Q', $Query)
    if ($OutFile) { & $sqlcmd @a 2>&1 | Out-File $OutFile -Append } else { & $sqlcmd @a 2>&1 | Out-Null }
    $LASTEXITCODE
}

if ($sqlOK) {
    $rep = "$OutDir\report-sql.txt"
    # Baseline reports BEFORE changes
    Invoke-Sql "SELECT name, type_desc, is_disabled, create_date, modify_date FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY create_date DESC;" $rep | Out-Null
    Invoke-Sql "SELECT r.name AS role, m.name AS member FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id=rm.role_principal_id JOIN sys.server_principals m ON m.principal_id=rm.member_principal_id WHERE r.name IN ('sysadmin','securityadmin','serveradmin');" $rep | Out-Null
    Invoke-Sql "SELECT name, data_source, provider FROM sys.servers WHERE is_linked=1;" $rep | Out-Null
    Invoke-Sql "SELECT name, create_date FROM master.sys.procedures WHERE is_auto_executed=1;" $rep | Out-Null
    Invoke-Sql "SELECT name, parent_class_desc, create_date FROM sys.server_triggers;" $rep | Out-Null
    Invoke-Sql "SELECT name, is_trustworthy_on, SUSER_SNAME(owner_sid) AS owner FROM sys.databases;" $rep | Out-Null
    Invoke-Sql "SELECT name, enabled, date_modified FROM msdb.dbo.sysjobs;" $rep | Out-Null
    Invoke-Sql "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;" $rep | Out-Null
    Write-Host "    SQL baseline report: $rep"

    # Attack-surface reduction. Auth mode, logins and databases are NOT changed (scorer logs in and queries).
    Invoke-Sql "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;" | Out-Null
    foreach ($opt in 'xp_cmdshell', 'Ole Automation Procedures', 'Ad Hoc Distributed Queries', 'clr enabled',
                     'Database Mail XPs', 'external scripts enabled', 'remote admin connections', 'cross db ownership chaining') {
        if ((Invoke-Sql "EXEC sp_configure '$opt', 0; RECONFIGURE WITH OVERRIDE;") -eq 0) { Write-Host "    SQL option off: $opt" }
    }
    Invoke-Sql "EXEC sp_configure 'show advanced options', 0; RECONFIGURE;" | Out-Null

    # Rotate selected SQL logins (only when -ApplyPasswords). Add them to the PCR CSV either way.
    foreach ($login in $SqlLogins) {
        $pw = New-RandomPassword
        $pcr.Add("$login,$pw")
        if ($ApplyPasswords) {
            if ((Invoke-Sql "ALTER LOGIN [$login] WITH PASSWORD = N'$pw', CHECK_POLICY = OFF;") -eq 0) { Write-Host "    SQL password CHANGED: $login" }
            else { Warn "ALTER LOGIN failed for $login" }
        }
    }

    # Reduce abuse paths without touching scored behavior
    Invoke-Sql "EXEC sp_MSforeachdb 'USE [?]; IF DB_ID(''?'') > 4 BEGIN TRY REVOKE CONNECT FROM guest; END TRY BEGIN CATCH END CATCH';" | Out-Null
    foreach ($p in 'xp_cmdshell', 'xp_regread', 'xp_regwrite', 'xp_dirtree', 'xp_fileexist', 'xp_subdirs', 'xp_regdeletekey', 'xp_regdeletevalue') {
        Invoke-Sql "USE master; BEGIN TRY REVOKE EXECUTE ON [sys].[$p] FROM PUBLIC; END TRY BEGIN CATCH END CATCH;" | Out-Null
    }
    Invoke-Sql "EXEC sp_MSforeachdb 'IF DB_ID(''?'') > 4 ALTER DATABASE [?] SET TRUSTWORTHY OFF';" | Out-Null
    # Login auditing, failed + successful (effective after SQL restart)
    Invoke-Sql "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', REG_DWORD, 3;" | Out-Null

    Warn 'Read report-sql.txt: remove rogue logins/sysadmins, linked servers, startup procs, server triggers, Agent jobs. Do NOT drop scored logins or business databases.'
}
#endregion

#region 10. PCR password file -------------------------------------------------
$csv = "$OutDir\PCR-passwords.csv"
if ($pcr.Count -gt 0) {
    $pcr | Set-Content -Path $csv -Encoding ASCII
    icacls $csv /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    Step 'Quotient PCR file generated'
    Write-Host "    $csv   (format: username,password)" -ForegroundColor Green
    if ($ApplyPasswords) { Warn 'Passwords were changed on the box. Submit this CSV on the Quotient PCR tab NOW, then delete the file.' }
    else { Warn 'Passwords NOT yet applied. To rotate: rerun with -ApplyPasswords (new random values), then submit that CSV to PCR immediately.' }
    Warn 'Domain accounts (SMB/RDP checks may use them) are changed on the 2022 AD VM, not here. Submit those on PCR too.'
}
#endregion

#region 11. Self-test ---------------------------------------------------------
Step 'Post-run self-test'
foreach ($p in $ScoredPorts) {
    $listening = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
    $fw = if ($SkipFirewall) { 'n/a' } else { if (Get-NetFirewallRule -DisplayName "CCDC Allow TCP $p" -ErrorAction SilentlyContinue) { 'rule ok' } else { 'NO RULE' } }
    $state = if ($listening) { 'PASS' } else { 'FAIL (nothing listening)' }
    Write-Host ("    TCP {0,-5} listener: {1}  firewall: {2}" -f $p, $state, $fw)
}
foreach ($t in @(@('Palo Alto gateway', $GatewayIP, $null), @('AD', $ADIP, 389), @('AD DNS', $ADIP, 53))) {
    if ($t[2]) { $ok = (Test-NetConnection -ComputerName $t[1] -Port $t[2] -WarningAction SilentlyContinue).TcpTestSucceeded }
    else       { $ok = Test-Connection -ComputerName $t[1] -Count 1 -Quiet }
    Write-Host ("    {0,-18} {1}{2}: {3}" -f $t[0], $t[1], $(if ($t[2]) { ":$($t[2])" } else { '' }), $(if ($ok) { 'PASS' } else { 'FAIL' }))
}
if ($sqlOK) {
    $r = Invoke-Sql 'SELECT 1'
    Write-Host ("    SQL login+query: {0}" -f $(if ($r -eq 0) { 'PASS' } else { 'FAIL' }))
}
#endregion

#region 12. Finish ------------------------------------------------------------
gpupdate /force | Out-Null
Warn 'If this VM is domain-joined, a domain GPO may override local firewall/audit settings. Check with gpresult /r.'
if ($RestartSql) {
    Get-Service 'MSSQLSERVER', 'MSSQL$*' -ErrorAction SilentlyContinue | ForEach-Object { Restart-Service $_.Name -Force }
    Write-Host '    SQL Server restarted.'
} else { Warn 'Restart SQL (brief MSSQL outage) when convenient to enable login auditing. LSA protection needs a reboot - use the NETLAB power cycle only if needed.' }

Write-Host "`nDone. Reports and backups: $OutDir" -ForegroundColor Green
Write-Host 'NEXT: 1) Watch quotient.ccdc.events until MSSQL / RDP / SMB / Ping are green.' -ForegroundColor Green
if (-not $SkipFirewall -and $SafetyRevertMinutes -gt 0) {
    Write-Host '      2) THEN cancel the safety revert:  Unregister-ScheduledTask -TaskName CCDC-FW-Revert -Confirm:$false' -ForegroundColor Green
}
Stop-Transcript | Out-Null
#endregion

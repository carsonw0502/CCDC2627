<#
.SYNOPSIS
  MWCCDC Invitational - Windows Server 2019 / SQL Server 2019 hardening (VM 5, 172.20.240.120)

.DESCRIPTION
  Run ONE phase at a time from an elevated PowerShell prompt, then check Quotient
  (https://quotient.ccdc.events/) before running the next.

    -Phase Audit       Read-only. Users, admins, listening ports, shares, tasks, services, run keys, WMI.
    -Phase Passwords   Lists enabled local users and prompts you to type a new password for each.
    -Phase Firewall    Default-deny inbound; allows only 1433, 3389, 445, ICMP echo from ANY source.
    -Phase Hardening   Disables SMBv1, junk services, LLMNR/NetBIOS, WDigest; turns on logging + Defender.
    -Phase SQL         Audits SQL logins/config, disables dangerous features, optionally resets SQL logins.

  RULEBOOK CONSTRAINTS BAKED IN:
    - No account renaming/deleting (passwords only)             [Play rule 11]
    - No source-IP filtering of scored services (no knife-edge) [Systems rule 9]
    - ICMP stays allowed                                        [Play rule 12]
    - No hostname / IP changes                                  [Systems rule 7]
    - Scored here: SMB (445), RDP (3389), MSSQL (1433)

.EXAMPLE
  .\Harden-MSSQL.ps1                                   # interactive: asks before each phase, in order
  .\Harden-MSSQL.ps1 -SkipUsers sysadmin -SqlLogins sa # interactive, with options passed through
  .\Harden-MSSQL.ps1 -Phase Audit
  .\Harden-MSSQL.ps1 -Phase Passwords                        # prompts for a new password for each local user
  .\Harden-MSSQL.ps1 -Phase Firewall
  .\Harden-MSSQL.ps1 -Phase SQL -SqlLogins sa
#>
[CmdletBinding()]
param(
    # 'All' (default) walks through every phase in order and asks before each one.
    [ValidateSet('All','Audit','Passwords','Firewall','Hardening','SQL')]
    [string]$Phase = 'All',

    # Local users to leave alone in the Passwords phase
    [string[]]$SkipUsers = @(),

    # SQL logins whose passwords should be reset in the SQL phase (e.g. sa)
    [string[]]$SqlLogins = @(),

    [string]$SqlInstance = 'localhost',
    [string]$OutDir = 'C:\ccdc'
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Start-Transcript -Path (Join-Path $OutDir ("harden-{0}-{1}.log" -f $Phase, (Get-Date -Format 'HHmmss'))) | Out-Null

# ---------------------------------------------------------------- helpers
function Convert-SecureToPlain([System.Security.SecureString]$Secure) {
    # Only used to compare two typed entries; never printed or saved
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Host "[+] $Path\$Name = $Value"
}

# ---------------------------------------------------------------- phases
$descriptions = @{
    Audit     = 'Read-only inventory of users, ports, shares, tasks, services.'
    Passwords = 'Reset local user passwords (can affect scored logins).'
    Firewall  = 'Default-deny inbound; allow only 1433, 3389, 445, ICMP.'
    Hardening = 'SMBv1/LLMNR/NetBIOS off, junk services off, Defender, auditing.'
    SQL       = 'Audit SQL logins, disable risky features, optional login resets.'
}
$queue = if ($Phase -eq 'All') { 'Audit','Passwords','Firewall','Hardening','SQL' } else { @($Phase) }

foreach ($current in $queue) {

    if ($Phase -eq 'All') {
        Write-Host "`n------------------------------------------------------------" -ForegroundColor Magenta
        Write-Host "NEXT PHASE: $current - $($descriptions[$current])" -ForegroundColor Magenta
        Write-Host "Check the service status page first: did the last phase break anything?" -ForegroundColor Magenta
        $ans = Read-Host "Run it? [y = run, s = skip, q = quit]"
        if ($ans -eq 'q') { Write-Host "Stopping."; break }
        if ($ans -ne 'y') { Write-Host "Skipped $current."; continue }
    }

switch ($current) {

'Audit' {
    Write-Host "`n=== Host ===" -ForegroundColor Cyan
    $cs = Get-CimInstance Win32_ComputerSystem
    "Hostname: $($cs.Name)   DomainJoined: $($cs.PartOfDomain)   Domain: $($cs.Domain)"

    Write-Host "`n=== Local users ===" -ForegroundColor Cyan
    Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon | Format-Table -AutoSize

    Write-Host "=== Local Administrators ===" -ForegroundColor Cyan
    Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource -AutoSize

    Write-Host "=== Listening TCP ports ===" -ForegroundColor Cyan
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{ Addr = $_.LocalAddress; Port = $_.LocalPort; PID = $_.OwningProcess; Proc = $p.Name; Path = $p.Path }
    } | Format-Table -AutoSize

    Write-Host "=== UDP endpoints ===" -ForegroundColor Cyan
    Get-NetUDPEndpoint | Sort-Object LocalPort | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{ Addr = $_.LocalAddress; Port = $_.LocalPort; Proc = $p.Name }
    } | Format-Table -AutoSize

    Write-Host "=== Established connections (look for odd remote IPs) ===" -ForegroundColor Cyan
    Get-NetTCPConnection -State Established | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{ Local = "$($_.LocalAddress):$($_.LocalPort)"; Remote = "$($_.RemoteAddress):$($_.RemotePort)"; Proc = $p.Name }
    } | Format-Table -AutoSize

    Write-Host "=== SMB shares (do NOT remove the one holding the SOPs) ===" -ForegroundColor Cyan
    Get-SmbShare | Format-Table Name, Path, Description -AutoSize

    Write-Host "=== Non-Microsoft scheduled tasks ===" -ForegroundColor Cyan
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskName, TaskPath, State,
            @{n='Action'; e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ' }} |
        Format-List

    Write-Host "=== Autorun keys ===" -ForegroundColor Cyan
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object {
        if (Test-Path $_) { Write-Host $_; Get-ItemProperty $_ | Format-List }
    }
    Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue

    Write-Host "=== Services outside normal Windows/SQL paths ===" -ForegroundColor Cyan
    Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -notmatch 'System32|SysWOW64|Microsoft SQL Server|Windows Defender|Microsoft\\Edge|WindowsApps' } |
        Select-Object Name, State, StartMode, PathName | Format-Table -AutoSize -Wrap

    Write-Host "=== WMI event subscriptions (persistence) ===" -ForegroundColor Cyan
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
    Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue

    Write-Host "=== RDP / SMB / Firewall state ===" -ForegroundColor Cyan
    "fDenyTSConnections: " + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    "NLA (UserAuthentication): " + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature | Format-List
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize
}

'Passwords' {
    # Lists every ENABLED local user (including sysadmin / Administrator) and asks you to type
    # a new password for each. Nothing is generated and nothing is written to disk -
    # memorize what you type. Press Enter at a prompt to skip that user.
    # Use -SkipUsers to leave specific accounts out entirely (e.g. -SkipUsers sysadmin).
    Write-Host "Typed passwords are hidden and must be entered twice. Windows complexity rules apply (8+ chars, 3 of 4 character types)." -ForegroundColor Cyan
    Write-Host "Use a different password per account." -ForegroundColor Cyan

    foreach ($user in (Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin $SkipUsers })) {
        $name     = $user.Name
        $done     = $false
        $skipped  = $false
        $attempts = 0

        while (-not $done -and $attempts -lt 3) {
            $attempts++
            $p1 = Read-Host "New password for '$name' (Enter = skip this user)" -AsSecureString
            if ($p1.Length -eq 0) { Write-Host "[-] Skipped $name"; $skipped = $true; break }

            $p2 = Read-Host "Confirm password for '$name'" -AsSecureString
            if ((Convert-SecureToPlain $p1) -cne (Convert-SecureToPlain $p2)) {
                Write-Warning "Entries did not match. Try again ($attempts of 3)."
                continue
            }

            try {
                Set-LocalUser -Name $name -Password $p1 -PasswordNeverExpires $true -ErrorAction Stop
                $done = $true
                Write-Host "[+] Reset $name"
            } catch {
                Write-Warning "Could not set password for ${name}: $($_.Exception.Message) (complexity policy? try again - $attempts of 3)"
            }
        }

        if (-not $done -and -not $skipped) { Write-Warning "Gave up on $name - password unchanged." }
    }

    # Built-in accounts that should never be logging in (disabling, not deleting/renaming)
    foreach ($n in 'Guest','DefaultAccount','WDAGUtilityAccount') {
        if (Get-LocalUser -Name $n -ErrorAction SilentlyContinue) {
            Disable-LocalUser -Name $n -ErrorAction SilentlyContinue
            Write-Host "[+] Disabled $n"
        }
    }

    Write-Host "Domain accounts are NOT touched here - change those on the AD server (VM 4)." -ForegroundColor Yellow
    Write-Host "Check the service status page right away - if SMB/RDP/MSSQL went red, a scored account's password may need to be coordinated with the White Team." -ForegroundColor Yellow
}

'Firewall' {
    netsh advfirewall export (Join-Path $OutDir 'fw-backup.wfw') | Out-Null
    Write-Host "[+] Backed up firewall to $OutDir\fw-backup.wfw  (restore: netsh advfirewall import <file>)"

    # Firewall ON, inbound default-deny, outbound open (keeps AD auth, DNS, Splunk forwarder, updates working)
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384 `
        -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

    # Remove old CCDC rules if re-running
    Get-NetFirewallRule -DisplayName 'CCDC-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    # Disable every existing inbound ALLOW rule except Core Networking (DHCP/IPv6 plumbing)
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
        Where-Object { $_.DisplayGroup -ne 'Core Networking' } |
        Disable-NetFirewallRule

    # Scored services - RemoteAddress left as Any on purpose (no knife-edge filtering allowed)
    New-NetFirewallRule -DisplayName 'CCDC-MSSQL-1433' -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'CCDC-RDP-3389'   -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'CCDC-SMB-445'    -Direction Inbound -Protocol TCP -LocalPort 445  -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'CCDC-ICMPv4-Echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null

    Write-Host "`n[+] Inbound allowed now:" -ForegroundColor Green
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
        Select-Object DisplayName, DisplayGroup | Format-Table -AutoSize

    Write-Host @"

To block a specific attacker IP (allowed by the rules - only blocking IPs seen attacking):
  New-NetFirewallRule -DisplayName 'CCDC-BLOCK-1.2.3.4' -Direction Inbound -RemoteAddress 1.2.3.4 -Action Block
Block rules beat allow rules. NEVER block the scoring engine, the Palo Alto (172.20.240.254), or your own LAN.
Check blocked traffic: Get-Content `$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log -Tail 50
"@
}

'Hardening' {
    Write-Host "[*] SMB" -ForegroundColor Cyan
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
    # NOTE: not forcing SMB signing/encryption - the scoring engine's SMB client may not support it.

    Write-Host "[*] Credential / protocol hardening" -ForegroundColor Cyan
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1
    # NTLMv2 only. If SMB or SQL scoring goes red right after this, revert to 3.
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0   # LLMNR off

    Write-Host "[*] NetBIOS over TCP/IP off" -ForegroundColor Cyan
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | ForEach-Object {
        Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
    }

    Write-Host "[*] Disabling unneeded services (NOT touching LanmanServer, TermService, MSSQLSERVER, WinRM)" -ForegroundColor Cyan
    foreach ($svc in 'Spooler','RemoteRegistry','SNMP','TlntSvr','WebClient','SSDPSRV','upnphost','SQLBrowser','Fax','XblAuthManager','XblGameSave') {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $svc -StartupType Disabled
            Write-Host "[+] Disabled $svc"
        }
    }

    Write-Host "[*] RDP: ensure enabled (scored). NLA left at its current value." -ForegroundColor Cyan
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0

    Write-Host "[*] Defender" -ForegroundColor Cyan
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Update-MpSignature -ErrorAction SilentlyContinue
    Start-MpScan -ScanType QuickScan -AsJob | Out-Null

    Write-Host "[*] Logging (helps with incident reports)" -ForegroundColor Cyan
    auditpol /set /subcategory:"Logon"                    /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Account Lockout"          /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"User Account Management"  /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Process Creation"         /success:enable | Out-Null
    auditpol /set /subcategory:"Special Logon"            /success:enable | Out-Null
    auditpol /set /subcategory:"File Share"               /success:enable /failure:enable | Out-Null
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1

    Write-Host "`nVerify Quotient now. Hardening phase done." -ForegroundColor Green
}

'SQL' {
    if (-not (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "sqlcmd.exe not found in PATH. Try: C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\ or use SSMS."
        break
    }
    function Invoke-Sql([string]$Query) { & sqlcmd.exe -S $SqlInstance -E -b -W -Q $Query }

    Write-Host "`n=== Logins, status, sysadmin membership ===" -ForegroundColor Cyan
    Invoke-Sql @"
SET NOCOUNT ON;
SELECT name, type_desc, is_disabled, IS_SRVROLEMEMBER('sysadmin', name) AS is_sysadmin
FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%';
"@

    Write-Host "`n=== SQL logins with blank / username / default passwords (should return nothing) ===" -ForegroundColor Cyan
    Invoke-Sql @"
SET NOCOUNT ON;
SELECT name AS weak_login FROM sys.sql_logins
WHERE PWDCOMPARE('', password_hash)=1 OR PWDCOMPARE(name, password_hash)=1
   OR PWDCOMPARE('Changeme1!', password_hash)=1 OR PWDCOMPARE('password', password_hash)=1;
"@

    Write-Host "`n=== Disabling dangerous features ===" -ForegroundColor Cyan
    Invoke-Sql @"
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
EXEC sp_configure 'Ole Automation Procedures', 0;
EXEC sp_configure 'Ad Hoc Distributed Queries', 0;
EXEC sp_configure 'cross db ownership chaining', 0;
RECONFIGURE;
SELECT name, value_in_use FROM sys.configurations
WHERE name IN ('xp_cmdshell','Ole Automation Procedures','Ad Hoc Distributed Queries','cross db ownership chaining','clr enabled');
"@

    Write-Host "`n=== TRUSTWORTHY databases (privilege-escalation risk) ===" -ForegroundColor Cyan
    Invoke-Sql "SET NOCOUNT ON; SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name <> 'msdb';"

    Write-Host "`n=== TCP config (want static 1433, no dynamic port) ===" -ForegroundColor Cyan
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^MSSQL\d+\.' } | ForEach-Object {
            $p = Join-Path $_.PSPath 'MSSQLServer\SuperSocketNetLib\Tcp\IPAll'
            if (Test-Path $p) { Write-Host $_.PSChildName; Get-ItemProperty $p | Select-Object TcpPort, TcpDynamicPorts | Format-List }
        }

    if ($SqlLogins.Count -gt 0) {
        foreach ($login in $SqlLogins) {
            $p1 = Read-Host "New password for SQL login '$login' (Enter = skip)" -AsSecureString
            if ($p1.Length -eq 0) { Write-Host "[-] Skipped $login"; continue }
            $p2 = Read-Host "Confirm password for '$login'" -AsSecureString
            $plain = Convert-SecureToPlain $p1
            if ($plain -cne (Convert-SecureToPlain $p2)) { Write-Warning "Entries did not match - $login unchanged."; continue }

            $escaped = $plain.Replace("'", "''")   # escape single quotes for T-SQL
            Invoke-Sql "ALTER LOGIN [$login] WITH PASSWORD = '$escaped';"
            if ($LASTEXITCODE -eq 0) { Write-Host "[+] Reset SQL login $login" }
            else { Write-Warning "Failed to reset $login" }
            $plain = $null; $escaped = $null
        }
        Write-Host "`nIf the MSSQL scoring check goes red, the scoring engine may be using one of these logins." -ForegroundColor Yellow
    } else {
        Write-Host "`nNo -SqlLogins given. Re-run with e.g. -SqlLogins sa to reset SQL-auth passwords." -ForegroundColor Yellow
    }
}

}   # end switch

}   # end foreach

Stop-Transcript | Out-Null

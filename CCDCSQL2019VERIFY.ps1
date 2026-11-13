<#
.SYNOPSIS
  MWCCDC Invitational - health / drift check for the Server 2019 + SQL Server 2019 box (VM 5).

.DESCRIPTION
  Run it any time to confirm scored services are still reachable and your hardening is intact.
  Prints PASS / FAIL / WARN / INFO per check, logs to C:\ccdc\verify.log, and exits 1 if any FAIL.

  WORKFLOW
    1. Run Harden-MSSQL.ps1 and confirm scoring is healthy.
    2. Run:  .\Verify-MSSQL.ps1 -SaveBaseline      (snapshot of "known good": users, password-change
                                                    timestamps, admins, ports, shares, tasks, SQL sysadmins)
    3. Run:  .\Verify-MSSQL.ps1                    (compare current state to baseline + health checks)
       or:   .\Verify-MSSQL.ps1 -WatchMinutes 5    (re-run every 5 minutes until Ctrl+C)

  PASSWORD CHANGE DETECTION (two layers)
    - Always (needs baseline): flags any local account whose PasswordLastSet differs from baseline,
      so you can tell if someone other than you changed a password. No passwords are stored.
    - Optional -VerifyPasswords: you type each current password ONCE (kept in memory only, never
      written to disk); every run then tests that it still logs in.
      WARNING: each test is a real logon attempt. A wrong/changed password counts toward any account
      lockout threshold and creates Event 4625 entries. Use sparingly on accounts that matter.
    - Optional -CheckDefaultPassword: tests that the default 'Changeme1!' no longer works.

.EXAMPLE
  .\Verify-MSSQL.ps1 -SaveBaseline
  .\Verify-MSSQL.ps1
  .\Verify-MSSQL.ps1 -WatchMinutes 5 -OnlyProblems
  .\Verify-MSSQL.ps1 -VerifyPasswords -PasswordUsers sysadmin
  .\Verify-MSSQL.ps1 -CheckDefaultPassword
#>
[CmdletBinding()]
param(
    [switch]$SaveBaseline,
    [switch]$VerifyPasswords,
    [string[]]$PasswordUsers = @(),
    [switch]$CheckDefaultPassword,
    [int]$WatchMinutes = 0,
    [switch]$OnlyProblems,
    [string]$SqlInstance = 'localhost',
    [string]$OutDir = 'C:\ccdc'
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Run this from an elevated (Administrator) PowerShell window.'; return }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$BaselineFile = Join-Path $OutDir 'baseline.json'
$LogFile      = Join-Path $OutDir 'verify.log'

# Scored ports on this VM and the firewall rules Harden-MSSQL.ps1 creates
$RequiredPorts   = @{ 1433 = 'MSSQL'; 3389 = 'RDP'; 445 = 'SMB' }
$ExpectedPorts   = 135, 445, 1433, 3389, 5985, 47001, 5040     # normal Windows listeners (49152+ = dynamic RPC)
$ExpectedRules   = 'CCDC-MSSQL-1433', 'CCDC-RDP-3389', 'CCDC-SMB-445', 'CCDC-ICMPv4-Echo'
$DefaultPassword = 'Changeme1!'

$script:Results = New-Object System.Collections.Generic.List[object]
$script:Creds   = @{}

# ---------------------------------------------------------------- helpers
function Add-Result {
    param([string]$Category, [string]$Check, [ValidateSet('PASS','FAIL','WARN','INFO')][string]$Status, [string]$Detail = '')
    $script:Results.Add([pscustomobject]@{ Category = $Category; Check = $Check; Status = $Status; Detail = $Detail })
}

function Write-Result($r) {
    $color = switch ($r.Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
    Write-Host ("[{0}] {1,-9} {2,-32} {3}" -f $r.Status, $r.Category, $r.Check, $r.Detail) -ForegroundColor $color
}

function Convert-SecureToPlain([System.Security.SecureString]$Secure) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-SqlLines([string]$Query) {
    # Returns an array of output lines, or $null if sqlcmd failed / is unavailable
    if (-not (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)) { return $null }
    $out = & sqlcmd.exe -S $SqlInstance -E -b -h -1 -W -Q "SET NOCOUNT ON; $Query" 2>&1
    if ($LASTEXITCODE -ne 0) { return $null }
    $lines = @($out | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    return ,$lines
}

function Compare-List {
    param([string]$Category, [string]$Check, $Current, $Baseline, [string]$BadStatus = 'WARN')
    $cur  = @($Current  | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    $base = @($Baseline | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    $added   = @($cur  | Where-Object { $base -notcontains $_ })
    $removed = @($base | Where-Object { $cur  -notcontains $_ })
    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        Add-Result $Category $Check 'PASS' 'matches baseline'
    } else {
        $d = @()
        if ($added.Count)   { $d += "NEW: "     + ($added   -join ', ') }
        if ($removed.Count) { $d += "MISSING: " + ($removed -join ', ') }
        Add-Result $Category $Check $BadStatus ($d -join ' | ')
    }
}

function Test-ServiceRunning([string]$Name, [string]$Label) {
    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $s)                         { Add-Result 'Services' $Label 'FAIL' "service '$Name' not found" }
    elseif ($s.StartType -eq 'Disabled') { Add-Result 'Services' $Label 'FAIL' "$Name is DISABLED" }
    elseif ($s.Status -ne 'Running')     { Add-Result 'Services' $Label 'FAIL' "$Name is $($s.Status)" }
    else                                 { Add-Result 'Services' $Label 'PASS' "$Name running ($($s.StartType))" }
}

# Snapshot of the things we compare against baseline
function Get-State {
    $users = @(Get-LocalUser | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            Enabled         = [bool]$_.Enabled
            PasswordLastSet = $(if ($_.PasswordLastSet) { $_.PasswordLastSet.ToUniversalTime().Ticks.ToString() } else { '' })
        }
    })
    $runKeys = @(foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
        if (Test-Path $k) {
            (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$($_.Value)" }
        }
    })
    $sqlAdmins = Invoke-SqlLines "SELECT name FROM sys.server_principals WHERE type IN ('S','U','G') AND IS_SRVROLEMEMBER('sysadmin', name) = 1 ORDER BY name"
    [pscustomobject]@{
        Saved        = (Get-Date).ToString('o')
        Users        = $users
        Admins       = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        ListenPorts  = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
        Shares       = @(Get-SmbShare | ForEach-Object { $_.Name })
        Tasks        = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
        RunKeys      = $runKeys
        SqlSysadmins = @($sqlAdmins)
    }
}

# ---------------------------------------------------------------- the checks
function Invoke-Verification {
    $script:Results.Clear()

    $baseline = $null
    if (Test-Path $BaselineFile) {
        try { $baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json }
        catch { Add-Result 'Baseline' 'Load baseline.json' 'WARN' 'file exists but is unreadable' }
    }
    if ($baseline) { Add-Result 'Baseline' 'Baseline loaded' 'INFO' "saved $($baseline.Saved)" }
    else           { Add-Result 'Baseline' 'No baseline' 'WARN' 'drift checks skipped - run -SaveBaseline once things are healthy' }

    # ---- Services
    $sqlSvc = Get-Service | Where-Object { $_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*' } | Select-Object -First 1
    if ($sqlSvc) { Test-ServiceRunning $sqlSvc.Name 'SQL Server' } else { Add-Result 'Services' 'SQL Server' 'FAIL' 'no MSSQL service found' }
    Test-ServiceRunning 'LanmanServer' 'SMB server (Server)'
    Test-ServiceRunning 'TermService'  'Remote Desktop'
    Test-ServiceRunning 'WinDefend'    'Windows Defender'
    Test-ServiceRunning 'MpsSvc'       'Windows Firewall'
    Test-ServiceRunning 'EventLog'     'Event Log'

    # ---- Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AntivirusEnabled)            { Add-Result 'Defender' 'Antivirus enabled' 'PASS' } else { Add-Result 'Defender' 'Antivirus enabled' 'FAIL' 'AntivirusEnabled = False' }
        if ($mp.RealTimeProtectionEnabled)   { Add-Result 'Defender' 'Real-time protection' 'PASS' } else { Add-Result 'Defender' 'Real-time protection' 'FAIL' 'turned OFF' }
        if ($mp.AntivirusSignatureAge -le 7) { Add-Result 'Defender' 'Signature age' 'PASS' "$($mp.AntivirusSignatureAge) day(s)" }
        else                                 { Add-Result 'Defender' 'Signature age' 'WARN' "$($mp.AntivirusSignatureAge) days old" }
        $pref = Get-MpPreference
        $excl = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
        if ($excl.Count -eq 0) { Add-Result 'Defender' 'No exclusions' 'PASS' } else { Add-Result 'Defender' 'Exclusions present' 'WARN' (($excl | Select-Object -First 6) -join ', ') }
    } catch {
        Add-Result 'Defender' 'Status query' 'WARN' "Get-MpComputerStatus failed: $($_.Exception.Message)"
    }

    # ---- Firewall
    foreach ($p in Get-NetFirewallProfile) {
        if ([string]$p.Enabled -ne 'True')                 { Add-Result 'Firewall' "$($p.Name) profile" 'FAIL' 'firewall OFF' }
        elseif ([string]$p.DefaultInboundAction -ne 'Block') { Add-Result 'Firewall' "$($p.Name) profile" 'WARN' "default inbound = $($p.DefaultInboundAction)" }
        else                                                { Add-Result 'Firewall' "$($p.Name) profile" 'PASS' 'on, inbound default-deny' }
    }
    foreach ($name in $ExpectedRules) {
        $r = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if (-not $r) { Add-Result 'Firewall' "Rule $name" 'FAIL' 'rule missing'; continue }
        $remote = ($r | Get-NetFirewallAddressFilter).RemoteAddress
        if ([string]$r.Enabled -ne 'True' -or [string]$r.Action -ne 'Allow') { Add-Result 'Firewall' "Rule $name" 'FAIL' "Enabled=$($r.Enabled) Action=$($r.Action)" }
        elseif ("$remote" -ne 'Any')                                           { Add-Result 'Firewall' "Rule $name" 'FAIL' "RemoteAddress=$remote (must be Any - no knife-edge filtering)" }
        else                                                                   { Add-Result 'Firewall' "Rule $name" 'PASS' 'enabled, any source' }
    }
    $extra = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayGroup -ne 'Core Networking' -and $_.DisplayName -notlike 'CCDC-*' } | ForEach-Object { $_.DisplayName })
    if ($extra.Count -eq 0) { Add-Result 'Firewall' 'No extra inbound allows' 'PASS' }
    else                    { Add-Result 'Firewall' 'Extra inbound allow rules' 'WARN' (($extra | Select-Object -First 8) -join ' | ') }
    $blocks = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Block -ErrorAction SilentlyContinue)
    if ($blocks.Count -eq 0) { Add-Result 'Firewall' 'No inbound block rules' 'PASS' }
    else {
        $desc = $blocks | Select-Object -First 8 | ForEach-Object { "$($_.DisplayName) [$((($_ | Get-NetFirewallAddressFilter).RemoteAddress) -join ',')]" }
        Add-Result 'Firewall' 'Inbound block rules exist' 'WARN' ("make sure none hit the scoring engine: " + ($desc -join ' | '))
    }

    # ---- Ports
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    foreach ($port in ($RequiredPorts.Keys | Sort-Object)) {
        if ($listen -contains $port) { Add-Result 'Ports' "TCP $port ($($RequiredPorts[$port]))" 'PASS' 'listening' }
        else                         { Add-Result 'Ports' "TCP $port ($($RequiredPorts[$port]))" 'FAIL' 'NOT listening' }
    }
    if ($baseline) { $unexpected = @($listen | Where-Object { $_ -lt 49152 -and @($baseline.ListenPorts) -notcontains $_ }) }
    else           { $unexpected = @($listen | Where-Object { $_ -lt 49152 -and $ExpectedPorts -notcontains $_ }) }
    if ($unexpected.Count -eq 0) { Add-Result 'Ports' 'No unexpected listeners' 'PASS' }
    else {
        $detail = $unexpected | ForEach-Object {
            $c = Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue | Select-Object -First 1
            $proc = if ($c) { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } else { '?' }
            "$_($proc)"
        }
        Add-Result 'Ports' 'New/unexpected listeners' 'WARN' ($detail -join ', ')
    }

    # ---- SQL Server
    if (-not (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)) {
        Add-Result 'SQL' 'sqlcmd available' 'WARN' 'sqlcmd.exe not found - SQL checks skipped'
    } else {
        $t = Invoke-SqlLines 'SELECT 1'
        if ($null -eq $t) { Add-Result 'SQL' 'Login + query' 'FAIL' 'sqlcmd could not log in / run a query (Windows auth)' }
        else {
            Add-Result 'SQL' 'Login + query' 'PASS' 'query succeeded'
            $x = Invoke-SqlLines "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
            if ($x -and $x[0] -eq '0') { Add-Result 'SQL' 'xp_cmdshell disabled' 'PASS' } else { Add-Result 'SQL' 'xp_cmdshell' 'WARN' 'enabled (or could not read)' }
            $weak = Invoke-SqlLines "SELECT name FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1 OR PWDCOMPARE('$DefaultPassword', password_hash) = 1"
            if ($null -ne $weak -and $weak.Count -eq 0) { Add-Result 'SQL' 'No weak SQL passwords' 'PASS' }
            elseif ($weak)                              { Add-Result 'SQL' 'Weak SQL passwords' 'FAIL' ($weak -join ', ') }
            if ($baseline) {
                $admins = Invoke-SqlLines "SELECT name FROM sys.server_principals WHERE type IN ('S','U','G') AND IS_SRVROLEMEMBER('sysadmin', name) = 1 ORDER BY name"
                Compare-List 'SQL' 'sysadmin members' $admins $baseline.SqlSysadmins 'FAIL'
            }
        }
    }

    # ---- SMB / RDP / domain
    try {
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { Add-Result 'SMB/RDP' 'SMBv1' 'WARN' 'SMBv1 is enabled' } else { Add-Result 'SMB/RDP' 'SMBv1 disabled' 'PASS' }
    } catch { Add-Result 'SMB/RDP' 'SMBv1' 'WARN' 'could not read SMB config' }
    $custom = @(Get-SmbShare | Where-Object { $_.Name -notin 'ADMIN$', 'C$', 'IPC$' } | ForEach-Object { $_.Name })
    if ($custom.Count -gt 0) { Add-Result 'SMB/RDP' 'Custom shares (SOPs?)' 'INFO' ($custom -join ', ') }
    else                     { Add-Result 'SMB/RDP' 'Custom shares' 'WARN' 'none found - is the SOP share still there?' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0) { Add-Result 'SMB/RDP' 'RDP enabled' 'PASS' }
    else { Add-Result 'SMB/RDP' 'RDP enabled' 'FAIL' 'fDenyTSConnections = 1' }
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        try {
            if (Test-ComputerSecureChannel) { Add-Result 'SMB/RDP' 'Domain secure channel' 'PASS' } else { Add-Result 'SMB/RDP' 'Domain secure channel' 'FAIL' 'broken trust with DC (domain logins will fail)' }
        } catch { Add-Result 'SMB/RDP' 'Domain secure channel' 'WARN' $_.Exception.Message }
    }

    # ---- Accounts and password-change detection
    $state = Get-State
    $guest = $state.Users | Where-Object { $_.Name -eq 'Guest' }
    if ($guest -and $guest.Enabled) { Add-Result 'Accounts' 'Guest account' 'FAIL' 'Guest is ENABLED' } else { Add-Result 'Accounts' 'Guest disabled' 'PASS' }
    if ($baseline) {
        $bUsers = @{}
        foreach ($b in @($baseline.Users)) { $bUsers[$b.Name] = $b }
        $newUsers = @(); $pwChanged = @(); $enabledChanged = @()
        foreach ($u in $state.Users) {
            if (-not $bUsers.ContainsKey($u.Name)) { $newUsers += $u.Name; continue }
            $b = $bUsers[$u.Name]
            if ([string]$u.PasswordLastSet -ne [string]$b.PasswordLastSet) { $pwChanged += $u.Name }
            if ([bool]$u.Enabled -ne [bool]$b.Enabled) { $enabledChanged += "$($u.Name)->$(if ($u.Enabled) {'enabled'} else {'disabled'})" }
        }
        $gone = @($bUsers.Keys | Where-Object { $state.Users.Name -notcontains $_ })
        if ($newUsers.Count)       { Add-Result 'Accounts' 'New local users' 'FAIL' ($newUsers -join ', ') } else { Add-Result 'Accounts' 'No new local users' 'PASS' }
        if ($gone.Count)           { Add-Result 'Accounts' 'Users removed' 'WARN' ($gone -join ', ') }
        if ($pwChanged.Count)      { Add-Result 'Accounts' 'Password changed since baseline' 'FAIL' (($pwChanged -join ', ') + ' (PasswordLastSet differs - was this you?)') }
        else                       { Add-Result 'Accounts' 'Password timestamps' 'PASS' 'unchanged since baseline' }
        if ($enabledChanged.Count) { Add-Result 'Accounts' 'Enable/disable changed' 'FAIL' ($enabledChanged -join ', ') }
        Compare-List 'Accounts' 'Local Administrators' $state.Admins $baseline.Admins 'FAIL'
        Compare-List 'Persist'  'Scheduled tasks (non-MS)' $state.Tasks $baseline.Tasks 'WARN'
        Compare-List 'Persist'  'HKLM Run keys' $state.RunKeys $baseline.RunKeys 'WARN'
        Compare-List 'SMB/RDP'  'All SMB shares' $state.Shares $baseline.Shares 'WARN'
    }

    # ---- Live password tests (optional)
    if ($script:Creds.Count -gt 0 -or $CheckDefaultPassword) {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $env:COMPUTERNAME)
        try {
            foreach ($n in @($script:Creds.Keys)) {
                $plain = Convert-SecureToPlain $script:Creds[$n]
                $ok = $ctx.ValidateCredentials($n, $plain)
                $plain = $null
                if ($ok) { Add-Result 'Passwords' "Login test: $n" 'PASS' 'password still valid' }
                else     { Add-Result 'Passwords' "Login test: $n" 'FAIL' 'password REJECTED (changed, account disabled/locked, or typo)' }
            }
            if ($CheckDefaultPassword) {
                $stillDefault = @()
                foreach ($u in ($state.Users | Where-Object { $_.Enabled })) { if ($ctx.ValidateCredentials($u.Name, $DefaultPassword)) { $stillDefault += $u.Name } }
                if ($stillDefault.Count) { Add-Result 'Passwords' 'Default password still works' 'FAIL' ($stillDefault -join ', ') }
                else                     { Add-Result 'Passwords' 'No account uses default password' 'PASS' }
            }
        } finally { $ctx.Dispose() }
    }
}

function Show-Results {
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "`n===== Verification $stamp =====" -ForegroundColor Cyan
    $order = @{ FAIL = 0; WARN = 1; INFO = 2; PASS = 3 }
    foreach ($r in ($script:Results | Sort-Object { $order[$_.Status] }, Category)) {
        if ($OnlyProblems -and $r.Status -in 'PASS', 'INFO') { continue }
        Write-Result $r
    }
    $f = @($script:Results | Where-Object Status -eq 'FAIL').Count
    $w = @($script:Results | Where-Object Status -eq 'WARN').Count
    $p = @($script:Results | Where-Object Status -eq 'PASS').Count
    $summary = "SUMMARY: $p pass, $w warn, $f FAIL"
    Write-Host $summary -ForegroundColor $(if ($f) { 'Red' } elseif ($w) { 'Yellow' } else { 'Green' })

    Add-Content -Path $LogFile -Value "[$stamp] $summary"
    foreach ($r in ($script:Results | Where-Object { $_.Status -in 'FAIL', 'WARN' })) {
        Add-Content -Path $LogFile -Value ("    [{0}] {1} / {2}: {3}" -f $r.Status, $r.Category, $r.Check, $r.Detail)
    }
    return $f
}

# ---------------------------------------------------------------- main
if ($SaveBaseline) {
    Write-Host "Saving baseline of the CURRENT state. Only do this when everything is known-good." -ForegroundColor Yellow
    Get-State | ConvertTo-Json -Depth 5 | Set-Content -Path $BaselineFile -Encoding UTF8
    Write-Host "[+] Baseline saved to $BaselineFile (no passwords are stored)." -ForegroundColor Green
    Write-Host "    Re-run -SaveBaseline after you intentionally change passwords or add users." -ForegroundColor Yellow
    return
}

if ($VerifyPasswords) {
    Write-Host "Enter the CURRENT password for each account to monitor (hidden, kept in memory only). Enter = skip." -ForegroundColor Cyan
    Write-Host "Each run performs one real logon attempt per account (counts toward lockout if a password is wrong)." -ForegroundColor Yellow
    $names = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
    if ($PasswordUsers.Count -gt 0) { $names = @($names | Where-Object { $PasswordUsers -contains $_ }) }
    foreach ($n in $names) {
        $s = Read-Host "Current password for '$n'" -AsSecureString
        if ($s.Length -gt 0) { $script:Creds[$n] = $s }
    }
}

if ($WatchMinutes -gt 0) {
    Write-Host "Watching every $WatchMinutes minute(s). Press Ctrl+C to stop." -ForegroundColor Cyan
    while ($true) {
        Invoke-Verification
        $fails = Show-Results
        if ($fails -gt 0) { try { [console]::Beep(1000, 400) } catch {} }
        Start-Sleep -Seconds ($WatchMinutes * 60)
    }
} else {
    Invoke-Verification
    $fails = Show-Results
    if ($fails -gt 0) { exit 1 } else { exit 0 }
}

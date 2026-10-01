<#
  provision.ps1 — stand up a DELIBERATELY-VULNERABLE AD Domain Controller. LAB ONLY.
  Idempotent in two passes:
    pass 1: install AD DS + promote to a new forest (lab.local), then reboot.
    pass 2 (vagrant provision again): seed vulnerable accounts.
  Seeds:
    - svc_sql   : Kerberoastable (has an SPN) + weak password  -> kerberoast
    - svc_asrep : AS-REP roastable (no Kerberos pre-auth)       -> kerberos_asrep
    - Administrator password set weak                            -> dcsync/psexec/petitpotam
#>
$ErrorActionPreference = "Stop"
$Domain       = "lab.local"
$WeakPass     = "Passw0rd!"
$DsrmPass     = ConvertTo-SecureString "P@ssw0rd-DSRM!" -AsPlainText -Force

# ---- pass 1: install + promote -------------------------------------------
if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    Write-Host "[*] Installing AD DS role..."
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
}

$isDC = $false
try { $isDC = (Get-Service NTDS -ErrorAction Stop) -ne $null } catch { $isDC = $false }

if (-not $isDC) {
    Write-Host "[*] Promoting to Domain Controller for $Domain (will reboot)..."
    Import-Module ADDSDeployment
    Install-ADDSForest -DomainName $Domain -SafeModeAdministratorPassword $DsrmPass `
        -InstallDns -Force -NoRebootOnCompletion:$false
    Write-Host "[*] Promotion started; the box will reboot. Run 'vagrant provision' again."
    return
}

# ---- pass 2: seed vulnerable accounts ------------------------------------
Import-Module ActiveDirectory
$sec = ConvertTo-SecureString $WeakPass -AsPlainText -Force

# weak Administrator password (dcsync/psexec/petitpotam use these creds)
Set-ADAccountPassword -Identity Administrator -NewPassword $sec -Reset

# Kerberoastable: user WITH an SPN + weak password
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'")) {
    New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword $sec `
        -Enabled $true -PasswordNeverExpires $true
    Set-ADUser svc_sql -ServicePrincipalNames @{Add = "MSSQL/dc01.$Domain:1433"}
    Write-Host "[*] Created Kerberoastable svc_sql (SPN MSSQL/dc01.$Domain:1433)"
}

# AS-REP roastable: no Kerberos pre-auth required
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_asrep'")) {
    New-ADUser -Name "svc_asrep" -SamAccountName "svc_asrep" -AccountPassword $sec `
        -Enabled $true -PasswordNeverExpires $true
    Set-ADAccountControl svc_asrep -DoesNotRequirePreAuth $true
    Write-Host "[*] Created AS-REP-roastable svc_asrep (no pre-auth)"
}

# --- alternate SMB/RPC ports for the cloud path -----------------------------
# ISPs commonly block OUTBOUND 445 (and raw SMB/RPC shouldn't sit on a public
# edge), so expose SMB and RPC on alternate high ports and let the client reach
# those (the harness maps them in modules/_portpatch.py: 445->4445, 135->1135).
# netsh portproxy forwards the alternate port to the real local service; the
# host firewall must also allow the alternate ports (the cloud SG already does).
# RPC/DCOM also uses a dynamic high port after 135 — that is NOT forwarded here,
# so SMB-based modules (psexec, dcsync over the SMB pipe) work on the cloud path
# while pure-DCOM (wmiexec) may still need direct 135 + the dynamic range.
try {
    netsh interface portproxy add v4tov4 listenport=4445 listenaddress=0.0.0.0 connectport=445 connectaddress=127.0.0.1 | Out-Null
    netsh interface portproxy add v4tov4 listenport=1135 listenaddress=0.0.0.0 connectport=135 connectaddress=127.0.0.1 | Out-Null
    foreach ($p in 4445, 1135) {
        $n = "USS-alt-$p"
        if (-not (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $n -Direction Inbound -Protocol TCP `
                -LocalPort $p -Action Allow | Out-Null
        }
    }
    Write-Host "[*] Alternate ports up: SMB 4445->445, RPC 1135->135 (cloud path)"
} catch { Write-Host "[!] could not set up alternate SMB/RPC portproxy: $_" }

Write-Host ""
Write-Host "[+] AD DC ready:"
Write-Host "      domain=$Domain  admin=Administrator  pass=$WeakPass"
Write-Host "      kerberoast=svc_sql  asrep=svc_asrep"
Write-Host "      cloud alt-ports: SMB 4445, RPC 1135 (also raw 445/135 locally)"
Write-Host "    Point the harness: HARNESS_DOMAIN=$Domain HARNESS_DC_USER=Administrator HARNESS_DC_PASS='$WeakPass'"

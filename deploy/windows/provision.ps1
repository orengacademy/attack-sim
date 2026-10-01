<#
  provision.ps1 — stand up a DELIBERATELY-VULNERABLE AD Domain Controller. LAB ONLY.
  Idempotent in two passes:
    pass 1: install AD DS + promote to a new forest (lab.local), then reboot.
    pass 2 (vagrant provision again): seed vulnerable accounts.
  Seeds:
    - svc_sql   : Kerberoastable (has an SPN) + weak password  -> kerberoast
    - svc_asrep : AS-REP roastable (no Kerberos pre-auth)       -> kerberos_asrep
    - Administrator password set weak                            -> dcsync/psexec/petitpotam
    - ms-DS-MachineAccountQuota = 10 (default, set explicitly)   -> nopac/samaccountname_spoof

  ⚠ nopac (CVE-2021-42278 + CVE-2021-42287) and samaccountname_spoof
    (CVE-2021-42278) require an UNPATCHED DC. A fully-patched Windows Server
    (KB5008380/KB5008602, Nov-2021+) is NOT vulnerable — those two modules will
    then correctly fail. For a repeatable lab, build this DC from an pre-Nov-2021
    media/image and DO NOT run Windows Update, or accept that only the other AD
    modules (kerberoast/asrep/dcsync/psexec/petitpotam) will land.
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

# machine-account quota (default 10) that nopac/samaccountname_spoof rely on to
# add a computer account — set explicitly so the lab doesn't depend on a default
# that a hardened build may have zeroed. (The DC must also be UNPATCHED — see top.)
try {
    Set-ADDomain -Identity $Domain -Replace @{"ms-DS-MachineAccountQuota" = "10"}
    Write-Host "[*] ms-DS-MachineAccountQuota set to 10 (nopac/samaccountname_spoof)"
} catch { Write-Host "[!] could not set ms-DS-MachineAccountQuota: $_" }

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

Write-Host ""
Write-Host "[+] AD DC ready:"
Write-Host "      domain=$Domain  admin=Administrator  pass=$WeakPass"
Write-Host "      kerberoast=svc_sql  asrep=svc_asrep"
Write-Host "    Point the harness: HARNESS_DOMAIN=$Domain HARNESS_DC_USER=Administrator HARNESS_DC_PASS='$WeakPass'"

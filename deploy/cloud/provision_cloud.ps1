<#
  provision_cloud.ps1 — cloud/unattended wrapper around the existing provision.ps1.

  provision.ps1 is 2-pass (promote -> REBOOT -> seed). On a desktop you run
  `vagrant provision` twice; in the cloud there's no second manual pass, so this
  wrapper registers a SYSTEM scheduled task that re-runs provision.ps1 at every
  startup until the vulnerable accounts exist, then removes itself. It reuses
  provision.ps1 unchanged, so the lab definition stays in one place.

  Expects provision.ps1 to sit NEXT TO this file (both delivered by Terraform's
  CustomScriptExtension). LAB ONLY — deliberately vulnerable AD.
#>
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$prov = Join-Path $here "provision.ps1"
$self = $MyInvocation.MyCommand.Path
$taskName = "USS-AD-Seed"

if (-not (Test-Path $prov)) { throw "provision.ps1 not found next to provision_cloud.ps1" }

# Register a startup task that finishes provisioning after the promo reboot, then
# self-removes once the AS-REP-roastable account (last thing provision.ps1 seeds)
# exists — idempotent and safe to run repeatedly.
$seedCmd = @"
try {
  & '$prov'
  Import-Module ActiveDirectory -ErrorAction SilentlyContinue
  if (Get-ADUser -Filter "SamAccountName -eq 'svc_asrep'" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue
  }
} catch { }
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($seedCmd))

if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
  $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
             -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $princ -Description "Finish USS vulnerable-AD provisioning after reboot" | Out-Null
  Write-Host "[*] Registered startup task '$taskName' to finish provisioning after reboot."
}

# Kick off pass 1 now (installs AD DS + promotes, then reboots -> task does pass 2).
Write-Host "[*] Running provision.ps1 (pass 1)…"
& $prov
Write-Host "[*] provision_cloud.ps1 done (a reboot + startup task will complete seeding)."

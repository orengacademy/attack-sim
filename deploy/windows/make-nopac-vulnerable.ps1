# make-nopac-vulnerable.ps1 — revert an already-PATCHED live DC so nopac
# (CVE-2021-42287) and samaccountname_spoof (CVE-2021-42278) succeed again.
# provision.ps1 builds fresh DCs UNPATCHED; use THIS only when the live DC was
# patched (e.g. Windows Update ran) and you can't rebuild it right now.
#
# Run ON THE DC as Administrator (via RDP/WinRM/psexec), then REBOOT:
#   powershell -ExecutionPolicy Bypass -File make-nopac-vulnerable.ps1
#
# ⚠ Removing a cumulative update is not always possible and is slow; a rebuild
# from unpatched media is the reliable path. This is best-effort. Lab only.
param([switch]$Reboot)

Write-Host "[*] make-nopac-vulnerable: reverting CVE-2021-42287/42278 hardening"

# 1) the mitigating control nopac/sama rely on being OPEN
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{"ms-DS-MachineAccountQuota" = "10"}
    Write-Host "[*] ms-DS-MachineAccountQuota = 10 (lets a low-priv user add a machine account)"
} catch { Write-Host "[!] could not set MachineAccountQuota: $_" }

# 2) remove the KBs that fix CVE-2021-42287 (Nov-2021 CU and the specific updates)
$kbs = @("KB5008380", "KB5008602", "KB5007206", "KB5007205")
foreach ($kb in $kbs) {
    $num = $kb -replace "KB", ""
    $present = Get-HotFix -Id $kb -ErrorAction SilentlyContinue
    if ($present) {
        Write-Host "[*] removing $kb ..."
        Start-Process -FilePath "wusa.exe" -ArgumentList "/uninstall /kb:$num /quiet /norestart" -Wait -ErrorAction SilentlyContinue
    } else {
        Write-Host "[-] $kb not present (good, or newer CU supersedes it — a rebuild may be needed)"
    }
}

Write-Host "[*] DONE. A REBOOT is required for the change to take effect."
Write-Host "    Verify afterwards from the harness:  cli.py --target <dc> --only nopac,samaccountname_spoof --confirm-roe"
if ($Reboot) { Write-Host "[*] rebooting..."; Restart-Computer -Force }

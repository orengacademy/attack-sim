output "dc_private_ip" {
  description = "Private IP of the DC — point the harness here from inside the VNet/VPN."
  value       = azurerm_network_interface.nic.private_ip_address
}

output "dc_public_ip" {
  description = "Public IP (only if create_public_ip = true)."
  value       = var.create_public_ip ? azurerm_public_ip.pip[0].ip_address : "(none — reach via VNet/VPN)"
}

output "harness_hint" {
  description = "How to point the harness at this DC once provisioning completes."
  value = join("\n", [
    "# domain lab.local — Administrator password is the lab weak password from provision.ps1",
    "export HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator HARNESS_DC_PASS='Passw0rd!'",
    "python3 cli.py --target ${azurerm_network_interface.nic.private_ip_address} \\",
    "  --only kerberoast,kerberos_asrep,ldap_null_bind --confirm-roe   # survive ISP 139/445 block",
    "python3 cli.py --target ${azurerm_network_interface.nic.private_ip_address} \\",
    "  --only dcsync,psexec,petitpotam,eastwest_lateral --confirm-roe  # need 445 (run intra-cloud)",
  ])
}

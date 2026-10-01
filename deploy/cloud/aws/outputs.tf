output "dc_private_ip" {
  description = "Private IP — point the harness here from inside the VPC/VPN."
  value       = aws_instance.dc.private_ip
}

output "dc_public_ip" {
  description = "Public IP (only if create_public_ip = true)."
  value       = var.create_public_ip ? aws_instance.dc.public_ip : "(none — reach via VPC/VPN)"
}

output "windows_password_data" {
  description = "Encrypted local admin password (decrypt with your key_name .pem). The DOMAIN Administrator password is the lab weak password set by provision.ps1."
  value       = aws_instance.dc.password_data
  sensitive   = true
}

output "harness_hint" {
  description = "Point the harness at this DC once provisioning completes (~15-20 min)."
  value       = "export HARNESS_DOMAIN=lab.local HARNESS_DC_USER=Administrator HARNESS_DC_PASS='Passw0rd!'; python3 cli.py --target ${aws_instance.dc.private_ip} --only kerberoast,kerberos_asrep,ldap_null_bind --confirm-roe"
}

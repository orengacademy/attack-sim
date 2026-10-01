output "dc_internal_ip" {
  description = "Internal IP — point the harness here from inside the VPC/VPN."
  value       = google_compute_instance.dc.network_interface[0].network_ip
}

output "dc_external_ip" {
  description = "External IP (only if create_public_ip = true)."
  value       = var.create_public_ip ? google_compute_instance.dc.network_interface[0].access_config[0].nat_ip : "(none — reach via VPC/VPN)"
}

output "password_hint" {
  description = "Retrieve the local admin password; the DOMAIN Administrator password is the lab weak password from provision.ps1."
  value       = "gcloud compute reset-windows-password ${google_compute_instance.dc.name} --zone ${var.zone}"
}

# ---------------------------------------------------------------------------
# MyGovNet USS — vulnerable Windows AD DC in GCP (cloud target).
#
#   ⚠ LAB ONLY. Deliberately-vulnerable AD. Firewall locked to var.tester_cidrs
#   ONLY — never 0.0.0.0/0. `terraform destroy` after the window.
#
# Delivers provision.ps1 + provision_cloud.ps1 via the windows-startup-script-ps1
# metadata (base64-embedded), reusing the same lab definition as Vagrant/Azure/AWS.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.3"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.20" }
  }
}

provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

locals {
  # SMB/RPC on ALTERNATE high ports (RPC 1135, SMB 4445) via a netsh portproxy on
  # the DC — not raw 139/445 (blocked outbound by ISPs; off the public edge).
  # Client maps them in _portpatch.py; raw 135 stays for the RPC EPM (DCOM).
  allowed_tcp = ["53", "88", "135", "1135", "389", "636", "3268",
  "3269", "3389", "4445", "5985", "5986"]
  allowed_udp = ["53", "88", "123", "389"]
  startup = templatefile("${path.module}/startup.ps1.tftpl", {
    prov_b64  = filebase64("${path.module}/../../windows/provision.ps1")
    provc_b64 = filebase64("${path.module}/../provision_cloud.ps1")
  })
}

resource "google_compute_firewall" "dc" {
  name    = "${var.prefix}-dc-allow-testers"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = local.allowed_tcp
  }
  allow {
    protocol = "udp"
    ports    = local.allowed_udp
  }
  source_ranges = var.tester_cidrs
  target_tags   = ["${var.prefix}-dc"]
}

resource "google_compute_instance" "dc" {
  name         = "${var.prefix}-dc01"
  machine_type = var.machine_type
  tags         = ["${var.prefix}-dc"]

  boot_disk {
    initialize_params {
      image = "windows-cloud/windows-2022"
      size  = 60
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork
    # public IP only if requested; otherwise reach via VPN/Cloud Interconnect
    dynamic "access_config" {
      for_each = var.create_public_ip ? [1] : []
      content {}
    }
  }

  metadata = {
    windows-startup-script-ps1 = local.startup
  }
}

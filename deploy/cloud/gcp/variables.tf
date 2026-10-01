variable "project" {
  description = "GCP project id."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "asia-southeast1"
}

variable "zone" {
  description = "GCP zone."
  type        = string
  default     = "asia-southeast1-a"
}

variable "network" {
  description = "VPC network name."
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Subnetwork (leave null for auto-mode 'default')."
  type        = string
  default     = null
}

variable "tester_cidrs" {
  description = "REQUIRED. Source CIDRs allowed to reach the vulnerable DC. NEVER 0.0.0.0/0."
  type        = list(string)
}

variable "prefix" {
  description = "Name prefix."
  type        = string
  default     = "ussdc"
}

variable "machine_type" {
  description = "Machine type (>= 8 GB RAM for AD DS)."
  type        = string
  default     = "e2-standard-2"
}

variable "create_public_ip" {
  description = "Attach an external IP. Prefer false + reach via VPN; firewall still restricts to tester_cidrs."
  type        = bool
  default     = false
}

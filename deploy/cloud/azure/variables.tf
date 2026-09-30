variable "prefix" {
  description = "Name prefix for all resources (lowercase letters/digits)."
  type        = string
  default     = "ussdc"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "southeastasia"
}

variable "tester_cidrs" {
  description = "REQUIRED. Source IP/CIDRs allowed to reach the vulnerable DC (your tester / NOC egress). NEVER use 0.0.0.0/0 — this is a deliberately-vulnerable host."
  type        = list(string)
  # no default on purpose — you must set this in terraform.tfvars
}

variable "admin_username" {
  description = "Local admin username created by Azure at build (before promotion). provision.ps1 then sets the DOMAIN Administrator password to the lab weak password."
  type        = string
  default     = "azadmin"
}

variable "admin_password" {
  description = "Local admin password at build (min 12 chars, Azure complexity). Not the lab domain password."
  type        = string
  sensitive   = true
}

variable "vm_size" {
  description = "VM size (needs >= 4 GB RAM for AD DS)."
  type        = string
  default     = "Standard_B2ms"
}

variable "create_public_ip" {
  description = "Attach a public IP. Prefer false + reach it over your VPN/ExpressRoute; if true, the NSG still restricts to tester_cidrs."
  type        = bool
  default     = false
}

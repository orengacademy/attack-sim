variable "prefix" {
  description = "Name prefix for resources."
  type        = string
  default     = "ussdc"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "ap-southeast-1"
}

variable "vpc_id" {
  description = "VPC to place the DC in."
  type        = string
}

variable "subnet_id" {
  description = "Subnet for the DC (reach it from inside the VPC / your VPN)."
  type        = string
}

variable "tester_cidrs" {
  description = "REQUIRED. Source CIDRs allowed to reach the vulnerable DC. NEVER 0.0.0.0/0."
  type        = list(string)
}

variable "key_name" {
  description = "EC2 key pair name (to retrieve the Windows admin password). Optional but recommended."
  type        = string
  default     = null
}

variable "instance_type" {
  description = "Instance type (>= 4 GB RAM for AD DS)."
  type        = string
  default     = "t3.large"
}

variable "create_public_ip" {
  description = "Associate a public IP. Prefer false + reach via VPN; SG still restricts to tester_cidrs."
  type        = bool
  default     = false
}

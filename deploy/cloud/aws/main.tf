# ---------------------------------------------------------------------------
# MyGovNet USS — vulnerable Windows AD DC in AWS (cloud target).
#
#   ⚠ LAB ONLY. Deliberately-vulnerable AD. Security group locked to
#   var.tester_cidrs ONLY — never 0.0.0.0/0. `terraform destroy` after the window.
#
# Delivers the existing provision.ps1 + provision_cloud.ps1 via EC2 user_data
# (base64-embedded — no S3 bucket needed), reusing the same lab definition as the
# Vagrant/Azure paths.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.40" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_ami" "win2022" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  allowed_tcp = [53, 88, 135, 139, 389, 445, 636, 3268, 3269, 3389, 5985, 5986]
  user_data = templatefile("${path.module}/user_data.ps1.tftpl", {
    prov_b64  = filebase64("${path.module}/../../windows/provision.ps1")
    provc_b64 = filebase64("${path.module}/../provision_cloud.ps1")
  })
}

resource "aws_security_group" "dc" {
  name        = "${var.prefix}-dc-sg"
  description = "USS vulnerable DC — tester CIDRs only"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = local.allowed_tcp
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = var.tester_cidrs
    }
  }
  # DNS + Kerberos also use UDP
  dynamic "ingress" {
    for_each = [53, 88, 123, 137, 138, 389]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "udp"
      cidr_blocks = var.tester_cidrs
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.prefix}-dc-sg" }
}

resource "aws_instance" "dc" {
  ami                         = data.aws_ami.win2022.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.dc.id]
  key_name                    = var.key_name
  associate_public_ip_address = var.create_public_ip
  user_data                   = local.user_data
  get_password_data           = var.key_name != null

  root_block_device {
    volume_size = 60
    volume_type = "gp3"
  }
  tags = { Name = "${var.prefix}-dc01" }
}

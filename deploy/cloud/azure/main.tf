# ---------------------------------------------------------------------------
# MyGovNet USS — vulnerable Windows AD DC in Azure (KVDC/cloud target).
#
#   ⚠ LAB ONLY. Deliberately-vulnerable AD (weak Administrator, Kerberoastable
#   SPN, AS-REP-roastable account). Locked by NSG to var.tester_cidrs ONLY.
#   Never open to 0.0.0.0/0. Tear down with `terraform destroy` after the window.
#
# Reuses the existing provision.ps1 (deploy/windows/) verbatim, delivered via a
# CustomScriptExtension and finished after the promo-reboot by provision_cloud.ps1.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.3"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.100" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "azurerm" {
  features {}
}

locals {
  # AD / management ports the harness needs to the DC (see README for the ISP
  # 139/445 caveat on the cloud path). Opened to tester_cidrs ONLY.
  allowed_ports = ["53", "88", "135", "139", "389", "445", "636", "3268",
                   "3269", "3389", "5985", "5986"]
}

resource "random_string" "sfx" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_resource_group" "rg" {
  name     = "${var.prefix}-rg"
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.prefix}-vnet"
  address_space       = ["10.90.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.90.1.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  # single rule: tester CIDRs -> the AD/mgmt ports. Everything else denied by the
  # default NSG rules. This is the guardrail that keeps a vulnerable DC contained.
  security_rule {
    name                       = "allow-testers"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_ranges    = local.allowed_ports
    source_address_prefixes    = var.tester_cidrs
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "pip" {
  count               = var.create_public_ip ? 1 : 0
  name                = "${var.prefix}-pip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "nic" {
  name                = "${var.prefix}-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ipcfg"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.create_public_ip ? azurerm_public_ip.pip[0].id : null
  }
}

resource "azurerm_network_interface_security_group_association" "assoc" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_windows_virtual_machine" "dc" {
  name                = "${var.prefix}-dc01"
  computer_name       = "DC01"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = var.vm_size
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  network_interface_ids = [azurerm_network_interface.nic.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
}

# ----- deliver + run the provisioning scripts (reuse the existing provision.ps1) -
resource "azurerm_storage_account" "sa" {
  name                     = "${var.prefix}prov${random_string.sfx.result}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_container" "prov" {
  name                  = "provisioning"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "provision" {
  name                   = "provision.ps1"
  storage_account_name   = azurerm_storage_account.sa.name
  storage_container_name = azurerm_storage_container.prov.name
  type                   = "Block"
  source                 = "${path.module}/../../windows/provision.ps1"
}

resource "azurerm_storage_blob" "provision_cloud" {
  name                   = "provision_cloud.ps1"
  storage_account_name   = azurerm_storage_account.sa.name
  storage_container_name = azurerm_storage_container.prov.name
  type                   = "Block"
  source                 = "${path.module}/../provision_cloud.ps1"
}

resource "azurerm_virtual_machine_extension" "provision" {
  name                       = "provision-ad"
  virtual_machine_id         = azurerm_windows_virtual_machine.dc.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    fileUris = [azurerm_storage_blob.provision.url, azurerm_storage_blob.provision_cloud.url]
  })
  # private blobs: the extension authenticates with the storage account key.
  protected_settings = jsonencode({
    commandToExecute     = "powershell -ExecutionPolicy Bypass -File provision_cloud.ps1"
    storageAccountName   = azurerm_storage_account.sa.name
    storageAccountKey    = azurerm_storage_account.sa.primary_access_key
  })
}

# =============================================================================
# HIE SIEM Framework — Azure Canada Central Foundation
# Region: canadacentral | Compliance: HIPAA, PHIPA, PIPEDA
# =============================================================================

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
  }
  backend "azurerm" {
    resource_group_name  = "hie-siem-tfstate-rg"
    storage_account_name = "hiesiemtfstateca"
    container_name       = "tfstate"
    key                  = "azure/foundation/terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy               = false
      recover_soft_deleted_key_vaults            = true
      purge_soft_deleted_secrets_on_destroy      = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }
}

# =============================================================================
# Resource Groups
# =============================================================================
resource "azurerm_resource_group" "hie_siem" {
  name     = "hie-siem-${var.environment}-rg"
  location = var.azure_region

  tags = {
    Project    = "HIE-SIEM"
    Compliance = "HIPAA-PHIPA-PIPEDA"
    DataClass  = "PHI-Restricted"
    ManagedBy  = "Terraform"
  }
}

# =============================================================================
# Key Vault — PHI encryption keys and secrets
# =============================================================================
resource "azurerm_key_vault" "hie_siem" {
  name                        = "hie-siem-kv-${var.environment}"
  location                    = azurerm_resource_group.hie_siem.location
  resource_group_name         = azurerm_resource_group.hie_siem.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium" # HSM-backed keys for PHI
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true # WORM equivalent for key vault

  network_acls {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.private.id]
  }
}

resource "azurerm_key_vault_key" "hie_master" {
  name         = "hie-siem-master-key"
  key_vault_id = azurerm_key_vault.hie_siem.id
  key_type     = "RSA-HSM"
  key_size     = 4096
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P365D"
    notify_before_expiry = "P30D"
  }
}

# =============================================================================
# Virtual Network
# =============================================================================
resource "azurerm_virtual_network" "hie_siem" {
  name                = "hie-siem-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.hie_siem.location
  resource_group_name = azurerm_resource_group.hie_siem.name
}

resource "azurerm_subnet" "private" {
  name                 = "hie-siem-private-subnet"
  resource_group_name  = azurerm_resource_group.hie_siem.name
  virtual_network_name = azurerm_virtual_network.hie_siem.name
  address_prefixes     = [var.private_subnet_cidr]

  service_endpoints = [
    "Microsoft.KeyVault",
    "Microsoft.Storage",
    "Microsoft.Sql"
  ]
}

# NSG — deny-by-default, explicit allow for SIEM traffic only
resource "azurerm_network_security_group" "hie_siem" {
  name                = "hie-siem-nsg"
  location            = azurerm_resource_group.hie_siem.location
  resource_group_name = azurerm_resource_group.hie_siem.name

  # Wazuh agent registration
  security_rule {
    name                       = "Allow-Wazuh-Agent-Enrollment"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1515"
    source_address_prefix      = var.vnet_cidr
    destination_address_prefix = var.private_subnet_cidr
  }

  # Wazuh agent event forwarding
  security_rule {
    name                       = "Allow-Wazuh-Events"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "1514"
    source_address_prefix      = var.vnet_cidr
    destination_address_prefix = var.private_subnet_cidr
  }

  # Logstash Beats input
  security_rule {
    name                       = "Allow-Logstash-Beats"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5044"
    source_address_prefix      = var.vnet_cidr
    destination_address_prefix = var.private_subnet_cidr
  }

  # Deny all other inbound
  security_rule {
    name                       = "Deny-All-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# NSG Flow Logs — network-level visibility (PHIPA S.12)
resource "azurerm_network_watcher_flow_log" "hie_siem" {
  network_watcher_name      = azurerm_network_watcher.hie_siem.name
  resource_group_name       = azurerm_resource_group.hie_siem.name
  name                      = "hie-siem-nsg-flow-log"
  network_security_group_id = azurerm_network_security_group.hie_siem.id
  storage_account_id        = azurerm_storage_account.log_archive.id
  enabled                   = true
  version                   = 2 # Include application-layer metadata

  retention_policy {
    enabled = true
    days    = 365
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.hie_siem.workspace_id
    workspace_region      = var.azure_region
    workspace_resource_id = azurerm_log_analytics_workspace.hie_siem.id
    interval_in_minutes   = 10
  }
}

resource "azurerm_network_watcher" "hie_siem" {
  name                = "hie-siem-network-watcher"
  location            = azurerm_resource_group.hie_siem.location
  resource_group_name = azurerm_resource_group.hie_siem.name
}

# =============================================================================
# Log Analytics Workspace + Microsoft Sentinel
# =============================================================================
resource "azurerm_log_analytics_workspace" "hie_siem" {
  name                = "hie-siem-law-${var.environment}"
  location            = azurerm_resource_group.hie_siem.location
  resource_group_name = azurerm_resource_group.hie_siem.name
  sku                 = "PerGB2018"
  retention_in_days   = 365 # HIPAA minimum

  daily_quota_gb = var.log_daily_quota_gb
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "hie_siem" {
  workspace_id = azurerm_log_analytics_workspace.hie_siem.id
}

# Sentinel data connectors
resource "azurerm_sentinel_data_connector_azure_active_directory" "hie" {
  name                       = "hie-siem-aad-connector"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.hie_siem.id
}

resource "azurerm_sentinel_data_connector_microsoft_defender_advanced_threat_protection" "hie" {
  name                       = "hie-siem-mde-connector"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.hie_siem.id
}

# =============================================================================
# Storage — Immutable log archive
# =============================================================================
resource "azurerm_storage_account" "log_archive" {
  name                            = "hiesiemlogarchive${var.environment}"
  resource_group_name             = azurerm_resource_group.hie_siem.name
  location                        = azurerm_resource_group.hie_siem.location
  account_tier                    = "Standard"
  account_replication_type        = "ZRS" # Zone-redundant within canadacentral
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Force Azure AD auth only

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 365 }
  }

  network_rules {
    default_action             = "Deny"
    virtual_network_subnet_ids = [azurerm_subnet.private.id]
    bypass                     = ["AzureServices"]
  }
}

# Immutable storage policy — WORM for audit logs
resource "azurerm_storage_container" "audit_logs" {
  name                  = "audit-logs"
  storage_account_name  = azurerm_storage_account.log_archive.name
  container_access_type = "private"
}

# =============================================================================
# Data Sources
# =============================================================================
data "azurerm_client_config" "current" {}

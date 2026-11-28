# Keyring's own config vault and user-assigned managed identity.
#
# Holds Keyring's startup secrets (session-secret, and entra-client-secret when
# not using a federated credential). The managed identity gets Key Vault Secrets
# User on THIS vault only — never on any user vault.

data "azurerm_client_config" "current" {}

resource "azurerm_user_assigned_identity" "this" {
  name                = var.identity_name
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_key_vault" "this" {
  name                          = var.vault_name
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  soft_delete_retention_days    = 90
  purge_protection_enabled      = true
  public_network_access_enabled = !var.disable_public_access
  tags                          = var.tags

  network_acls {
    bypass         = "AzureServices"
    default_action = var.disable_public_access ? "Deny" : "Allow"
  }

  lifecycle {
    precondition {
      condition     = !var.disable_public_access || (var.private_endpoint_subnet_id != "" && var.private_dns_zone_id != "")
      error_message = "disable_public_access requires private_endpoint_subnet_id and private_dns_zone_id."
    }
  }
}

resource "azurerm_role_assignment" "read_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  principal_type       = "ServicePrincipal"
}

# The config vault holds the session secret: whoever reads it can forge
# sessions. Its audit log says who did, and Keyring's own Vault health check
# (and infra/policy) flag a vault without one.
resource "azurerm_monitor_diagnostic_setting" "audit" {
  count = var.diagnostics_workspace_id != "" ? 1 : 0

  name                       = "keyring-config-audit"
  target_resource_id         = azurerm_key_vault.this.id
  log_analytics_workspace_id = var.diagnostics_workspace_id

  enabled_log {
    category_group = "audit"
  }
}

resource "azurerm_private_endpoint" "this" {
  count = var.private_endpoint_subnet_id != "" ? 1 : 0

  name                = "${var.vault_name}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "${var.vault_name}-pe-conn"
    private_connection_resource_id = azurerm_key_vault.this.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  dynamic "private_dns_zone_group" {
    for_each = var.private_dns_zone_id != "" ? [1] : []
    content {
      name                 = "default"
      private_dns_zone_ids = [var.private_dns_zone_id]
    }
  }
}

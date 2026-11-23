# Email for Keyring's notifications through Azure Communication Services.
#
# Grants Keyring's managed identity the narrowest possible custom role (two
# actions on this one Communication Services resource only: Read and Write).
# No access keys or connection strings are ever created or output.

locals {
  azure_managed = var.notify_domain == "AzureManaged"
}

resource "azurerm_email_communication_service" "this" {
  name                = "${var.name}-email"
  resource_group_name = var.resource_group_name
  data_location       = var.data_location
  tags                = var.tags
}

resource "azurerm_email_communication_service_domain" "this" {
  name                             = local.azure_managed ? "AzureManagedDomain" : var.notify_domain
  email_service_id                 = azurerm_email_communication_service.this.id
  domain_management                = local.azure_managed ? "AzureManaged" : "CustomerManaged"
  user_engagement_tracking_enabled = false
  tags                             = var.tags
}

resource "azurerm_communication_service" "this" {
  name                = "${var.name}-acs"
  resource_group_name = var.resource_group_name
  data_location       = var.data_location
  tags                = var.tags
}

resource "azurerm_communication_service_email_domain_association" "this" {
  communication_service_id = azurerm_communication_service.this.id
  email_service_domain_id  = azurerm_email_communication_service_domain.this.id
}

resource "azurerm_role_definition" "email_sender" {
  name        = "Keyring email sender (${var.name})"
  scope       = var.resource_group_id
  description = "Send email from one Azure Communication Services resource. Read and Write on Communication Services only: no key, Email Service or data actions."

  permissions {
    actions = [
      "Microsoft.Communication/CommunicationServices/Read",
      "Microsoft.Communication/CommunicationServices/Write",
    ]
    not_actions      = []
    data_actions     = []
    not_data_actions = []
  }

  assignable_scopes = [var.resource_group_id]
}

resource "azurerm_role_assignment" "email_sender" {
  scope              = azurerm_communication_service.this.id
  role_definition_id = azurerm_role_definition.email_sender.role_definition_resource_id
  principal_id       = var.identity_principal_id
  principal_type     = "ServicePrincipal"
}

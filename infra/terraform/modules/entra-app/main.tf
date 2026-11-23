# Entra ID app registration for Keyring (delegated permissions ONLY).
#
# Creates a single-tenant app registration with:
# - Exposed API scope: api://<client_id>/access_as_user
# - Web redirect URIs: <base>/auth/callback and <base>/auth/signed-out
# - Delegated permissions only (Azure Key Vault, ARM, Log Analytics, Microsoft
#   Graph OIDC scopes, plus optional Graph sharing scopes). Never adds any
#   application permissions, so Keyring's managed identity can never act
#   without a signed-in user's OBO token.
# - Optional federated identity credential trusting Keyring's managed identity.

locals {
  # Verified Microsoft well-known resource application IDs and delegated scope IDs.
  key_vault_app_id           = "cfa8b339-82a2-471a-a3c9-0fc0be7a4093"
  key_vault_impersonation_id = "f53da476-18e3-4152-8e01-aec403e6edc0"

  arm_app_id           = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
  arm_impersonation_id = "41094075-9dad-400e-a0bd-54e686782033"

  log_analytics_app_id = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5"
  log_analytics_read   = "e8dac03d-d467-4a7e-9293-9cca7df08b31"

  ms_graph_app_id       = "00000003-0000-0000-c000-000000000000"
  graph_openid          = "37f7f235-527c-4136-accd-4a02d197296e"
  graph_profile         = "14dad69e-099b-42c9-810b-d002981feec1"
  graph_offline_access  = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
  graph_user_read_basic = "b340eb25-3456-403f-be2f-af7a0d370277"
  graph_group_members   = "bc024368-1153-4739-b217-4326f2e966d0"

  graph_scope_ids = concat(
    [local.graph_openid, local.graph_profile, local.graph_offline_access],
    var.enable_sharing ? [local.graph_user_read_basic, local.graph_group_members] : []
  )

  redirect_uris = flatten([
    for u in var.app_base_urls : [
      "${trimsuffix(u, "/")}/auth/callback",
      "${trimsuffix(u, "/")}/auth/signed-out",
    ]
  ])
}

resource "random_uuid" "access_as_user_scope" {}

resource "azuread_application" "this" {
  display_name     = var.display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = length(var.owners) > 0 ? var.owners : null

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      admin_consent_description  = "Allow Keyring to call Azure Key Vault, Resource Manager and Log Analytics on behalf of the signed-in user."
      admin_consent_display_name = "Use Keyring as you"
      enabled                    = true
      id                         = random_uuid.access_as_user_scope.result
      type                       = "Admin"
      user_consent_description   = "Allow Keyring to act as you in Azure Key Vault."
      user_consent_display_name  = "Use Keyring as you"
      value                      = "access_as_user"
    }
  }

  web {
    redirect_uris = local.redirect_uris
  }

  # Azure Key Vault: user_impersonation (delegated)
  required_resource_access {
    resource_app_id = local.key_vault_app_id
    resource_access {
      id   = local.key_vault_impersonation_id
      type = "Scope"
    }
  }

  # Azure Resource Manager: user_impersonation (delegated)
  required_resource_access {
    resource_app_id = local.arm_app_id
    resource_access {
      id   = local.arm_impersonation_id
      type = "Scope"
    }
  }

  # Log Analytics API: Data.Read (delegated)
  required_resource_access {
    resource_app_id = local.log_analytics_app_id
    resource_access {
      id   = local.log_analytics_read
      type = "Scope"
    }
  }

  # Microsoft Graph: OIDC scopes (plus optional sharing lookup scopes)
  required_resource_access {
    resource_app_id = local.ms_graph_app_id
    dynamic "resource_access" {
      for_each = local.graph_scope_ids
      content {
        id   = resource_access.value
        type = "Scope"
      }
    }
  }
}

resource "azuread_application_identifier_uri" "this" {
  application_id = azuread_application.this.id
  identifier_uri = "api://${azuread_application.this.client_id}"
}

resource "azuread_service_principal" "this" {
  client_id                    = azuread_application.this.client_id
  app_role_assignment_required = false
  owners                       = length(var.owners) > 0 ? var.owners : null
}

resource "azuread_application_federated_identity_credential" "managed_identity" {
  count = var.managed_identity_principal_id != "" ? 1 : 0

  application_id = azuread_application.this.id
  display_name   = "keyring-managed-identity"
  description    = "Trust Keyring's user-assigned managed identity as this app (no client secret)."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://login.microsoftonline.com/${lower(var.tenant_id)}/v2.0"
  subject        = var.managed_identity_principal_id
}

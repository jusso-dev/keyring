data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

locals {
  location         = var.location != "" ? var.location : data.azurerm_resource_group.this.location
  tenant_id        = var.tenant_id != "" ? var.tenant_id : data.azurerm_client_config.current.tenant_id
  use_audit_sink   = var.audit_workspace_id != ""
  use_notify       = var.notify_domain != ""
  public_inbound   = var.inbound_private_endpoint_subnet_id == ""
  notify_types_set = [for t in split(",", lower(var.notify_types)) : trimspace(t)]
  has_expiry       = contains(local.notify_types_set, "expiry")
  eg_subs          = var.eventgrid_subscriptions != "" ? var.eventgrid_subscriptions : data.azurerm_client_config.current.subscription_id

  session_secret_ref = "@Microsoft.KeyVault(VaultName=${module.config_vault.vault_name};SecretName=session-secret)"
  client_secret_ref  = "@Microsoft.KeyVault(VaultName=${module.config_vault.vault_name};SecretName=entra-client-secret)"

  app_settings = merge(
    {
      WEBSITES_PORT                       = "3000"
      WEBSITES_ENABLE_APP_SERVICE_STORAGE = "false"
      # Time to stop before the container is killed: Keyring needs up to 40
      # seconds to finish requests and send queued email and audit events.
      WEBSITES_CONTAINER_STOP_TIME_LIMIT = "60"
      ENTRA_TENANT_ID                    = local.tenant_id
      ENTRA_CLIENT_ID                    = var.client_id
      APP_BASE_URL                       = var.app_base_url
      SESSION_SECRET                     = local.session_secret_ref
      KEYRING_ALLOW_PURGE                = tostring(var.allow_purge)
      KEYRING_TRUSTED_PROXY_HOPS         = tostring(var.trusted_proxy_hops)
    },
    var.use_federated_credential || local.use_audit_sink || local.use_notify ? {
      KEYRING_MANAGED_IDENTITY_CLIENT_ID = module.config_vault.identity_client_id
    } : {},
    var.use_federated_credential ? {} : { ENTRA_CLIENT_SECRET = local.client_secret_ref },
    var.api_scope != "" ? { ENTRA_API_SCOPE = var.api_scope } : {},
    var.log_level != "" ? { KEYRING_LOG_LEVEL = var.log_level } : {},
    var.log_format != "" ? { KEYRING_LOG_FORMAT = var.log_format } : {},
    var.stale_after_days > 0 ? { KEYRING_STALE_AFTER_DAYS = tostring(var.stale_after_days) } : {},
    var.expiry_warn_days > 0 ? { KEYRING_EXPIRY_WARN_DAYS = tostring(var.expiry_warn_days) } : {},
    var.step_up_auth_context != "" ? { KEYRING_STEP_UP_AUTH_CONTEXT = var.step_up_auth_context } : {},
    var.step_up_max_age > 0 ? { KEYRING_STEP_UP_MAX_AGE = tostring(var.step_up_max_age) } : {},
    var.require_reason != "" ? { KEYRING_REQUIRE_REASON = var.require_reason } : {},
    var.reason_ticket_pattern != "" ? { KEYRING_REASON_TICKET_PATTERN = var.reason_ticket_pattern } : {},
    var.password_policy != "" ? { KEYRING_PASSWORD_POLICY = var.password_policy } : {},
    var.require_owner ? { KEYRING_REQUIRE_OWNER = "true" } : {},
    var.sharing ? { KEYRING_SHARING = "true" } : {},
    var.share_max_days > 0 ? { KEYRING_SHARE_MAX_DAYS = tostring(var.share_max_days) } : {},
    local.use_audit_sink ? {
      KEYRING_AUDIT_INGESTION_ENDPOINT = module.audit_sink[0].ingestion_endpoint
      KEYRING_AUDIT_DCR_ID             = module.audit_sink[0].rule_immutable_id
      KEYRING_AUDIT_STREAM             = module.audit_sink[0].stream_name
      KEYRING_AUDIT_REQUIRED           = tostring(var.audit_required)
      KEYRING_AUDIT_WORKSPACE_ID       = var.audit_workspace_id
    } : {},
    local.use_notify ? merge(
      {
        KEYRING_NOTIFY_ACS_ENDPOINT = module.notify[0].endpoint
        KEYRING_NOTIFY_SENDER       = module.notify[0].sender_address
      },
      var.notify_types != "" ? { KEYRING_NOTIFY_TYPES = var.notify_types } : {},
      var.notify_admins != "" ? { KEYRING_NOTIFY_ADMINS = var.notify_admins } : {},
      var.notify_allowed_domains != "" ? { KEYRING_NOTIFY_ALLOWED_DOMAINS = var.notify_allowed_domains } : {},
      local.has_expiry && local.eg_subs != "" ? { KEYRING_EVENTGRID_SUBSCRIPTIONS = local.eg_subs } : {},
      local.has_expiry && var.eventgrid_audience != "" ? { KEYRING_EVENTGRID_AUDIENCE = var.eventgrid_audience } : {},
    ) : {}
  )
}

module "config_vault" {
  source = "../../modules/config-vault"

  resource_group_name        = data.azurerm_resource_group.this.name
  location                   = local.location
  vault_name                 = var.config_vault_name
  identity_name              = "${var.name}-id"
  disable_public_access      = var.config_vault_private_endpoint_subnet_id != ""
  private_endpoint_subnet_id = var.config_vault_private_endpoint_subnet_id
  private_dns_zone_id        = var.vault_private_dns_zone_id
  tags                       = var.tags
}

module "audit_sink" {
  count  = local.use_audit_sink ? 1 : 0
  source = "../../modules/audit-sink"

  workspace_id                = var.audit_workspace_id
  workspace_resource_group_id = var.audit_workspace_resource_group_id != "" ? var.audit_workspace_resource_group_id : data.azurerm_resource_group.this.id
  location                    = var.audit_workspace_location != "" ? var.audit_workspace_location : local.location
  rule_name                   = "${var.name}-audit"
  identity_principal_id       = module.config_vault.identity_principal_id
  retention_in_days           = var.audit_retention_in_days
  tags                        = var.tags
}

module "notify" {
  count  = local.use_notify ? 1 : 0
  source = "../../modules/notify"

  resource_group_name   = data.azurerm_resource_group.this.name
  resource_group_id     = data.azurerm_resource_group.this.id
  name                  = var.name
  notify_domain         = var.notify_domain
  data_location         = var.notify_data_location
  identity_principal_id = module.config_vault.identity_principal_id
  tags                  = var.tags
}

resource "azurerm_service_plan" "this" {
  name                   = "${var.name}-plan"
  location               = local.location
  resource_group_name    = data.azurerm_resource_group.this.name
  os_type                = "Linux"
  sku_name               = var.sku_name
  worker_count           = var.replicas
  zone_balancing_enabled = var.zone_redundant
  tags                   = var.tags
}

resource "azurerm_linux_web_app" "this" {
  name                                           = var.name
  location                                       = local.location
  resource_group_name                            = data.azurerm_resource_group.this.name
  service_plan_id                                = azurerm_service_plan.this.id
  https_only                                     = true
  client_affinity_enabled                        = var.replicas > 1
  public_network_access_enabled                  = local.public_inbound
  ftp_publish_basic_authentication_enabled       = false
  webdeploy_publish_basic_authentication_enabled = false
  key_vault_reference_identity_id                = module.config_vault.identity_id
  virtual_network_subnet_id                      = var.vnet_integration_subnet_id != "" ? var.vnet_integration_subnet_id : null
  tags                                           = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [module.config_vault.identity_id]
  }

  site_config {
    always_on               = true
    ftps_state              = "Disabled"
    http2_enabled           = true
    minimum_tls_version     = "1.2"
    scm_minimum_tls_version = "1.2"
    health_check_path       = "/healthz"
    # Only the trusted ranges reach the app and its deployment (SCM) site.
    ip_restriction_default_action     = "Deny"
    scm_ip_restriction_default_action = "Deny"
    scm_use_main_ip_restriction       = true

    dynamic "ip_restriction" {
      for_each = var.allowed_ip_ranges
      content {
        name       = "trusted-${ip_restriction.key}"
        ip_address = ip_restriction.value
        action     = "Allow"
        priority   = 100 + ip_restriction.key
      }
    }
    vnet_route_all_enabled                        = var.vnet_integration_subnet_id != ""
    container_registry_use_managed_identity       = var.use_managed_identity_for_registry
    container_registry_managed_identity_client_id = var.use_managed_identity_for_registry ? module.config_vault.identity_client_id : null

    application_stack {
      docker_image_name = var.image
    }
  }

  app_settings = local.app_settings

  lifecycle {
    precondition {
      condition     = var.config_vault_private_endpoint_subnet_id == "" || (var.vnet_integration_subnet_id != "" && var.vault_private_dns_zone_id != "")
      error_message = "Private config vault requires vnet_integration_subnet_id and vault_private_dns_zone_id."
    }
    precondition {
      condition     = !local.public_inbound || length(var.allowed_ip_ranges) > 0
      error_message = "Keyring must not be reachable from the whole internet. Set inbound_private_endpoint_subnet_id for private access, or allowed_ip_ranges to the trusted ranges."
    }
    precondition {
      condition     = !local.has_expiry
      error_message = "expiry in notify_types needs Event Grid to reach Keyring from the internet, which this stack never allows. Send expiry email with infra/alerts and notifyVia = 'actionGroup' instead (docs/alerts.md)."
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "app_logs" {
  count = var.log_analytics_workspace_id != "" ? 1 : 0

  name                       = "keyring-logs"
  target_resource_id         = azurerm_linux_web_app.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "AppServiceConsoleLogs"
  }

  enabled_log {
    category = "AppServiceHTTPLogs"
  }
}

resource "azurerm_private_endpoint" "inbound" {
  count = local.public_inbound ? 0 : 1

  name                = "${var.name}-pe"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.this.name
  subnet_id           = var.inbound_private_endpoint_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "${var.name}-pe-conn"
    private_connection_resource_id = azurerm_linux_web_app.this.id
    is_manual_connection           = false
    subresource_names              = ["sites"]
  }

  dynamic "private_dns_zone_group" {
    for_each = var.app_private_dns_zone_id != "" ? [1] : []
    content {
      name                 = "default"
      private_dns_zone_ids = [var.app_private_dns_zone_id]
    }
  }
}

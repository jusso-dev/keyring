data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

locals {
  location         = var.location != "" ? var.location : data.azurerm_resource_group.this.location
  tenant_id        = var.tenant_id != "" ? var.tenant_id : data.azurerm_client_config.current.tenant_id
  use_audit_sink   = var.audit_workspace_id != ""
  use_notify       = var.notify_domain != ""
  notify_types_set = [for t in split(",", lower(var.notify_types)) : trimspace(t)]
  has_expiry       = contains(local.notify_types_set, "expiry")
  eg_subs          = var.eventgrid_subscriptions != "" ? var.eventgrid_subscriptions : data.azurerm_client_config.current.subscription_id

  base_env = merge(
    {
      ENTRA_TENANT_ID            = local.tenant_id
      ENTRA_CLIENT_ID            = var.client_id
      APP_BASE_URL               = var.app_base_url
      KEYRING_ALLOW_PURGE        = tostring(var.allow_purge)
      KEYRING_TRUSTED_PROXY_HOPS = tostring(var.trusted_proxy_hops)
    },
    var.use_federated_credential || local.use_audit_sink || local.use_notify ? {
      KEYRING_MANAGED_IDENTITY_CLIENT_ID = module.config_vault.identity_client_id
    } : {},
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

resource "azurerm_log_analytics_workspace" "env_logs" {
  count = var.config_only ? 0 : 1

  name                = "${var.name}-logs"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_container_app_environment" "this" {
  count = var.config_only ? 0 : 1

  name                           = "${var.name}-env"
  location                       = local.location
  resource_group_name            = data.azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.env_logs[0].id
  infrastructure_subnet_id       = var.infrastructure_subnet_id != "" ? var.infrastructure_subnet_id : null
  internal_load_balancer_enabled = var.ingress == "internal"
  zone_redundancy_enabled        = var.zone_redundant
  tags                           = var.tags

  lifecycle {
    precondition {
      condition     = var.ingress == "external" || var.infrastructure_subnet_id != ""
      error_message = "Internal ingress requires infrastructure_subnet_id."
    }
    precondition {
      condition     = !var.zone_redundant || var.infrastructure_subnet_id != ""
      error_message = "zone_redundant requires infrastructure_subnet_id."
    }
    precondition {
      condition     = var.ingress == "internal" || length(var.allowed_ip_ranges) > 0
      error_message = "Keyring must not be reachable from the whole internet. Use ingress = \"internal\", or set allowed_ip_ranges to the trusted ranges."
    }
    precondition {
      condition     = !local.has_expiry
      error_message = "expiry in notify_types needs Event Grid to reach Keyring from the internet, which this stack never allows. Send expiry email with infra/alerts and notifyVia = 'actionGroup' instead (docs/alerts.md)."
    }
  }
}

resource "azurerm_container_app" "this" {
  count = var.config_only ? 0 : 1

  name                         = var.name
  container_app_environment_id = azurerm_container_app_environment.this[0].id
  resource_group_name          = data.azurerm_resource_group.this.name
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [module.config_vault.identity_id]
  }

  dynamic "registry" {
    for_each = var.registry_server != "" ? [1] : []
    content {
      server   = var.registry_server
      identity = module.config_vault.identity_id
    }
  }

  secret {
    name                = "session-secret"
    key_vault_secret_id = "${module.config_vault.vault_uri}secrets/session-secret"
    identity            = module.config_vault.identity_id
  }

  dynamic "secret" {
    for_each = var.use_federated_credential ? [] : [1]
    content {
      name                = "entra-client-secret"
      key_vault_secret_id = "${module.config_vault.vault_uri}secrets/entra-client-secret"
      identity            = module.config_vault.identity_id
    }
  }

  ingress {
    external_enabled           = true
    target_port                = 3000
    transport                  = "http"
    allow_insecure_connections = false

    # Only the trusted ranges get in; with only Allow rules, Container Apps
    # refuses every other address.
    dynamic "ip_security_restriction" {
      for_each = var.allowed_ip_ranges
      content {
        name             = "trusted-${ip_security_restriction.key}"
        ip_address_range = ip_security_restriction.value
        action           = "Allow"
      }
    }

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.replicas
    max_replicas = var.replicas

    container {
      name   = "keyring"
      image  = var.image
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "SESSION_SECRET"
        secret_name = "session-secret"
      }

      dynamic "env" {
        for_each = var.use_federated_credential ? [] : [1]
        content {
          name        = "ENTRA_CLIENT_SECRET"
          secret_name = "entra-client-secret"
        }
      }

      dynamic "env" {
        for_each = local.base_env
        content {
          name  = env.key
          value = env.value
        }
      }

      liveness_probe {
        transport        = "HTTP"
        path             = "/healthz"
        port             = 3000
        interval_seconds = 30
      }

      readiness_probe {
        transport        = "HTTP"
        path             = "/healthz"
        port             = 3000
        interval_seconds = 10
      }
    }
  }
}

resource "azurerm_private_dns_zone" "internal_env" {
  count = !var.config_only && var.ingress == "internal" && var.private_dns_vnet_id != "" ? 1 : 0

  name                = azurerm_container_app_environment.this[0].default_domain
  resource_group_name = data.azurerm_resource_group.this.name
  tags                = var.tags
}

resource "azurerm_private_dns_a_record" "internal_env_wildcard" {
  count = !var.config_only && var.ingress == "internal" && var.private_dns_vnet_id != "" ? 1 : 0

  name                = "*"
  zone_name           = azurerm_private_dns_zone.internal_env[0].name
  resource_group_name = data.azurerm_resource_group.this.name
  ttl                 = 300
  records             = [azurerm_container_app_environment.this[0].static_ip_address]
}

resource "azurerm_private_dns_zone_virtual_network_link" "internal_env" {
  count = !var.config_only && var.ingress == "internal" && var.private_dns_vnet_id != "" ? 1 : 0

  name                  = "${var.name}-vnet-link"
  resource_group_name   = data.azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.internal_env[0].name
  virtual_network_id    = var.private_dns_vnet_id
  registration_enabled  = false
  tags                  = var.tags
}

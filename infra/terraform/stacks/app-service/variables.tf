variable "resource_group_name" {
  type        = string
  description = "Existing resource group where Keyring will be deployed."
}

variable "location" {
  type        = string
  default     = ""
  description = "Azure region. Leave empty to inherit the resource group's location."
}

variable "name" {
  type        = string
  description = "Short name prefix (3 to 18 characters), for example keyring-prod."

  validation {
    condition     = length(var.name) >= 3 && length(var.name) <= 18
    error_message = "name must be between 3 and 18 characters."
  }
}

variable "image" {
  type        = string
  description = "Container image pinned by digest, for example ghcr.io/jusso-dev/keyring@sha256:..."
}

variable "use_managed_identity_for_registry" {
  type        = bool
  default     = false
  description = "Pull the container image from a private ACR using Keyring's managed identity (requires AcrPull)."
}

variable "sku_name" {
  type        = string
  default     = "P0v3"
  description = "App Service plan SKU."
}

variable "replicas" {
  type        = number
  default     = 1
  description = "App Service plan worker count (1 to 10). ARR session affinity is enabled automatically when > 1."

  validation {
    condition     = var.replicas >= 1 && var.replicas <= 10
    error_message = "replicas must be between 1 and 10."
  }
}

variable "zone_redundant" {
  type        = bool
  default     = false
  description = "Spread the App Service plan across availability zones (requires Premium v2/v3 SKU)."
}

variable "tenant_id" {
  type        = string
  default     = ""
  description = "Entra directory (tenant) ID. Defaults to current azurerm tenant."
}

variable "client_id" {
  type        = string
  description = "Application (client) ID of the Entra app registration."
}

variable "app_base_url" {
  type        = string
  description = "Public URL people use, for example https://keyring.example.com."
}

variable "config_vault_name" {
  type        = string
  description = "Name of Keyring's config Key Vault (3 to 24 characters, globally unique)."
}

variable "vnet_integration_subnet_id" {
  type        = string
  default     = ""
  description = "Delegated subnet ID (Microsoft.Web/serverFarms) for outbound VNet integration."
}

variable "inbound_private_endpoint_subnet_id" {
  type        = string
  default     = ""
  description = "Subnet ID for an inbound private endpoint to App Service, so people reach Keyring over your VNet, VPN or ExpressRoute only. Disables public network access."
}

variable "allowed_ip_ranges" {
  type        = list(string)
  default     = []
  description = "Without inbound_private_endpoint_subnet_id: the trusted IP ranges (CIDR) that may reach Keyring's public address, such as your office or VPN egress. Everything else is refused. Keyring is never open to the whole internet, so one of the two is required."

  validation {
    # One IPv4 CIDR per entry, /16 or narrower: no commas, no IPv6, and no
    # set of ranges wide enough to add up to the whole internet.
    condition     = alltrue([for r in var.allowed_ip_ranges : can(cidrhost(r, 0)) && !strcontains(r, ",") && !strcontains(r, ":") && can(tonumber(element(split("/", r), 1)) >= 16) && try(tonumber(element(split("/", r), 1)) >= 16, false)])
    error_message = "allowed_ip_ranges must list trusted ranges only: each one IPv4 CIDR, /16 or narrower, no commas."
  }
}

variable "app_private_dns_zone_id" {
  type        = string
  default     = ""
  description = "Private DNS zone ID for privatelink.azurewebsites.net."
}

variable "config_vault_private_endpoint_subnet_id" {
  type        = string
  default     = ""
  description = "Subnet ID for a private endpoint to the config vault."
}

variable "vault_private_dns_zone_id" {
  type        = string
  default     = ""
  description = "Private DNS zone ID for privatelink.vaultcore.azure.net."
}

variable "use_federated_credential" {
  type        = bool
  default     = true
  description = "Sign in to Entra with Keyring's managed identity federated credential instead of a client secret."
}

variable "allow_purge" {
  type        = bool
  default     = false
  description = "Allow permanent deletes (purge) in Keyring."
}

variable "api_scope" {
  type        = string
  default     = ""
  description = "Custom ENTRA_API_SCOPE."
}

variable "log_level" {
  type        = string
  default     = ""
  description = "error, warn, info, debug or trace."
}

variable "log_format" {
  type        = string
  default     = "json"
  description = "text or json."
}

variable "trusted_proxy_hops" {
  type        = number
  default     = 1
  description = "Proxies adding to X-Forwarded-For (1 for App Service front end)."
}

variable "step_up_auth_context" {
  type        = string
  default     = ""
  description = "Conditional Access authentication context (c1 to c99)."
}

variable "step_up_max_age" {
  type        = number
  default     = 0
  description = "Minutes since sign-in allowed before sensitive actions (0 disables)."
}

variable "require_reason" {
  type        = string
  default     = ""
  description = "off, reveal or all."
}

variable "reason_ticket_pattern" {
  type        = string
  default     = ""
  description = "Regex a ticket reference must match."
}

variable "password_policy" {
  type        = string
  default     = ""
  description = "Password policy rule string."
}

variable "require_owner" {
  type        = bool
  default     = false
  description = "Require an owner tag on every item."
}

variable "sharing" {
  type        = bool
  default     = false
  description = "Enable time-limited single-secret sharing."
}

variable "share_max_days" {
  type        = number
  default     = 0
  description = "Maximum share duration in days (0 keeps default 30)."
}

variable "stale_after_days" {
  type        = number
  default     = 0
  description = "Days without a new value before items show the stale badge (0 keeps default 365)."
}

variable "expiry_warn_days" {
  type        = number
  default     = 0
  description = "Days before expiry when items count as expiring soon (0 keeps default 30)."
}

variable "log_analytics_workspace_id" {
  type        = string
  default     = ""
  description = "Log Analytics workspace ID for AppServiceConsoleLogs and AppServiceHTTPLogs."
}

variable "audit_workspace_id" {
  type        = string
  default     = ""
  description = "Log Analytics workspace ID for KeyringAudit_CL."
}

variable "audit_workspace_resource_group_id" {
  type        = string
  default     = ""
  description = "Resource group ID containing audit_workspace_id."
}

variable "audit_workspace_location" {
  type        = string
  default     = ""
  description = "Azure region of audit_workspace_id."
}

variable "audit_retention_in_days" {
  type        = number
  default     = 365
  description = "Days KeyringAudit_CL retains rows."
}

variable "audit_required" {
  type        = bool
  default     = false
  description = "Fail closed on reveals/private key downloads while the audit sink is degraded."
}

variable "notify_domain" {
  type        = string
  default     = ""
  description = "AzureManaged, a custom domain, or empty to disable ACS email."
}

variable "notify_data_location" {
  type        = string
  default     = "Australia"
  description = "ACS data residency location."
}

variable "notify_types" {
  type        = string
  default     = ""
  description = "Comma-separated notification types."
}

variable "notify_admins" {
  type        = string
  default     = ""
  description = "Comma-separated admin email addresses."
}

variable "notify_allowed_domains" {
  type        = string
  default     = ""
  description = "Comma-separated allowed recipient domains."
}

variable "eventgrid_subscriptions" {
  type        = string
  default     = ""
  description = "Comma-separated subscription IDs allowed to send Event Grid expiry events."
}

variable "eventgrid_audience" {
  type        = string
  default     = ""
  description = "Expected aud claim on Event Grid tokens."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources."
}

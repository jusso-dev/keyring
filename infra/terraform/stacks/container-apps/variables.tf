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

variable "registry_server" {
  type        = string
  default     = ""
  description = "Private Azure Container Registry login server (pulls via Keyring's managed identity). Leave empty for a public registry."
}

variable "config_only" {
  type        = bool
  default     = false
  description = "First-pass bootstrap: deploy only the config vault and managed identity so you can populate session-secret (and grant AcrPull) before creating the Container App."
}

variable "tenant_id" {
  type        = string
  default     = ""
  description = "Entra directory (tenant) ID. Defaults to the current azurerm client tenant."
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

variable "ingress" {
  type        = string
  default     = "external"
  description = "external (public address) or internal (VNet-only private address)."

  validation {
    condition     = contains(["external", "internal"], var.ingress)
    error_message = "ingress must be 'external' or 'internal'."
  }
}

variable "allowed_ip_ranges" {
  type        = list(string)
  default     = []
  description = "With external ingress: the trusted IP ranges (CIDR) that may reach Keyring, such as your office or VPN egress. Everything else is refused. Keyring is never open to the whole internet, so external ingress needs at least one."

  validation {
    condition     = alltrue([for r in var.allowed_ip_ranges : r != "*" && !endswith(trimspace(r), "/0") && lower(trimspace(r)) != "internet"])
    error_message = "allowed_ip_ranges must list trusted ranges only: no /0, * or Internet."
  }
}

variable "infrastructure_subnet_id" {
  type        = string
  default     = ""
  description = "Delegated subnet ID for the Container Apps environment (required for internal ingress, zone redundancy and reaching private vaults)."
}

variable "zone_redundant" {
  type        = bool
  default     = false
  description = "Spread the Container Apps environment across availability zones (requires infrastructure_subnet_id)."
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

variable "private_dns_vnet_id" {
  type        = string
  default     = ""
  description = "VNet ID to link an auto-created private DNS zone for an internal Container Apps environment."
}

variable "replicas" {
  type        = number
  default     = 1
  description = "Replica count (1 to 10). Sticky sessions are enabled automatically when > 1."

  validation {
    condition     = var.replicas >= 1 && var.replicas <= 10
    error_message = "replicas must be between 1 and 10."
  }
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
  description = "Custom ENTRA_API_SCOPE. Leave empty for api://<client_id>/access_as_user."
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
  description = "Proxies adding to X-Forwarded-For (1 for Container Apps ingress)."
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
  description = "Regex a ticket reference must match as a whole."
}

variable "password_policy" {
  type        = string
  default     = ""
  description = "Password policy rule string, for example min=14,upper,lower,digit,symbol,max-repeat=3,common."
}

variable "require_owner" {
  type        = bool
  default     = false
  description = "Refuse to save items without an owner tag."
}

variable "sharing" {
  type        = bool
  default     = false
  description = "Enable time-limited single-secret sharing (KEYRING_SHARING)."
}

variable "share_max_days" {
  type        = number
  default     = 0
  description = "Maximum share duration in days (0 keeps default 30)."
}

variable "stale_after_days" {
  type        = number
  default     = 0
  description = "Days without a value change before items show the stale badge (0 keeps default 365)."
}

variable "expiry_warn_days" {
  type        = number
  default     = 0
  description = "Days before expiry when items count as expiring soon (0 keeps default 30)."
}

variable "audit_workspace_id" {
  type        = string
  default     = ""
  description = "Log Analytics workspace resource ID for KeyringAudit_CL."
}

variable "audit_workspace_resource_group_id" {
  type        = string
  default     = ""
  description = "Resource group ID containing audit_workspace_id (required when audit_workspace_id is set)."
}

variable "audit_workspace_location" {
  type        = string
  default     = ""
  description = "Azure region of audit_workspace_id (defaults to deployment location)."
}

variable "audit_retention_in_days" {
  type        = number
  default     = 365
  description = "Days KeyringAudit_CL retains rows (30 to 730)."
}

variable "audit_required" {
  type        = bool
  default     = false
  description = "Fail closed on reveals/private key downloads while the audit sink is degraded."
}

variable "notify_domain" {
  type        = string
  default     = ""
  description = "AzureManaged, a custom email domain, or empty to disable ACS email."
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
  description = "Comma-separated subscription IDs allowed to send Event Grid expiry events. Defaults to current subscription."
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

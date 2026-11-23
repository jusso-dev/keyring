variable "resource_group_name" {
  type        = string
  description = "Existing resource group where the Keyring VM will be deployed."
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

variable "subnet_id" {
  type        = string
  description = "Subnet ID for the VM NIC (private IP only, no public IP)."
}

variable "allowed_proxy_source_prefix" {
  type        = string
  default     = "VirtualNetwork"
  description = "CIDR prefix allowed to reach port 3000 (for example Application Gateway / reverse proxy subnet)."
}

variable "gallery_image_id" {
  type        = string
  default     = ""
  description = "Optional Azure Compute Gallery image version ID built with infra/vm/packer/keyring.pkr.hcl."
}

variable "vm_size" {
  type        = string
  default     = "Standard_DC2as_v5"
  description = "VM SKU (Standard_DC2as_v5 supports both TrustedLaunch and ConfidentialVM)."
}

variable "security_type" {
  type        = string
  default     = "TrustedLaunch"
  description = "TrustedLaunch or ConfidentialVM (AMD SEV-SNP encrypted memory)."

  validation {
    condition     = contains(["TrustedLaunch", "ConfidentialVM"], var.security_type)
    error_message = "security_type must be 'TrustedLaunch' or 'ConfidentialVM'."
  }
}

variable "confidential_disk_encryption_type" {
  type        = string
  default     = "VMGuestStateOnly"
  description = "Confidential VM OS disk encryption type (VMGuestStateOnly or DiskWithVMGuestState)."
}

variable "availability_zone" {
  type        = string
  default     = ""
  description = "Optional availability zone (1, 2, or 3)."
}

variable "admin_username" {
  type        = string
  default     = "azureuser"
  description = "SSH admin username."
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key for emergency break-glass access. Password authentication is disabled."
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
  description = "Sign in to Entra with the VM's managed identity federated credential."
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
  description = "Number of proxies in front of Keyring adding to X-Forwarded-For."
}

variable "step_up_auth_context" {
  type        = string
  default     = ""
  description = "Conditional Access authentication context (c1 to c99)."
}

variable "step_up_max_age" {
  type        = number
  default     = 0
  description = "Minutes since sign-in allowed before sensitive actions."
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
  description = "Maximum share duration in days."
}

variable "stale_after_days" {
  type        = number
  default     = 0
  description = "Days without a new value before items show the stale badge."
}

variable "expiry_warn_days" {
  type        = number
  default     = 0
  description = "Days before expiry when items count as expiring soon."
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

variable "resource_group_name" {
  type        = string
  description = "Resource group where Keyring's config vault and managed identity are created."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "vault_name" {
  type        = string
  description = "Name of Keyring's config Key Vault (3 to 24 characters, globally unique)."

  validation {
    condition     = length(var.vault_name) >= 3 && length(var.vault_name) <= 24
    error_message = "vault_name must be between 3 and 24 characters."
  }
}

variable "identity_name" {
  type        = string
  description = "Name of the user-assigned managed identity Keyring runs as."
}

variable "disable_public_access" {
  type        = bool
  default     = false
  description = "Turn off public network access to the config vault. Requires private_endpoint_subnet_id and private_dns_zone_id."
}

variable "private_endpoint_subnet_id" {
  type        = string
  default     = ""
  description = "Subnet ID for a private endpoint to the config vault. Leave empty for none."
}

variable "private_dns_zone_id" {
  type        = string
  default     = ""
  description = "Resource ID of the privatelink.vaultcore.azure.net private DNS zone."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to every resource."
}

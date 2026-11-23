variable "display_name" {
  type        = string
  default     = "Keyring"
  description = "Display name of the Entra ID app registration."
}

variable "tenant_id" {
  type        = string
  description = "Directory (tenant) ID where Keyring runs (used as the federated credential issuer)."
}

variable "app_base_urls" {
  type        = list(string)
  description = "Base URLs for Keyring (for example [\"https://keyring.example.com\"]). Registers /auth/callback and /auth/signed-out for each."

  validation {
    condition     = length(var.app_base_urls) > 0
    error_message = "At least one app_base_url is required."
  }
}

variable "enable_sharing" {
  type        = bool
  default     = false
  description = "Add delegated Microsoft Graph User.ReadBasic.All and GroupMember.Read.All permissions for KEYRING_SHARING=true. Leave false if sharing is off."
}

variable "managed_identity_principal_id" {
  type        = string
  default     = ""
  description = "Principal (object) ID of Keyring's user-assigned managed identity to trust via a federated credential (eliminates client secrets). Leave empty to skip."
}

variable "owners" {
  type        = list(string)
  default     = []
  description = "Optional list of Entra object IDs to assign as application owners."
}

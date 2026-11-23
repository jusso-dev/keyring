variable "resource_group_name" {
  type        = string
  description = "Resource group where Keyring's ACS resources live."
}

variable "resource_group_id" {
  type        = string
  description = "ARM resource ID of the resource group (narrowest assignable scope for the two-action custom role)."
}

variable "name" {
  type        = string
  description = "Short name prefix, for example keyring-prod."
}

variable "notify_domain" {
  type        = string
  description = "AzureManaged for an Azure-managed domain, or your own domain name (for example mail.example.com)."

  validation {
    condition     = var.notify_domain == "AzureManaged" || (length(var.notify_domain) >= 3 && can(regex("^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.notify_domain)))
    error_message = "notify_domain must be AzureManaged or a plain domain name such as mail.example.com."
  }
}

variable "data_location" {
  type        = string
  default     = "Australia"
  description = "Where ACS keeps its data at rest (for example Australia, Europe or United States)."
}

variable "identity_principal_id" {
  type        = string
  description = "Principal (object) ID of Keyring's user-assigned managed identity."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to the ACS resources."
}

variable "workspace_id" {
  type        = string
  description = "ARM resource ID of the Log Analytics workspace where KeyringAudit_CL is created."
}

variable "workspace_resource_group_id" {
  type        = string
  description = "ARM resource ID of the resource group containing the Log Analytics workspace."
}

variable "location" {
  type        = string
  description = "Azure region of the Log Analytics workspace."
}

variable "rule_name" {
  type        = string
  description = "Name of the Direct Data Collection Rule."
}

variable "identity_principal_id" {
  type        = string
  description = "Principal (object) ID of Keyring's user-assigned managed identity."
}

variable "retention_in_days" {
  type        = number
  default     = 365
  description = "Days KeyringAudit_CL retains rows (30 to 730)."

  validation {
    condition     = var.retention_in_days >= 30 && var.retention_in_days <= 730
    error_message = "retention_in_days must be between 30 and 730."
  }
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to the Data Collection Rule."
}

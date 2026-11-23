output "vault_id" {
  value       = azurerm_key_vault.this.id
  description = "Resource ID of the config Key Vault."
}

output "vault_name" {
  value       = azurerm_key_vault.this.name
  description = "Name of the config Key Vault."
}

output "vault_uri" {
  value       = azurerm_key_vault.this.vault_uri
  description = "URI of the config Key Vault."
}

output "identity_id" {
  value       = azurerm_user_assigned_identity.this.id
  description = "Resource ID of Keyring's user-assigned managed identity."
}

output "identity_client_id" {
  value       = azurerm_user_assigned_identity.this.client_id
  description = "Client ID of Keyring's user-assigned managed identity."
}

output "identity_principal_id" {
  value       = azurerm_user_assigned_identity.this.principal_id
  description = "Principal (object) ID of Keyring's user-assigned managed identity."
}

output "app_name" {
  value       = azurerm_linux_web_app.this.name
  description = "App Service web app name."
}

output "default_hostname" {
  value       = azurerm_linux_web_app.this.default_hostname
  description = "Default App Service hostname."
}

output "config_vault_name" {
  value       = module.config_vault.vault_name
  description = "Keyring config Key Vault name."
}

output "identity_client_id" {
  value       = module.config_vault.identity_client_id
  description = "Keyring managed identity client ID."
}

output "identity_principal_id" {
  value       = module.config_vault.identity_principal_id
  description = "Keyring managed identity principal ID."
}

output "audit_rule_id" {
  value       = local.use_audit_sink ? module.audit_sink[0].rule_immutable_id : ""
  description = "Audit DCR immutable ID when audit sink is enabled."
}

output "notify_endpoint" {
  value       = local.use_notify ? module.notify[0].endpoint : ""
  description = "ACS endpoint when notifications are enabled."
}

output "app_name" {
  value       = var.config_only ? "" : azurerm_container_app.this[0].name
  description = "Container App name."
}

output "fqdn" {
  value       = var.config_only ? "" : azurerm_container_app.this[0].ingress[0].fqdn
  description = "Container App FQDN."
}

output "static_ip" {
  value       = var.config_only ? "" : azurerm_container_app_environment.this[0].static_ip_address
  description = "Container Apps environment static IP address."
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
  description = "Keyring managed identity principal ID (use as subject for Entra federated credential)."
}

output "audit_rule_id" {
  value       = local.use_audit_sink ? module.audit_sink[0].rule_immutable_id : ""
  description = "Audit DCR immutable ID when audit sink is enabled."
}

output "notify_endpoint" {
  value       = local.use_notify ? module.notify[0].endpoint : ""
  description = "ACS endpoint when notifications are enabled."
}

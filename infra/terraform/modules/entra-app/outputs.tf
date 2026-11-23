output "application_id" {
  value       = azuread_application.this.id
  description = "Microsoft Graph resource ID of the Entra application."
}

output "client_id" {
  value       = azuread_application.this.client_id
  description = "Application (client) ID for ENTRA_CLIENT_ID."
}

output "api_scope" {
  value       = "api://${azuread_application.this.client_id}/access_as_user"
  description = "Default ENTRA_API_SCOPE value."
}

output "service_principal_object_id" {
  value       = azuread_service_principal.this.object_id
  description = "Object ID of the Enterprise Application (service principal)."
}

output "admin_consent_url" {
  value       = "https://login.microsoftonline.com/${lower(var.tenant_id)}/adminconsent?client_id=${azuread_application.this.client_id}"
  description = "Open this URL as a tenant admin to grant delegated API consent."
}

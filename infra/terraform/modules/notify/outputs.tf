output "endpoint" {
  value       = "https://${azurerm_communication_service.this.hostname}"
  description = "Value for KEYRING_NOTIFY_ACS_ENDPOINT."
}

output "sender_address" {
  value       = "DoNotReply@${azurerm_email_communication_service_domain.this.mail_from_sender_domain}"
  description = "Value for KEYRING_NOTIFY_SENDER."
}

output "domain_name" {
  value       = azurerm_email_communication_service_domain.this.name
  description = "Configured ACS email domain name."
}

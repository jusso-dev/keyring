output "ingestion_endpoint" {
  value       = azapi_resource.dcr.output.properties.endpoints.logsIngestion
  description = "Value for KEYRING_AUDIT_INGESTION_ENDPOINT."
}

output "rule_immutable_id" {
  value       = azapi_resource.dcr.output.properties.immutableId
  description = "Value for KEYRING_AUDIT_DCR_ID."
}

output "stream_name" {
  value       = local.stream_name
  description = "Value for KEYRING_AUDIT_STREAM."
}

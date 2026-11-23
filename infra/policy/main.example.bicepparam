// Example parameters for the Keyring Key Vault Guardrails Azure Policy
// Initiative. Copy to main.bicepparam and deploy at subscription scope:
//   az deployment sub create -l australiaeast \
//     -f infra/policy/keyvault-guardrails.bicep \
//     -p infra/policy/main.bicepparam
using './keyvault-guardrails.bicep'

param initiativeName = 'keyring-keyvault-guardrails'
param enforcementEffect = 'Audit' // Switch to 'Deny' once Vault Health is green
param auditIfNotExistsEffect = 'AuditIfNotExists'
param createAssignment = true

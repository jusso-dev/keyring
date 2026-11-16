// Example parameters. Copy next to access.bicep
// (infra/alerts/access.bicepparam), fill in, and keep out of source control
// (.gitignore skips *.bicepparam except the examples).
using './access.bicep'

param vaultName = 'kv-app-prod'
param workspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/law-prod'

// AzureDiagnostics or AZKVAuditLogs: whichever the vault's diagnostic setting
// writes to (see docs/alerts.md).
param table = 'AzureDiagnostics'

param watchedSecretNames = [
  'db-password'
]
param alertOnPurge = true
param refusedThreshold = 10

param emails = [
  'platform-team@example.com'
]

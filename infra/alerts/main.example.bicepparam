// Example parameters. Copy next to main.bicep (infra/alerts/main.bicepparam),
// fill in, and keep out of source control (.gitignore skips *.bicepparam
// except the examples).
using './main.bicep'

param vaultName = 'kv-app-prod'
param emails = [
  'platform-team@example.com'
]

// Set if the vault already has an Event Grid system topic (see docs/alerts.md).
param existingSystemTopicName = ''

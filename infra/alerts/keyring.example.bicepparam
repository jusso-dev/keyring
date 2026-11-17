// Example parameters for sending a vault's expiry events to Keyring's
// webhook, which emails through Azure Communication Services. Copy next to
// main.bicep (infra/alerts/keyring.bicepparam), fill in, and keep out of
// source control. Do the one-off Entra steps in docs/alerts.md first.
using './main.bicep'

param vaultName = 'kv-app-prod'
param notifyVia = 'keyring'
param keyringBaseUrl = 'https://keyring.example.com'
// Keyring's app ID URI: api://<ENTRA_CLIENT_ID>, or KEYRING_EVENTGRID_AUDIENCE.
param entraAudience = 'api://00000000-0000-0000-0000-000000000000'
// Used by Keyring only with KEYRING_NOTIFY_ALLOWED_DOMAINS set. Empty sends
// to KEYRING_NOTIFY_ADMINS.
param keyringRecipients = 'platform-team@example.com'
// Optional: a blob container for events Event Grid gives up on.
param deadLetterContainerId = ''

// Set if the vault already has an Event Grid system topic (see docs/alerts.md).
param existingSystemTopicName = ''

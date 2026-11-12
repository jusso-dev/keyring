// Example parameters. Copy next to main.bicep, fill in, and keep out of
// source control (.gitignore skips *.bicepparam except the examples).
// Contains no secrets: those go straight into the config vault after
// deployment.
using './main.bicep'

param name = 'keyring-prod'
param image = 'ghcr.io/your-org/keyring@sha256:0000000000000000000000000000000000000000000000000000000000000000'
param clientId = '00000000-0000-0000-0000-000000000000'
param appBaseUrl = 'https://keyring.example.com'
param configVaultName = 'kv-keyring-config-01'

// Optional. Leave empty for the defaults.
param apiScope = '' // only if your app registration's scope isn't api://<clientId>/access_as_user
param logLevel = '' // error, warn, info (default), debug or trace
param logAnalyticsWorkspaceId = '' // keeps Keyring's action lines; see docs/deploy.md, "Logs"
param useFederatedCredential = false // true: sign in to Entra with the app's managed identity, no client secret; see the README, step 2 option B

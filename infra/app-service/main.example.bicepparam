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
param logFormat = '' // text (default) or json; see docs/deploy.md, "Logs"
param trustedProxyHops = 1 // proxies in front that add to X-Forwarded-For: 1 behind this template's front end
param stepUpAuthContext = '' // c1 to c99: ask for this Conditional Access authentication context before a reveal; see docs/deploy.md, "Step-up before sensitive actions"
param stepUpMaxAge = 0 // minutes since sign-in allowed before a reveal; 0 is off
param logAnalyticsWorkspaceId = '' // keeps Keyring's audit events; see docs/deploy.md, "Logs"
param useFederatedCredential = false // true: sign in to Entra with the app's managed identity, no client secret; see the README, step 2 option B

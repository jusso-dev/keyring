// Example parameters. Copy, fill in, and keep out of source control if it
// holds anything specific to your organisation. Contains no secrets: those
// go straight into the config vault after deployment.
using './main.bicep'

param name = 'keyring-prod'
param image = 'ghcr.io/your-org/keyring@sha256:0000000000000000000000000000000000000000000000000000000000000000'
param clientId = '00000000-0000-0000-0000-000000000000'
param appBaseUrl = 'https://keyring.example.com'
param configVaultName = 'kv-keyring-config-01'

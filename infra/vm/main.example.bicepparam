// Example parameters for deploying Keyring on an Azure VM (Trusted Launch or
// Confidential VM). Copy to main.bicepparam, fill in, and keep out of git.
using './main.bicep'

param name = 'keyring-prod'
param clientId = '00000000-0000-0000-0000-000000000000'
param appBaseUrl = 'https://keyring.example.com'
param configVaultName = 'kv-keyring-config-01'
param subnetId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/snet-keyring'
param allowedProxySourcePrefix = '10.0.1.0/24'
param sshPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyReplaceBeforeDeploy admin@example.com'

// Optional: point at a Compute Gallery image built with infra/vm/packer/keyring.pkr.hcl
param galleryImageId = ''
param securityType = 'TrustedLaunch' // or 'ConfidentialVM' (AMD SEV-SNP encrypted memory)
param vmSize = 'Standard_DC2as_v5'
param useFederatedCredential = true
param trustedProxyHops = 1
param logFormat = 'json'
param staleAfterDays = 0
param expiryWarnDays = 0
param auditWorkspaceId = ''
param auditRetentionInDays = 365
param auditRequired = false
param notifyDomain = ''
param notifyTypes = ''
param notifyAdmins = ''
param notifyAllowedDomains = ''

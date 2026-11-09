// Keyring's own config vault and identity.
//
// Holds two secrets Keyring needs to start: the Entra client secret and the
// session secret. The app reads them through Key Vault references, using a
// user-assigned managed identity with Key Vault Secrets User on THIS vault
// only.
//
// That identity never gets access to anyone else's vaults. Every call
// Keyring makes to user vaults uses the signed-in person's own token.
//
// The secret values are not set here. Set them after deployment with
// `az keyvault secret set` (see docs/deploy.md), so they never appear in a
// template, parameter file or deployment history.

@description('Azure region.')
param location string

@description('Name of the config vault. 3 to 24 characters, globally unique.')
@minLength(3)
@maxLength(24)
param vaultName string

@description('Name of the managed identity Keyring runs as.')
param identityName string

@description('Turn off public network access to the config vault. Needs a private endpoint (privateEndpointSubnetId) so the app can still reach it.')
param disablePublicAccess bool = false

@description('Subnet for a private endpoint to the config vault. Leave empty for none.')
param privateEndpointSubnetId string = ''

@description('Resource ID of the privatelink.vaultcore.azure.net private DNS zone. Needed with a private endpoint.')
param privateDnsZoneId string = ''

param tags object = {}

var secretsUserRole = '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
  tags: tags
}

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: vaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: disablePublicAccess ? 'Disabled' : 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: disablePublicAccess ? 'Deny' : 'Allow'
    }
  }
}

resource readSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, identity.id, secretsUserRole)
  scope: vault
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', secretsUserRole)
  }
}

module endpoint 'private-endpoint.bicep' = if (!empty(privateEndpointSubnetId)) {
  name: '${vaultName}-pe'
  params: {
    location: location
    name: '${vaultName}-pe'
    targetId: vault.id
    groupId: 'vault'
    subnetId: privateEndpointSubnetId
    privateDnsZoneId: privateDnsZoneId
    tags: tags
  }
}

output vaultName string = vault.name
output vaultUri string = vault.properties.vaultUri
output identityId string = identity.id
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId

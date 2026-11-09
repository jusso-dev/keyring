// Keyring on Azure App Service (Linux, container).
//
// Creates: an App Service plan, the web app running the Keyring image, and
// Keyring's own config vault and managed identity (modules/config-vault.bicep).
// Optional: outbound VNet integration (to reach private vaults) and an
// inbound private endpoint.
//
// The managed identity can only read Keyring's two config secrets. It has
// no access to user vaults. See docs/deploy.md.
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Azure region. Defaults to the resource group\'s.')
param location string = resourceGroup().location

@description('Short name used in resource names, for example keyring-prod.')
@minLength(3)
@maxLength(18)
param name string

@description('Container image, pinned by digest, for example ghcr.io/your-org/keyring@sha256:...')
param image string

@description('Directory (tenant) ID of the Entra app registration.')
param tenantId string = subscription().tenantId

@description('Application (client) ID of the Entra app registration.')
param clientId string

@description('Public URL people use, for example https://keyring.example.com. Must match the redirect URI in Entra.')
param appBaseUrl string

@description('Config vault name, 3 to 24 characters, globally unique.')
@minLength(3)
@maxLength(24)
param configVaultName string

@description('App Service plan size. B1 is enough for a small team; P0v3 or above for VNet integration and private endpoints.')
param skuName string = 'P0v3'

@description('Allow permanent deletes (purge) in Keyring.')
param allowPurge bool = false

@description('Subnet for outbound VNet integration, so Keyring can reach private vaults. Must be delegated to Microsoft.Web/serverFarms. Leave empty for none.')
param vnetIntegrationSubnetId string = ''

@description('Subnet for an inbound private endpoint to the app. Leave empty for public access.')
param inboundPrivateEndpointSubnetId string = ''

@description('Private DNS zone ID for privatelink.azurewebsites.net, used with the inbound private endpoint.')
param appPrivateDnsZoneId string = ''

@description('Subnet for a private endpoint to the config vault. Leave empty to use its public endpoint.')
param configVaultPrivateEndpointSubnetId string = ''

@description('Private DNS zone ID for privatelink.vaultcore.azure.net, used with the config vault private endpoint.')
param vaultPrivateDnsZoneId string = ''

param tags object = {}

var publicInbound = empty(inboundPrivateEndpointSubnetId)
var identityName = '${name}-id'
// Known before deployment, as the site's identity block needs.
var identityId = resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', identityName)

module config '../modules/config-vault.bicep' = {
  name: '${name}-config'
  params: {
    location: location
    vaultName: configVaultName
    identityName: identityName
    disablePublicAccess: !empty(configVaultPrivateEndpointSubnetId)
    privateEndpointSubnetId: configVaultPrivateEndpointSubnetId
    privateDnsZoneId: vaultPrivateDnsZoneId
    tags: tags
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${name}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: skuName
  }
  properties: {
    reserved: true
  }
}

// Key Vault references: App Service resolves these with the identity, so
// the values never appear in settings or templates.
var clientSecretRef = '@Microsoft.KeyVault(VaultName=${config.outputs.vaultName};SecretName=entra-client-secret)'
var sessionSecretRef = '@Microsoft.KeyVault(VaultName=${config.outputs.vaultName};SecretName=session-secret)'

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: name
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientCertEnabled: false
    publicNetworkAccess: publicInbound ? 'Enabled' : 'Disabled'
    keyVaultReferenceIdentity: identityId
    virtualNetworkSubnetId: empty(vnetIntegrationSubnetId) ? null : vnetIntegrationSubnetId
    siteConfig: {
      linuxFxVersion: 'DOCKER|${image}'
      alwaysOn: true
      ftpsState: 'Disabled'
      http20Enabled: true
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      healthCheckPath: '/healthz'
      vnetRouteAllEnabled: !empty(vnetIntegrationSubnetId)
      appSettings: [
        { name: 'WEBSITES_PORT', value: '3000' }
        { name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'false' }
        { name: 'ENTRA_TENANT_ID', value: tenantId }
        { name: 'ENTRA_CLIENT_ID', value: clientId }
        { name: 'APP_BASE_URL', value: appBaseUrl }
        { name: 'ENTRA_CLIENT_SECRET', value: clientSecretRef }
        { name: 'SESSION_SECRET', value: sessionSecretRef }
        { name: 'KEYRING_ALLOW_PURGE', value: string(allowPurge) }
      ]
    }
  }
}

// Turn off basic auth for deployments (FTP and the SCM site).
resource ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'scm'
  properties: {
    allow: false
  }
}

module inbound '../modules/private-endpoint.bicep' = if (!publicInbound) {
  name: '${name}-inbound-pe'
  params: {
    location: location
    name: '${name}-pe'
    targetId: site.id
    groupId: 'sites'
    subnetId: inboundPrivateEndpointSubnetId
    privateDnsZoneId: appPrivateDnsZoneId
    tags: tags
  }
}

output appName string = site.name
output defaultHostName string = site.properties.defaultHostName
output configVaultName string = config.outputs.vaultName
output identityPrincipalId string = config.outputs.identityPrincipalId

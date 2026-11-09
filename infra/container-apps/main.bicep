// Keyring on Azure Container Apps.
//
// Creates: a Log Analytics workspace for the environment's logs, a Container
// Apps environment (optionally in your VNet), the Keyring app, and Keyring's
// own config vault and managed identity (modules/config-vault.bicep).
//
// Ingress can be external (public) or internal (only inside the VNet).
// Secrets come from Key Vault references, read with the managed identity,
// which has no access to user vaults. See docs/deploy.md.
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

@description('external: reachable from the internet. internal: only from inside the VNet (needs infrastructureSubnetId).')
@allowed([
  'external'
  'internal'
])
param ingress string = 'external'

@description('Subnet for the environment (at least /27, delegated to Microsoft.App/environments). Needed for internal ingress and to reach private vaults. Leave empty for a Microsoft-managed network.')
param infrastructureSubnetId string = ''

@description('Subnet for a private endpoint to the config vault. Leave empty to use its public endpoint.')
param configVaultPrivateEndpointSubnetId string = ''

@description('Private DNS zone ID for privatelink.vaultcore.azure.net, used with the config vault private endpoint.')
param vaultPrivateDnsZoneId string = ''

@description('Allow permanent deletes (purge) in Keyring.')
param allowPurge bool = false

@description('Replicas. Sessions live in memory, so keep this at 1 unless you add session affinity (enabled below for more than 1).')
@minValue(1)
@maxValue(10)
param replicas int = 1

param tags object = {}

var identityName = '${name}-id'
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

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${name}-logs'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
    vnetConfiguration: empty(infrastructureSubnetId)
      ? null
      : {
          infrastructureSubnetId: infrastructureSubnetId
          internal: ingress == 'internal'
        }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    environmentId: env.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: ingress == 'external'
        targetPort: 3000
        transport: 'http'
        allowInsecure: false
        stickySessions: {
          affinity: replicas > 1 ? 'sticky' : 'none'
        }
      }
      // Key Vault references, resolved with the identity.
      secrets: [
        {
          name: 'entra-client-secret'
          keyVaultUrl: '${config.outputs.vaultUri}secrets/entra-client-secret'
          identity: identityId
        }
        {
          name: 'session-secret'
          keyVaultUrl: '${config.outputs.vaultUri}secrets/session-secret'
          identity: identityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'keyring'
          image: image
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            { name: 'ENTRA_TENANT_ID', value: tenantId }
            { name: 'ENTRA_CLIENT_ID', value: clientId }
            { name: 'APP_BASE_URL', value: appBaseUrl }
            { name: 'ENTRA_CLIENT_SECRET', secretRef: 'entra-client-secret' }
            { name: 'SESSION_SECRET', secretRef: 'session-secret' }
            { name: 'KEYRING_ALLOW_PURGE', value: string(allowPurge) }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 3000
              }
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/healthz'
                port: 3000
              }
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: replicas
        maxReplicas: replicas
      }
    }
  }
}

output appName string = app.name
output fqdn string = app.properties.configuration.ingress.fqdn
output configVaultName string = config.outputs.vaultName
output identityPrincipalId string = config.outputs.identityPrincipalId

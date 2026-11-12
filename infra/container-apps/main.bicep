// Keyring on Azure Container Apps.
//
// Creates: a Log Analytics workspace for the environment's logs, a Container
// Apps environment (optionally in your VNet), the Keyring app, and Keyring's
// own config vault and managed identity (modules/config-vault.bicep).
//
// The environment can have a public address (external) or only a private
// address in your VNet (internal). Either way the app itself accepts traffic
// from outside the environment, so people's browsers can reach it. An
// internal environment also needs private DNS for its default domain:
// set privateDnsVnetId to have this template create it.
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

@description('Container image, pinned by digest, for example myregistry.azurecr.io/keyring@sha256:...')
param image string

@description('Login server of a private Azure Container Registry, for example myregistry.azurecr.io. The app pulls with its managed identity, which needs AcrPull (see docs/deploy.md). Leave empty for a public image.')
param registryServer string = ''

@description('Deploy only the config vault and identity, not the app. Container Apps reads Key Vault secrets when it creates the app, so run once with this true, set the secrets, then run again with it false. See docs/deploy.md.')
param configOnly bool = false

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

@description('external: the environment gets a public address. internal: the environment only gets a private address in your VNet (needs infrastructureSubnetId), so Keyring is reachable from that VNet and networks peered with it, not the internet.')
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

@description('With internal ingress: the VNet to link a private DNS zone to, so the environment\'s default domain resolves to its private address. Leave empty to manage that DNS yourself (see docs/deploy.md).')
param privateDnsVnetId string = ''

@description('Allow permanent deletes (purge) in Keyring.')
param allowPurge bool = false

@description('Full API scope Keyring asks for at sign-in. Leave empty for the default, api://<clientId>/access_as_user.')
param apiScope string = ''

@description('Log level. Leave empty for the default, info.')
@allowed([
  ''
  'error'
  'warn'
  'info'
  'debug'
  'trace'
])
param logLevel string = ''

@description('Replicas. Sessions live in memory, so keep this at 1 unless you add session affinity (enabled below for more than 1).')
@minValue(1)
@maxValue(10)
param replicas int = 1

@description('Sign in to Entra with the app\'s managed identity instead of a client secret. Needs a federated credential on the app registration first (see docs/deploy.md). When true, no entra-client-secret is read from the config vault.')
param useFederatedCredential bool = false

param tags object = {}

var privateVaultOk = empty(configVaultPrivateEndpointSubnetId) || (!empty(infrastructureSubnetId) && !empty(vaultPrivateDnsZoneId))
var privateVaultCheck = privateVaultOk ? 'ok' : fail('configVaultPrivateEndpointSubnetId needs infrastructureSubnetId and vaultPrivateDnsZoneId too, or the app can\'t reach its own secrets.')
// An internal environment only has an address inside a VNet, so it needs one.
var internalCheck = ingress == 'external' || !empty(infrastructureSubnetId) ? 'ok' : fail('Internal ingress needs infrastructureSubnetId.')
// The DNS zone only makes sense for an internal environment.
var dnsCheck = empty(privateDnsVnetId) || ingress == 'internal' ? 'ok' : fail('privateDnsVnetId is only used with internal ingress.')

var identityName = '${name}-id'
var identityId = resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', identityName)

// How Keyring proves itself to Entra: the client secret, or (with
// useFederatedCredential) the app's managed identity. Never both: Keyring
// refuses to start with both set.
var credentialEnv = useFederatedCredential
  ? [{ name: 'KEYRING_FEDERATED_IDENTITY_CLIENT_ID', value: config.outputs.identityClientId }]
  : [{ name: 'ENTRA_CLIENT_SECRET', secretRef: 'entra-client-secret' }]

// The deployment name depends on the checks, so a failed check stops the
// deployment before anything is created.
module config '../modules/config-vault.bicep' = {
  name: '${name}-config${privateVaultCheck == 'ok' && internalCheck == 'ok' && dnsCheck == 'ok' ? '' : '-invalid'}'
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

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (!configOnly) {
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

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = if (!configOnly) {
  name: '${name}-env'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs!.properties.customerId
        sharedKey: logs!.listKeys().primarySharedKey
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

resource app 'Microsoft.App/containerApps@2024-03-01' = if (!configOnly) {
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
    environmentId: env!.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      registries: empty(registryServer)
        ? []
        : [
            {
              server: registryServer
              identity: identityId
            }
          ]
      ingress: {
        // Accept traffic from outside the environment. Whether that means
        // the internet or only the VNet is the environment's internal flag.
        // false here would limit the app to other apps in the environment.
        external: true
        targetPort: 3000
        transport: 'http'
        allowInsecure: false
        stickySessions: {
          affinity: replicas > 1 ? 'sticky' : 'none'
        }
      }
      // Key Vault references, resolved with the identity.
      secrets: concat(
        useFederatedCredential
          ? []
          : [
              {
                name: 'entra-client-secret'
                keyVaultUrl: '${config.outputs.vaultUri}secrets/entra-client-secret'
                identity: identityId
              }
            ],
        [
          {
            name: 'session-secret'
            keyVaultUrl: '${config.outputs.vaultUri}secrets/session-secret'
            identity: identityId
          }
        ]
      )
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
          // Every setting is listed here, so one added by hand in the
          // portal is removed by the next deployment. Optional ones are left
          // out when empty.
          env: concat(
            [
              { name: 'ENTRA_TENANT_ID', value: tenantId }
              { name: 'ENTRA_CLIENT_ID', value: clientId }
              { name: 'APP_BASE_URL', value: appBaseUrl }
            ],
            credentialEnv,
            [
              { name: 'SESSION_SECRET', secretRef: 'session-secret' }
              { name: 'KEYRING_ALLOW_PURGE', value: string(allowPurge) }
            ],
            empty(apiScope) ? [] : [{ name: 'ENTRA_API_SCOPE', value: apiScope }],
            empty(logLevel) ? [] : [{ name: 'KEYRING_LOG_LEVEL', value: logLevel }]
          )
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

// An internal environment's default domain only resolves with a private
// DNS zone for it, holding a wildcard record for the environment's address.
module dns '../modules/container-apps-dns.bicep' = if (!configOnly && !empty(privateDnsVnetId) && dnsCheck == 'ok') {
  name: '${name}-env-dns'
  params: {
    zoneName: env!.properties.defaultDomain
    staticIp: env!.properties.staticIp
    vnetId: privateDnsVnetId
    tags: tags
  }
}

output appName string = configOnly ? '' : app.name
output fqdn string = configOnly ? '' : app!.properties.configuration.ingress.fqdn
@description('The environment\'s default domain. With internal ingress, a private DNS zone of this name needs a wildcard A record for staticIp.')
output defaultDomain string = configOnly ? '' : env!.properties.defaultDomain
@description('The environment\'s address: private with internal ingress, public with external.')
output staticIp string = configOnly ? '' : env!.properties.staticIp
output checks string = '${privateVaultCheck} ${internalCheck} ${dnsCheck}'
output configVaultName string = config.outputs.vaultName
output identityPrincipalId string = config.outputs.identityPrincipalId

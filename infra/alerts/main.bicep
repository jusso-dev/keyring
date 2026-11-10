// Optional expiry alerts for one Key Vault, with no Keyring involvement.
//
// Key Vault raises near-expiry events by itself (about 30 days before an
// item's expiry date). This subscribes to them with Event Grid and sends
// them to an Azure Monitor action group (email and, optionally, a webhook).
// Keyring stores nothing and runs nothing for this. The topic and
// subscription are in modules/expiry-events.bicep.
//
// Off by default: deploy it per vault only if you want it. Remove it by
// deleting the resources it made (see docs/alerts.md).
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Name of an existing vault in this resource group to watch.')
param vaultName string

@description('Name of an Event Grid system topic the vault already has, if any. Azure allows one per vault. Leave empty to create one. Check with: az eventgrid system-topic list -g <rg> --query "[?source==\'<vault ID>\'].name"')
param existingSystemTopicName string = ''

@description('Email addresses to notify.')
param emails array = []

@description('Optional HTTPS webhook (for example a Teams or Slack workflow) to notify. Leave empty for none. Treated as a secret because webhook URLs often hold a token.')
@secure()
param webhookUrl string = ''

@description('Which events to send.')
param eventTypes array = [
  'Microsoft.KeyVault.SecretNearExpiry'
  'Microsoft.KeyVault.SecretExpired'
  'Microsoft.KeyVault.CertificateNearExpiry'
  'Microsoft.KeyVault.CertificateExpired'
  'Microsoft.KeyVault.KeyNearExpiry'
  'Microsoft.KeyVault.KeyExpired'
]

param tags object = {}

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: vaultName
}

resource actions 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${vaultName}-expiry'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'kvexpiry'
    enabled: true
    emailReceivers: [
      for (email, i) in emails: {
        name: 'email-${i}'
        emailAddress: email
        useCommonAlertSchema: true
      }
    ]
    webhookReceivers: empty(webhookUrl)
      ? []
      : [
          {
            name: 'webhook'
            serviceUri: webhookUrl
            useCommonAlertSchema: true
          }
        ]
  }
}

// A Key Vault system topic must be in the vault's own region, which may not
// be the resource group's. The vault's region is only known once it's read,
// so the topic and subscription go in a module that takes it as a parameter.
module events '../modules/expiry-events.bicep' = {
  name: '${vaultName}-expiry-events'
  params: {
    location: vault.location
    vaultId: vault.id
    topicName: empty(existingSystemTopicName) ? '${vaultName}-events' : existingSystemTopicName
    createTopic: empty(existingSystemTopicName)
    actionGroupId: actions.id
    eventTypes: eventTypes
    tags: tags
  }
}

output actionGroupId string = actions.id
output systemTopicName string = events.outputs.topicName

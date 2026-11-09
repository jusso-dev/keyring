// Optional expiry alerts for one Key Vault, with no Keyring involvement.
//
// Key Vault raises near-expiry events by itself (about 30 days before an
// item's expiry date). This subscribes to them with Event Grid and sends
// them to an Azure Monitor action group (email and, optionally, a webhook).
// Keyring stores nothing and runs nothing for this.
//
// Off by default: deploy it per vault only if you want it. Remove it by
// deleting the resources it made (see docs/alerts.md).
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Name of an existing vault in this resource group to watch.')
param vaultName string

@description('Azure region of the vault.')
param location string = resourceGroup().location

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

resource topic 'Microsoft.EventGrid/systemTopics@2025-02-15' = {
  name: '${vaultName}-events'
  location: location
  tags: tags
  properties: {
    source: vault.id
    topicType: 'Microsoft.KeyVault.vaults'
  }
}

resource subscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15' = {
  parent: topic
  name: 'expiry-to-action-group'
  properties: {
    destination: {
      endpointType: 'MonitorAlert'
      properties: {
        severity: 'Sev3'
        actionGroups: [
          actions.id
        ]
        description: 'Key Vault item near or past expiry'
      }
    }
    filter: {
      includedEventTypes: eventTypes
    }
    eventDeliverySchema: 'CloudEventSchemaV1_0'
  }
}

output actionGroupId string = actions.id
output systemTopicName string = topic.name

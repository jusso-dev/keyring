// The Event Grid system topic for one vault and the subscription that sends
// its expiry events to an action group, or to Keyring's webhook. Used by
// infra/alerts/main.bicep.
//
// Azure allows one system topic per vault. With createTopic false the
// subscription is added to the topic the vault already has.

@description('The vault\'s region. A Key Vault system topic must be in it.')
param location string

param vaultId string

@description('Topic to create, or the existing topic to use.')
param topicName string

param createTopic bool

@description('actionGroup: an Azure Monitor action group. keyring: Keyring\'s /hooks/eventgrid webhook, with Microsoft Entra authentication.')
@allowed([
  'actionGroup'
  'keyring'
])
param notifyVia string = 'actionGroup'

@description('With actionGroup: the action group.')
param actionGroupId string = ''

@description('With keyring: https://<keyring>/hooks/eventgrid.')
param keyringWebhookUrl string = ''

@description('With keyring: the tenant of Keyring\'s app registration.')
param entraTenantId string = ''

@description('With keyring: the audience Event Grid asks Entra for, Keyring\'s app ID URI (api://<client ID>) unless KEYRING_EVENTGRID_AUDIENCE says otherwise.')
param entraAudience string = ''

@description('With keyring: addresses, separated by commas, sent in the keyring-notify delivery header. Keyring honours it only when KEYRING_NOTIFY_ALLOWED_DOMAINS is set. Empty sends no header.')
param notifyRecipients string = ''

@description('With keyring: the resource ID of a blob container for undeliverable events (dead-lettering), such as /subscriptions/.../storageAccounts/<account>/blobServices/default/containers/<container>. Empty for none.')
param deadLetterContainerId string = ''

param eventTypes array

param tags object = {}

resource newTopic 'Microsoft.EventGrid/systemTopics@2025-02-15' = if (createTopic) {
  name: topicName
  location: location
  tags: tags
  properties: {
    source: vaultId
    topicType: 'Microsoft.KeyVault.vaults'
  }
}

resource existingTopic 'Microsoft.EventGrid/systemTopics@2025-02-15' existing = if (!createTopic) {
  name: topicName
}

var toKeyring = notifyVia == 'keyring'

var actionGroupDestination = {
  endpointType: 'MonitorAlert'
  properties: {
    severity: 'Sev3'
    actionGroups: [
      actionGroupId
    ]
    description: 'Key Vault item near or past expiry'
  }
}

// Keyring checks every delivery's Entra token (issuer, audience, tenant,
// Event Grid's application ID and the AzureEventGridSecureWebhookSubscriber
// app role). No shared secret and no key in the address.
var keyringDestination = {
  endpointType: 'WebHook'
  properties: {
    endpointUrl: keyringWebhookUrl
    azureActiveDirectoryTenantId: entraTenantId
    azureActiveDirectoryApplicationIdOrUri: entraAudience
    maxEventsPerBatch: 10
    preferredBatchSizeInKilobytes: 64
    deliveryAttributeMappings: empty(notifyRecipients)
      ? []
      : [
          {
            name: 'keyring-notify'
            type: 'Static'
            properties: {
              value: notifyRecipients
              isSecret: false
            }
          }
        ]
  }
}

var deadLetter = toKeyring && !empty(deadLetterContainerId)
  ? {
      deadLetterDestination: {
        endpointType: 'StorageBlob'
        properties: {
          resourceId: split(deadLetterContainerId, '/blobServices/')[0]
          blobContainerName: last(split(deadLetterContainerId, '/'))
        }
      }
    }
  : {}

var subscriptionName = toKeyring ? 'expiry-to-keyring' : 'expiry-to-action-group'
var subscriptionProperties = union(
  {
    destination: toKeyring ? keyringDestination : actionGroupDestination
    filter: {
      includedEventTypes: eventTypes
    }
    // Keyring reads the Event Grid schema; the action group, CloudEvents.
    eventDeliverySchema: toKeyring ? 'EventGridSchema' : 'CloudEventSchemaV1_0'
  },
  toKeyring
    ? {
        retryPolicy: {
          maxDeliveryAttempts: 30
          eventTimeToLiveInMinutes: 1440
        }
      }
    : {},
  deadLetter
)

resource onNewTopic 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15' = if (createTopic) {
  parent: newTopic
  name: subscriptionName
  properties: subscriptionProperties
}

resource onExistingTopic 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15' = if (!createTopic) {
  parent: existingTopic
  name: subscriptionName
  properties: subscriptionProperties
}

output topicName string = topicName
output subscriptionName string = subscriptionName

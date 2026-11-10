// The Event Grid system topic for one vault and the subscription that sends
// its expiry events to an action group. Used by infra/alerts/main.bicep.
//
// Azure allows one system topic per vault. With createTopic false the
// subscription is added to the topic the vault already has.

@description('The vault\'s region. A Key Vault system topic must be in it.')
param location string

param vaultId string

@description('Topic to create, or the existing topic to use.')
param topicName string

param createTopic bool

param actionGroupId string

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

var subscriptionName = 'expiry-to-action-group'
var subscriptionProperties = {
  destination: {
    endpointType: 'MonitorAlert'
    properties: {
      severity: 'Sev3'
      actionGroups: [
        actionGroupId
      ]
      description: 'Key Vault item near or past expiry'
    }
  }
  filter: {
    includedEventTypes: eventTypes
  }
  eventDeliverySchema: 'CloudEventSchemaV1_0'
}

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

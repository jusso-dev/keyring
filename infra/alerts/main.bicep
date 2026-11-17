// Optional expiry alerts for one Key Vault.
//
// Key Vault raises near-expiry events by itself (about 30 days before an
// item's expiry date). This subscribes to them with Event Grid and sends
// them either
//
// - to an Azure Monitor action group (email and, optionally, a webhook),
//   with no Keyring involvement (notifyVia = 'actionGroup', the default), or
// - to Keyring's /hooks/eventgrid, which emails through Azure Communication
//   Services (notifyVia = 'keyring'). Event Grid authenticates with a
//   Microsoft Entra token for Keyring's app registration; there is no
//   shared secret. Keyring never reads the vault: the event carries what
//   the email needs. Needs the one-off Entra steps in docs/alerts.md.
//
// The topic and subscription are in modules/expiry-events.bicep.
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

@description('Where events go: actionGroup (an Azure Monitor action group) or keyring (Keyring\'s webhook, which emails through Azure Communication Services).')
@allowed([
  'actionGroup'
  'keyring'
])
param notifyVia string = 'actionGroup'

@description('With keyring: Keyring\'s public address, such as https://keyring.example.com. Event Grid posts to <address>/hooks/eventgrid.')
param keyringBaseUrl string = ''

@description('With keyring: the tenant ID of Keyring\'s app registration.')
param entraTenantId string = tenant().tenantId

@description('With keyring: the audience Event Grid asks Entra for. Keyring\'s app ID URI (api://<client ID>), or the value of KEYRING_EVENTGRID_AUDIENCE if you set it.')
param entraAudience string = ''

@description('With keyring: addresses, separated by commas, for this vault\'s notices, sent in the keyring-notify delivery header. Keyring uses them only when KEYRING_NOTIFY_ALLOWED_DOMAINS is set, and checks each against it; otherwise it sends to KEYRING_NOTIFY_ADMINS. Empty sends to the admins.')
param keyringRecipients string = ''

@description('With keyring: resource ID of a blob container for events Event Grid gives up on (dead-lettering). Empty for none.')
param deadLetterContainerId string = ''

@description('With actionGroup: email addresses to notify.')
param emails array = []

@description('With actionGroup: optional HTTPS webhook (for example a Teams or Slack workflow) to notify. Leave empty for none. Treated as a secret because webhook URLs often hold a token.')
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

var toKeyring = notifyVia == 'keyring'

// With keyring, an HTTPS address with no path, and an audience, are needed.
var keyringChecked = toKeyring
  ? (startsWith(keyringBaseUrl, 'https://') && !endsWith(keyringBaseUrl, '/') && !empty(entraAudience)
      ? true
      : fail('notifyVia = keyring needs keyringBaseUrl (https://..., no trailing slash) and entraAudience (api://<client ID>)'))
  : true

resource actions 'Microsoft.Insights/actionGroups@2023-01-01' = if (!toKeyring) {
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
    notifyVia: notifyVia
    actionGroupId: toKeyring ? '' : actions.id
    keyringWebhookUrl: toKeyring && keyringChecked ? '${keyringBaseUrl}/hooks/eventgrid' : ''
    entraTenantId: toKeyring ? entraTenantId : ''
    entraAudience: toKeyring ? entraAudience : ''
    notifyRecipients: toKeyring ? keyringRecipients : ''
    deadLetterContainerId: toKeyring ? deadLetterContainerId : ''
    eventTypes: eventTypes
    tags: tags
  }
}

output actionGroupId string = toKeyring ? '' : actions.id
output systemTopicName string = events.outputs.topicName
output subscriptionName string = events.outputs.subscriptionName

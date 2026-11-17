// The audit sink: a custom table for Keyring's own audit events, a data
// collection rule that writes to it, and the one role Keyring's managed
// identity needs to send rows through that rule.
//
// Deployed into the workspace's resource group, which can be in another
// subscription (an existing Sentinel workspace, for example).
//
// Keyring writes every row as its managed identity. Each row also names the
// person who acted (the Actor columns, from Keyring's verified session) and
// the writer (WriterIdentityClientId, KeyringInstance, KeyringVersion). No
// person gets a role on the rule, so nobody can add rows with their own
// token.
//
// The columns must match `COLUMNS` in src/audit/sink.rs, which
// tests/audit_events.rs checks.
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Name of the Log Analytics workspace, in this resource group.')
param workspaceName string

@description('Region of the rule. Must be the workspace\'s region.')
param location string = resourceGroup().location

@description('Name of the data collection rule.')
param ruleName string

@description('Principal (object) ID of Keyring\'s user-assigned managed identity. It gets Monitoring Metrics Publisher on the rule, and nothing else.')
param identityPrincipalId string

@description('Days the table keeps rows. 365 matches what most Sentinel workspaces keep.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 365

param tags object = {}

// The stream Keyring sends. `time` becomes TimeGenerated in the table.
var streamName = 'Custom-KeyringAudit_CL'
var streamColumns = [
  { name: 'time', type: 'datetime' }
  { name: 'EventId', type: 'string' }
  { name: 'SchemaVersion', type: 'int' }
  { name: 'Action', type: 'string' }
  { name: 'Outcome', type: 'string' }
  { name: 'ReasonCode', type: 'string' }
  { name: 'ActorObjectId', type: 'string' }
  { name: 'ActorTenantId', type: 'string' }
  { name: 'ActorUpn', type: 'string' }
  { name: 'SessionRef', type: 'string' }
  { name: 'ClientIp', type: 'string' }
  { name: 'UserAgent', type: 'string' }
  { name: 'Vault', type: 'string' }
  { name: 'ItemKind', type: 'string' }
  { name: 'ItemName', type: 'string' }
  { name: 'ItemVersion', type: 'string' }
  { name: 'KvRequestId', type: 'string' }
  { name: 'Reason', type: 'string' }
  { name: 'Ticket', type: 'string' }
  { name: 'Role', type: 'string' }
  { name: 'RoleScope', type: 'string' }
  { name: 'RoleDuration', type: 'string' }
  { name: 'NotifyType', type: 'string' }
  { name: 'NotifyRecipientCount', type: 'int' }
  { name: 'NotifyRecipients', type: 'string' }
  { name: 'WriterIdentityClientId', type: 'string' }
  { name: 'KeyringInstance', type: 'string' }
  { name: 'KeyringVersion', type: 'string' }
]
var tableColumns = concat(
  [{ name: 'TimeGenerated', type: 'datetime' }],
  filter(streamColumns, c => c.name != 'time')
)

// Monitoring Metrics Publisher: lets the holder send data through a rule.
var metricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'KeyringAudit_CL'
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    totalRetentionInDays: retentionInDays
    schema: {
      name: 'KeyringAudit_CL'
      description: 'Keyring\'s own audit events, written by Keyring\'s managed identity. Actor columns name the person who acted.'
      columns: tableColumns
    }
  }
}

// Kind Direct: the rule has its own logs ingestion endpoint, so no separate
// data collection endpoint is needed.
resource rule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: ruleName
  location: location
  tags: tags
  kind: 'Direct'
  properties: {
    description: 'Keyring audit events into KeyringAudit_CL'
    streamDeclarations: {
      '${streamName}': {
        columns: streamColumns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'workspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['workspace']
        // The table has TimeGenerated, not time, so time is dropped after.
        transformKql: 'source | extend TimeGenerated = todatetime(time) | project-away time'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [table]
}

resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(rule.id, identityPrincipalId, metricsPublisherRoleId)
  scope: rule
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', metricsPublisherRoleId)
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

@description('KEYRING_AUDIT_INGESTION_ENDPOINT')
output ingestionEndpoint string = rule.properties.endpoints.logsIngestion
@description('KEYRING_AUDIT_DCR_ID')
output ruleImmutableId string = rule.properties.immutableId
@description('KEYRING_AUDIT_STREAM')
output streamName string = streamName

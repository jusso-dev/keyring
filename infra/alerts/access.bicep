// Optional access alerts for one Key Vault, with no Keyring involvement.
//
// Log search alert rules (Azure Monitor scheduled query rules) on the Log
// Analytics workspace the vault sends its AuditEvent logs to. Up to three
// rules, each optional:
//
// - a read of a watched secret (SecretGet, or CertificateGet of the same name)
// - any purge (SecretPurge, CertificatePurge, KeyPurge)
// - more than N refusals (HTTP 403) from one caller in 15 minutes
//
// Each sends to an Azure Monitor action group (email and, optionally, a
// webhook). The alert carries who, what, the item, the caller's IP and the
// time window (as dimensions in the common alert schema). Key Vault's log never holds a value, so neither does the alert.
// Keyring stores nothing and runs nothing for this.
//
// Each rule runs its query as its own system-assigned identity, which needs
// Log Analytics Reader on the workspace (see docs/alerts.md). The column and
// operation names match src/azure/audit.rs; tests/alert_queries.rs checks.
//
// Off by default: deploy it per vault only if you want it. Remove it by
// deleting the resources it made (see docs/alerts.md).
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Name of the vault to watch, as it appears in its audit logs.')
@minLength(3)
@maxLength(24)
param vaultName string

@description('ARM resource ID of the Log Analytics workspace the vault sends AuditEvent logs to.')
param workspaceId string

@description('Which table the vault\'s diagnostic setting writes to: AzureDiagnostics (the default, "Azure diagnostics" in the portal) or AZKVAuditLogs ("Resource specific"). Keyring\'s audit page reads the same setting.')
@allowed([
  'AzureDiagnostics'
  'AZKVAuditLogs'
])
param table string = 'AzureDiagnostics'

@description('Names of secrets (or certificates) whose reads raise an alert. Leave empty for no read alert.')
param watchedSecretNames array = []

@description('Raise an alert on any purge of a secret, certificate or key.')
param alertOnPurge bool = true

@description('Raise an alert when one caller is refused (HTTP 403) more than this many times in 15 minutes. 0 turns it off.')
@minValue(0)
param refusedThreshold int = 10

@description('How often the read and purge rules run, and the window each run looks at.')
@allowed([
  'PT5M'
  'PT10M'
  'PT15M'
  'PT30M'
  'PT1H'
])
param evaluationFrequency string = 'PT5M'

@description('Email addresses to notify.')
param emails array = []

@description('Optional HTTPS webhook (for example a Teams or Slack workflow) to notify. Leave empty for none. Treated as a secret because webhook URLs often hold a token.')
@secure()
param webhookUrl string = ''

@description('Region for the alert rules. Usually the workspace\'s region.')
param location string = resourceGroup().location

param tags object = {}

// Values go into the KQL only as JSON inside dynamic(), so a name can't end
// the literal or add query text.
var vaultNameList = [
  vaultName
]
var vaultLiteral = 'tostring(dynamic(${string(vaultNameList)})[0])'
var namesLiteral = 'dynamic(${string(watchedSecretNames)})'

// Both tables projected to the audit view's columns: TimeGenerated, Who,
// OperationName, Item, ResultSignature, CallerIpAddress, plus Status (the
// HTTP status code) for refusals. AzureDiagnostics only has a column once
// data with it has arrived, so every optional column goes through
// column_ifexists, as in src/azure/audit.rs.
var diagnosticsSource = '''
AzureDiagnostics
| where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'
| where Resource =~ vaultName
| extend Item = tostring(split(tostring(parse_url(tostring(column_ifexists('requestUri_s', ''))).Path), '/')[2])
| extend Who = coalesce(
    tostring(column_ifexists('identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s', '')),
    tostring(column_ifexists('identity_claim_upn_s', '')),
    tostring(column_ifexists('identity_claim_appid_g', '')),
    tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')),
    tostring(column_ifexists('identity_claim_oid_g', '')))
| extend Client = tostring(column_ifexists('CallerIPAddress', ''))
| extend Status = toint(column_ifexists('httpStatusCode_d', real(null)))
'''

var resourceSpecificSource = '''
AZKVAuditLogs
| where _ResourceId endswith strcat('/vaults/', tolower(vaultName))
| extend Item = tostring(split(tostring(parse_url(column_ifexists('RequestUri', '')).Path), '/')[2])
| extend Claims = column_ifexists('Identity', dynamic(null)).claim
| extend Who = coalesce(
    tostring(Claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn']),
    tostring(Claims.upn),
    tostring(Claims.appid),
    tostring(Claims['http://schemas.microsoft.com/identity/claims/objectidentifier']),
    tostring(Claims.oid))
| extend Client = tostring(column_ifexists('CallerIpAddress', ''))
| extend Status = toint(column_ifexists('HttpStatusCode', int(null)))
'''

var source = 'let vaultName = ${vaultLiteral};\n${table == 'AzureDiagnostics' ? diagnosticsSource : resourceSpecificSource}| project TimeGenerated, Who, OperationName, Item, ResultSignature = tostring(column_ifexists(\'ResultSignature\', \'\')), CallerIpAddress = Client, Status\n'

var readsQuery = '''
| where OperationName in ('SecretGet', 'CertificateGet')
| where Item in~ (watched)
| summarize Count = count() by Who, OperationName, Item, ResultSignature, CallerIpAddress
'''

var purgeQuery = '''
| where OperationName in ('SecretPurge', 'CertificatePurge', 'KeyPurge')
| summarize Count = count() by Who, OperationName, Item, ResultSignature, CallerIpAddress
'''

var refusedQuery = '''
| where Status == 403
| extend Caller = iff(isempty(Who), CallerIpAddress, Who)
| summarize Refused = count(), Operations = strcat_array(make_set(OperationName, 10), ', '), Addresses = strcat_array(make_set(CallerIpAddress, 10), ', ') by Caller
'''

var eventDimensions = [
  for d in ['Who', 'OperationName', 'Item', 'ResultSignature', 'CallerIpAddress']: {
    name: d
    operator: 'Include'
    values: ['*']
  }
]

var refusalDimensions = [
  for d in ['Caller', 'Operations', 'Addresses']: {
    name: d
    operator: 'Include'
    values: ['*']
  }
]

var rules = filter(
  [
    {
      enabled: !empty(watchedSecretNames)
      key: 'reads'
      displayName: 'Watched secret read in ${vaultName}'
      description: 'A watched secret or certificate in ${vaultName} was read (SecretGet or CertificateGet).'
      severity: 2
      query: 'let watched = ${namesLiteral};\n${source}${readsQuery}'
      measure: 'Count'
      threshold: 0
      window: evaluationFrequency
      frequency: evaluationFrequency
      dimensions: eventDimensions
    }
    {
      enabled: alertOnPurge
      key: 'purges'
      displayName: 'Purge in ${vaultName}'
      description: 'A secret, certificate or key in ${vaultName} was purged (permanently deleted).'
      severity: 1
      query: '${source}${purgeQuery}'
      measure: 'Count'
      threshold: 0
      window: evaluationFrequency
      frequency: evaluationFrequency
      dimensions: eventDimensions
    }
    {
      enabled: refusedThreshold > 0
      key: 'refusals'
      displayName: 'Repeated refusals in ${vaultName}'
      description: 'One caller was refused (HTTP 403) by ${vaultName} more than ${refusedThreshold} times in 15 minutes.'
      severity: 2
      query: '${source}${refusedQuery}'
      measure: 'Refused'
      threshold: refusedThreshold
      window: 'PT15M'
      frequency: 'PT5M'
      dimensions: refusalDimensions
    }
  ],
  r => r.enabled
)

resource actions 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${vaultName}-access'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'kvaccess'
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

resource alerts 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = [
  for rule in rules: {
    name: '${vaultName}-access-${rule.key}'
    location: location
    tags: tags
    kind: 'LogAlert'
    identity: {
      type: 'SystemAssigned'
    }
    properties: {
      displayName: rule.displayName
      description: rule.description
      severity: rule.severity
      enabled: true
      scopes: [
        workspaceId
      ]
      evaluationFrequency: rule.frequency
      windowSize: rule.window
      // Every match notifies. A log alert has no "resolved" state worth sending.
      autoMitigate: false
      criteria: {
        allOf: [
          {
            query: rule.query
            timeAggregation: 'Total'
            metricMeasureColumn: rule.measure
            operator: 'GreaterThan'
            threshold: rule.threshold
            dimensions: rule.dimensions
            failingPeriods: {
              numberOfEvaluationPeriods: 1
              minFailingPeriodsToAlert: 1
            }
          }
        ]
      }
      actions: {
        actionGroups: [
          actions.id
        ]
      }
    }
  }
]

output actionGroupId string = actions.id
@description('Rule names and the principal IDs of their identities. Each needs Log Analytics Reader on the workspace.')
output rules array = [
  for (rule, i) in rules: {
    name: alerts[i].name
    principalId: alerts[i].identity.principalId
  }
]

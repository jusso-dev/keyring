// Optional Microsoft Sentinel content for Keyring's own audit table,
// KeyringAudit_CL (made by modules/audit-sink.bicep):
//
// - the ASIM Audit Event parsers vimAuditEventKeyring (filtering) and
//   ASimAuditEventKeyring (parameter-less), as workspace functions
// - hunting queries, as saved searches in the "Hunting Queries" category
// - a workbook: reveals over time, top people and vaults, denied and refused
//   events, sink health, and one person's activity
// - analytic rules (Sentinel Scheduled rules). Every rule is created turned
//   off, and each is turned on by its own parameter. Deploying with the
//   defaults creates nothing that raises an alert.
//
// The two rules that compare with Key Vault's log need Keyring's outbound
// addresses (keyringOutboundIps). With none, they aren't created at all.
//
// Keyring stores nothing and runs nothing for this: Sentinel runs the rules
// as itself. The query text lives in the .kql files next to this one, which
// tests/sentinel.rs checks against `COLUMNS` in src/audit/sink.rs.
//
// Deploy into the workspace's resource group, after Sentinel is turned on
// for the workspace. Needs Microsoft Sentinel Contributor and Log Analytics
// Contributor there (see docs/sentinel.md).
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Name of the Log Analytics workspace that holds KeyringAudit_CL, in this resource group. Sentinel must already be turned on for it.')
param workspaceName string

@description('Region of the workbook. Usually the workspace\'s region.')
param location string = resourceGroup().location

@description('Add the ASIM parsers vimAuditEventKeyring and ASimAuditEventKeyring as workspace functions.')
param deployParsers bool = true

@description('Add the hunting queries as saved searches.')
param deployHuntingQueries bool = true

@description('Add the Keyring workbook.')
param deployWorkbook bool = true

@description('Which table the vaults\' diagnostic settings write Key Vault\'s log to, for the two rules that compare with it: AzureDiagnostics or AZKVAuditLogs ("Resource specific").')
@allowed([
  'AzureDiagnostics'
  'AZKVAuditLogs'
])
param keyVaultTable string = 'AzureDiagnostics'

@description('Keyring\'s outbound IP addresses, as Key Vault sees them (the App Service outbound addresses, or the Container Apps environment\'s static outbound IP or NAT gateway). Keyring can\'t know these itself. Leave empty and the audit gap and unmatched SecretGet rules aren\'t created.')
param keyringOutboundIps array = []

@description('Minutes rows can take to arrive in KeyringAudit_CL after they happen. Each rule looks back this much further than it runs, and counts a row in the run after it arrives, so a late row is neither missed nor raised twice. Measure it in your workspace (see docs/sentinel.md) and set it above what you see.')
@minValue(0)
@maxValue(60)
param ingestionDelayMinutes int = 10

// Many reveals by one person
@description('Turn on: many secret reveals or private key downloads by one person in a short time.')
param enableManyReveals bool = false
@description('Reveals (and private key downloads) by one person in the window that raise an alert.')
@minValue(2)
param revealThreshold int = 20
@description('Window for the many reveals rule, in minutes. The rule also runs this often.')
@minValue(5)
@maxValue(1440)
param revealWindowMinutes int = 60

// Reveal from a new address
@description('Turn on: a reveal or private key download from an address not seen for that person in the last 14 days.')
param enableRevealNewIp bool = false
@description('How often the new address rule runs, and how far back it looks for new reads, in hours. Sentinel needs at least an hour for a rule that looks back 14 days.')
@minValue(1)
@maxValue(24)
param newIpWindowHours int = 1

// Denied across vaults
@description('Turn on: one person denied by Key Vault in several vaults (probing).')
param enableDeniedProbing bool = false
@description('Distinct vaults one person must be denied in to raise an alert.')
@minValue(2)
param probingVaults int = 3
@description('Denied events one person must have, across those vaults, to raise an alert.')
@minValue(1)
param probingDenied int = 5
@description('Window for the probing rule, in minutes. The rule also runs this often.')
@minValue(5)
@maxValue(1440)
param probingWindowMinutes int = 60

// Outside working hours
@description('Turn on: a purge, private key download or other watched action outside working hours.')
param enableOffHours bool = false
@description('Actions the working hours rule watches, by exact name.')
param offHoursActions array = [
  'secret.purge'
  'certificate.purge'
  'key.purge'
  'certificate.download_private_key'
]
@description('Words the working hours rule also watches for as a dotted part of an action name. "bulk" catches bulk change actions whatever they are named. Empty for none.')
param offHoursTerms array = [
  'bulk'
]
@description('The organisation\'s offset from UTC, in minutes (600 for AEST, 660 for AEDT). Fixed: daylight saving isn\'t followed.')
@minValue(-720)
@maxValue(840)
param utcOffsetMinutes int = 600
@description('First working hour, local time, 0 to 23.')
@minValue(0)
@maxValue(23)
param workStartHour int = 8
@description('Hour working hours end, local time, 1 to 24.')
@minValue(1)
@maxValue(24)
param workEndHour int = 18
@description('Working days, 0 for Sunday to 6 for Saturday.')
param workDays array = [
  1
  2
  3
  4
  5
]
@description('How often the working hours rule runs, and the window it looks at, in minutes.')
@minValue(5)
@maxValue(1440)
param offHoursWindowMinutes int = 15

// Attack on Keyring itself
@description('Turn on: requests Keyring refused as a forged form (csrf) or a cross-site post (cross_site).')
param enableAppAttack bool = false
@description('Such refusals from one address in the window that raise an alert.')
@minValue(1)
param attackThreshold int = 5
@description('Window for the attack rule, in minutes. The rule also runs this often.')
@minValue(5)
@maxValue(1440)
param attackWindowMinutes int = 15

// Audit gap
@description('Turn on: no Keyring events at all while Key Vault logged changes or reads from Keyring\'s outbound addresses. Needs keyringOutboundIps.')
param enableAuditGap bool = false
@description('Hours with no Keyring events that count as a gap. The rule also runs this often.')
@minValue(1)
@maxValue(48)
param auditGapHours int = 6

// SecretGet with no Keyring event
@description('Turn on: a Key Vault SecretGet from Keyring\'s addresses with no matching Keyring event. Not yet checked on a real vault: leave off until the real-vault checklist row "Sentinel: kv_request_id is CorrelationId" passes. Needs keyringOutboundIps.')
param enableUnmatchedSecretGet bool = false

@description('Microsoft Sentinel severity of each rule.')
@allowed([
  'Informational'
  'Low'
  'Medium'
  'High'
])
param severity string = 'Medium'

param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Parameter values go into KQL only as numbers, or as JSON inside
// dynamic(), so no value can end a literal and add query text.
var ipsLiteral = 'dynamic(${string(keyringOutboundIps)})'
var keyVaultSource = keyVaultTable == 'AzureDiagnostics'
  ? loadTextContent('rules/keyvault-diagnostics.kql')
  : loadTextContent('rules/keyvault-azkv.kql')
var keyVaultLet = 'let keyringIps = ${ipsLiteral};\nlet KeyVaultCalls = ${keyVaultSource};\n'
var hasIps = !empty(keyringOutboundIps)
var delayLet = 'let delay = ${ingestionDelayMinutes}m;\n'


var accountEntity = {
  entityType: 'Account'
  fieldMappings: [
    { identifier: 'AadUserId', columnName: 'ActorObjectId' }
    { identifier: 'FullName', columnName: 'ActorUpn' }
  ]
}
var ipEntity = {
  entityType: 'IP'
  fieldMappings: [
    { identifier: 'Address', columnName: 'ClientIp' }
  ]
}
var keyVaultIpEntity = {
  entityType: 'IP'
  fieldMappings: [
    { identifier: 'Address', columnName: 'CallerIpAddress' }
  ]
}
var vaultEntity = {
  entityType: 'AzureResource'
  fieldMappings: [
    { identifier: 'ResourceId', columnName: 'ResourceId' }
  ]
}

var allRules = [
  {
    key: 'many-reveals'
    create: true
    enabled: enableManyReveals
    displayName: 'Keyring: many secret reveals by one person'
    description: 'One person revealed secret values or downloaded private keys through Keyring ${revealThreshold} or more times in ${revealWindowMinutes} minutes.'
    query: 'let window = ${revealWindowMinutes}m;\n${delayLet}let revealThreshold = ${revealThreshold};\n${loadTextContent('rules/many-reveals.kql')}'
    frequency: 'PT${revealWindowMinutes}M'
    period: 'PT${revealWindowMinutes + ingestionDelayMinutes}M'
    tactics: ['CredentialAccess', 'Collection']
    entities: [accountEntity, ipEntity]
  }
  {
    key: 'reveal-new-ip'
    create: true
    enabled: enableRevealNewIp
    displayName: 'Keyring: secret revealed from a new address'
    description: 'A person revealed a secret value or downloaded a private key through Keyring from an address they hadn\'t used in the 14 days before.'
    query: 'let window = ${newIpWindowHours}h;\n${delayLet}${loadTextContent('rules/reveal-new-ip.kql')}'
    frequency: 'PT${newIpWindowHours}H'
    period: 'P14D'
    tactics: ['CredentialAccess', 'InitialAccess']
    entities: [accountEntity, ipEntity]
  }
  {
    key: 'denied-probing'
    create: true
    enabled: enableDeniedProbing
    displayName: 'Keyring: one person denied in several vaults'
    description: 'Key Vault denied one person through Keyring at least ${probingDenied} times across ${probingVaults} or more vaults in ${probingWindowMinutes} minutes.'
    query: 'let window = ${probingWindowMinutes}m;\n${delayLet}let probingVaults = ${probingVaults};\nlet probingDenied = ${probingDenied};\n${loadTextContent('rules/denied-probing.kql')}'
    frequency: 'PT${probingWindowMinutes}M'
    period: 'PT${probingWindowMinutes + ingestionDelayMinutes}M'
    tactics: ['Discovery']
    entities: [accountEntity, ipEntity]
  }
  {
    key: 'off-hours'
    create: true
    enabled: enableOffHours
    displayName: 'Keyring: sensitive action outside working hours'
    description: 'A purge, private key download or other watched action through Keyring outside working hours (${workStartHour}:00 to ${workEndHour}:00, UTC offset ${utcOffsetMinutes} minutes).'
    query: 'let window = ${offHoursWindowMinutes}m;\n${delayLet}let watchedActions = dynamic(${string(offHoursActions)});\nlet watchedTerms = dynamic(${string(offHoursTerms)});\nlet utcOffset = ${utcOffsetMinutes} * 1m;\nlet workStart = ${workStartHour};\nlet workEnd = ${workEndHour};\nlet workDays = dynamic(${string(workDays)});\n${loadTextContent('rules/off-hours.kql')}'
    frequency: 'PT${offHoursWindowMinutes}M'
    period: 'PT${offHoursWindowMinutes + ingestionDelayMinutes}M'
    tactics: ['Impact', 'CredentialAccess']
    entities: [accountEntity, ipEntity]
  }
  {
    key: 'app-attack'
    create: true
    enabled: enableAppAttack
    displayName: 'Keyring: forged or cross-site requests'
    description: 'Keyring refused ${attackThreshold} or more requests from one address in ${attackWindowMinutes} minutes as a forged form (csrf) or a cross-site post (cross_site): a possible attack on Keyring itself.'
    query: 'let window = ${attackWindowMinutes}m;\n${delayLet}let attackThreshold = ${attackThreshold};\n${loadTextContent('rules/app-attack.kql')}'
    frequency: 'PT${attackWindowMinutes}M'
    period: 'PT${attackWindowMinutes + ingestionDelayMinutes}M'
    tactics: ['InitialAccess']
    entities: [ipEntity, accountEntity]
  }
  {
    key: 'audit-gap'
    create: hasIps
    enabled: enableAuditGap
    displayName: 'Keyring: no audit events while Key Vault saw Keyring'
    description: 'No Keyring audit events in ${auditGapHours} hours, while Key Vault logged reads or changes from Keyring\'s outbound addresses. The audit sink may be broken or turned off.'
    query: 'let window = ${auditGapHours}h;\n${keyVaultLet}${loadTextContent('rules/audit-gap.kql')}'
    frequency: 'PT${auditGapHours}H'
    period: 'PT${auditGapHours}H'
    tactics: ['DefenseEvasion']
    entities: [vaultEntity, keyVaultIpEntity]
  }
  {
    key: 'unmatched-secret-get'
    create: hasIps
    enabled: enableUnmatchedSecretGet
    displayName: 'Keyring: SecretGet from Keyring with no audit event'
    description: 'Key Vault logged a SecretGet from Keyring\'s outbound addresses with no matching Keyring audit event. Not yet checked on a real vault.'
    query: '${keyVaultLet}${loadTextContent('rules/unmatched-secret-get.kql')}'
    frequency: 'PT1H'
    period: 'PT3H'
    tactics: ['DefenseEvasion', 'CredentialAccess']
    entities: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'AadUserId', columnName: 'CallerObjectId' }
        ]
      }
      keyVaultIpEntity
      vaultEntity
    ]
  }
]

var rules = filter(allRules, r => r.create)

resource alertRules 'Microsoft.SecurityInsights/alertRules@2024-09-01' = [
  for rule in rules: {
    scope: workspace
    name: guid(workspace.id, 'keyring', rule.key)
    kind: 'Scheduled'
    properties: {
      displayName: rule.displayName
      description: rule.description
      enabled: rule.enabled
      severity: severity
      query: rule.query
      queryFrequency: rule.frequency
      queryPeriod: rule.period
      triggerOperator: 'GreaterThan'
      triggerThreshold: 0
      suppressionDuration: 'PT1H'
      suppressionEnabled: false
      tactics: rule.tactics
      entityMappings: rule.entities
      eventGroupingSettings: {
        aggregationKind: 'AlertPerResult'
      }
      incidentConfiguration: {
        createIncident: true
        groupingConfiguration: {
          enabled: false
          reopenClosedIncident: false
          lookbackDuration: 'PT5H'
          matchingMethod: 'AllEntities'
        }
      }
    }
  }
]

// The filtering parser's parameters, as Microsoft's AuditEvent parsers
// declare them, so the custom unifying parser can call it by name.
var parserParameters = 'starttime:datetime=datetime(null), endtime:datetime=datetime(null), srcipaddr_has_any_prefix:dynamic=dynamic([]), eventtype_in:dynamic=dynamic([]), eventresult:string=\'*\', actorusername_has_any:dynamic=dynamic([]), operation_has_any:dynamic=dynamic([]), object_has_any:dynamic=dynamic([]), newvalue_has_any:dynamic=dynamic([]), disabled:bool=False, pack:bool=False'

resource filteringParser 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployParsers) {
  parent: workspace
  name: 'vimAuditEventKeyring'
  properties: {
    category: 'ASIM'
    displayName: 'Audit Event ASIM filtering parser for Keyring'
    query: loadTextContent('parsers/vimAuditEventKeyring.kql')
    functionAlias: 'vimAuditEventKeyring'
    functionParameters: parserParameters
    version: 2
    tags: [
      { name: 'Schema', value: 'AuditEvent' }
      { name: 'SchemaVersion', value: '1.0.0' }
    ]
  }
}

resource parser 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = if (deployParsers) {
  parent: workspace
  name: 'ASimAuditEventKeyring'
  properties: {
    category: 'ASIM'
    displayName: 'Audit Event ASIM parser for Keyring'
    query: loadTextContent('parsers/ASimAuditEventKeyring.kql')
    functionAlias: 'ASimAuditEventKeyring'
    version: 2
    tags: [
      { name: 'Schema', value: 'AuditEvent' }
      { name: 'SchemaVersion', value: '1.0.0' }
    ]
  }
  dependsOn: [filteringParser]
}

var huntingQueries = [
  {
    key: 'secret-values-read'
    displayName: 'Keyring: secret values read'
    description: 'Secret values revealed through Keyring, with who, vault, item, address and Key Vault request ID.'
    query: loadTextContent('hunting/secret-values-read.kql')
    tactics: 'CredentialAccess'
  }
  {
    key: 'private-keys-downloaded'
    displayName: 'Keyring: private keys downloaded'
    description: 'Certificate private keys downloaded through Keyring.'
    query: loadTextContent('hunting/private-keys-downloaded.kql')
    tactics: 'CredentialAccess'
  }
  {
    key: 'deletes-purges-recoveries'
    displayName: 'Keyring: deletes, purges and recoveries'
    description: 'Secrets, certificates and keys deleted, purged or recovered through Keyring.'
    query: loadTextContent('hunting/deletes-purges-recoveries.kql')
    tactics: 'Impact'
  }
  {
    key: 'refused-and-denied'
    displayName: 'Keyring: refused and denied, by person'
    description: 'What Keyring refused or Azure denied, counted by person, vault and reason.'
    query: loadTextContent('hunting/refused-and-denied.kql')
    tactics: 'Discovery'
  }
  {
    key: 'person-activity'
    displayName: 'Keyring: one person\'s activity'
    description: 'Everything one person did through Keyring.'
    query: loadTextContent('hunting/person-activity.kql')
    tactics: 'Collection'
  }
  {
    key: 'side-by-side'
    displayName: 'Keyring: Key Vault\'s log beside Keyring\'s'
    description: 'Every Key Vault call for one vault, with the Keyring event that made it, if any. The CorrelationId match is still to be confirmed on a real vault.'
    query: loadTextContent('hunting/side-by-side.kql')
    tactics: 'DefenseEvasion'
  }
]

resource hunting 'Microsoft.OperationalInsights/workspaces/savedSearches@2020-08-01' = [
  for q in huntingQueries: if (deployHuntingQueries) {
    parent: workspace
    name: 'keyring-${q.key}'
    properties: {
      category: 'Hunting Queries'
      displayName: q.displayName
      query: q.query
      version: 2
      tags: [
        { name: 'description', value: q.description }
        { name: 'tactics', value: q.tactics }
      ]
    }
  }
]

resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = if (deployWorkbook) {
  name: guid(workspace.id, 'keyring-workbook')
  location: location
  tags: tags
  kind: 'shared'
  properties: {
    displayName: 'Keyring audit'
    category: 'sentinel'
    sourceId: workspace.id
    serializedData: loadTextContent('workbook.json')
  }
}

@description('Rules created, each with whether it is turned on.')
output rules array = [
  for (rule, i) in rules: {
    name: alertRules[i].name
    displayName: rule.displayName
    enabled: rule.enabled
  }
]

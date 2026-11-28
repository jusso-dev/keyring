// Keyring on Azure App Service (Linux, container).
//
// Creates: an App Service plan, the web app running the Keyring image, and
// Keyring's own config vault and managed identity (modules/config-vault.bicep).
// Optional: outbound VNet integration (to reach private vaults), an
// inbound private endpoint, and sending the container's output (Keyring's
// audit events) to a Log Analytics workspace.
//
// The managed identity can only read Keyring's two config secrets. It has
// no access to user vaults. See docs/deploy.md.
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

@description('Set to pull the image from a private Azure Container Registry with the app\'s managed identity. Give that identity AcrPull on the registry first (see docs/deploy.md).')
param useManagedIdentityForRegistry bool = false

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

@description('App Service plan size. B1 or above is enough for a small team, and Basic supports VNet integration and private endpoints.')
param skuName string = 'P0v3'

@description('Plan instance count. When greater than 1, ARR session affinity is turned on so in-memory sessions stay on one instance.')
@minValue(1)
@maxValue(10)
param replicas int = 1

@description('Spread the App Service plan across availability zones (requires a Premium v2/v3 SKU and at least 2 or 3 instances depending on region).')
param zoneRedundant bool = false

@description('Allow permanent deletes (purge) in Keyring.')
param allowPurge bool = false

@description('Subnet for outbound VNet integration, so Keyring can reach private vaults. Must be delegated to Microsoft.Web/serverFarms. Leave empty for none.')
param vnetIntegrationSubnetId string = ''

@description('Subnet for an inbound private endpoint to the app, so people reach Keyring over your VNet, VPN or ExpressRoute only. Public access is then off. Leave empty to use allowedIpRanges instead.')
param inboundPrivateEndpointSubnetId string = ''

@description('Without inboundPrivateEndpointSubnetId: the trusted IP ranges (CIDR) that may reach Keyring\'s public address, such as your office or VPN egress. Everything else is refused. Keyring is never open to the whole internet, so one of the two is required. Each entry is one IPv4 CIDR, /16 or narrower, so no list can open Keyring to the internet.')
param allowedIpRanges array = []

@description('Private DNS zone ID for privatelink.azurewebsites.net, used with the inbound private endpoint.')
param appPrivateDnsZoneId string = ''

@description('Subnet for a private endpoint to the config vault. Leave empty to use its public endpoint.')
param configVaultPrivateEndpointSubnetId string = ''

@description('Private DNS zone ID for privatelink.vaultcore.azure.net, used with the config vault private endpoint.')
param vaultPrivateDnsZoneId string = ''

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

@description('How log lines are written: text (the default) or json, one JSON object per line with Keyring\'s audit events marked "kind":"audit". Leave empty for text.')
@allowed([
  ''
  'text'
  'json'
])
param logFormat string = ''

@description('Conditional Access authentication context ID (c1 to c99) that a reveal, private key download, rollback or purge needs. Leave empty to not ask for one (see docs/deploy.md, "Step-up before sensitive actions").')
param stepUpAuthContext string = ''

@description('Minutes since the person last signed in for a reveal, private key download, rollback or purge to go ahead. 0 turns this off (see docs/deploy.md, "Step-up before sensitive actions").')
@minValue(0)
@maxValue(720)
param stepUpMaxAge int = 0

@description('Ask for a reason before a secret value is shown or a private key downloaded (reveal), or before every change too (all). The reason goes on Keyring\'s audit event. Not a hard control: the CLI needs no reason (see docs/deploy.md, "A reason before a value is shown").')
@allowed([
  ''
  'off'
  'reveal'
  'all'
])
param requireReason string = ''

@description('Regular expression a ticket reference must match as a whole, such as (INC|CHG)[0-9]{7}. Shape only. Needs requireReason. Leave empty to ask for a reason only.')
@maxLength(200)
param reasonTicketPattern string = ''

@description('Password policy for values typed into a Password or Login secret, such as min=14,upper,lower,digit,symbol,max-repeat=3,common. Leave empty for no policy. A Keyring control only: the CLI and portal aren\'t limited by it (see docs/deploy.md, "Password policy").')
@maxLength(200)
// Non-secret rule string (for example "min=14,upper"), not a password.
#disable-next-line secure-secrets-in-params
param passwordPolicy string = ''

@description('Refuse to create or edit a secret, certificate or key without an owner tag, and skip import rows without one. A Keyring control only: the CLI and portal aren\'t limited by it (see README.md, "Owners").')
param requireOwner bool = false

@description('Turn on Share on a secret\'s page: a time-limited Key Vault Secrets User assignment on that one secret, made as the person sharing (KEYRING_SHARING). Needs the two Microsoft Graph permissions in the README\'s app registration step 4.')
param sharing bool = false

@description('The longest a share may last, in days, 1 to 365 (KEYRING_SHARE_MAX_DAYS). 0 keeps Keyring\'s default of 30.')
@minValue(0)
@maxValue(365)
param shareMaxDays int = 0

@description('How many proxies in front of Keyring add to X-Forwarded-For, so audit events record the browser\'s address. 1 for this template\'s front end. 0 records the front end\'s own address. A wrong value lets a client choose the address recorded (see docs/deploy.md, "Client address").')
@minValue(0)
@maxValue(8)
param trustedProxyHops int = 1

@description('Days without a new value before secrets, certificates and keys show "Not changed in over a year" (or over N days). 0 for the default, 365.')
@minValue(0)
@maxValue(3650)
param staleAfterDays int = 0

@description('Days before expiry when secrets, certificates and keys count as expiring soon on vault health, Home and the executive report. 0 for the default, 30.')
@minValue(0)
@maxValue(365)
param expiryWarnDays int = 0

@description('Resource ID of a Log Analytics workspace to send the container\'s output and HTTP logs to. Leave empty to keep a short local log on the app instead (7 days, see docs/deploy.md).')
param logAnalyticsWorkspaceId string = ''

@description('Sign in to Entra with the app\'s managed identity instead of a client secret. Needs a federated credential on the app registration first (see docs/deploy.md). When true, no entra-client-secret is read from the config vault.')
param useFederatedCredential bool = false

@description('Resource ID of a Log Analytics workspace for Keyring\'s audit sink. When set, a KeyringAudit_CL table, a data collection rule and Monitoring Metrics Publisher on that rule for Keyring\'s managed identity are made in the workspace\'s resource group (any subscription), and Keyring sends its audit events there as that identity. The audit page also gains a Keyring activity view, read from the table as each person. Leave empty for no sink. See docs/deploy.md, "Audit sink".')
param auditWorkspaceId string = ''

@description('Days the KeyringAudit_CL table keeps rows.')
@minValue(30)
@maxValue(730)
param auditRetentionInDays int = 365

@description('Refuse reveals and private key downloads while the audit sink has been failing for over a minute. Needs auditWorkspaceId.')
param auditRequired bool = false

@description('Email for Keyring\'s notifications through Azure Communication Services: AzureManaged for an Azure-managed domain, or your own domain name (such as mail.example.com, whose SPF, DKIM and DMARC records you add yourself). Leave empty for no email. Makes the ACS resources in this resource group and gives Keyring\'s managed identity a two-action custom role on the one Communication Services resource. See docs/deploy.md, "Email".')
param notifyDomain string = ''

@description('Where ACS keeps its data at rest, such as Australia, Europe or United States.')
param notifyDataLocation string = 'Australia'

@description('Which notices to send, separated by commas: expiry, access-requests, watched-reads, destructive, role-use, health. Empty sends none.')
param notifyTypes string = ''

@description('Addresses, separated by commas, for health and fallback notices.')
param notifyAdmins string = ''

@description('Domains, separated by commas, that every recipient must be in. Empty allows any.')
param notifyAllowedDomains string = ''

@description('With expiry in notifyTypes: the subscription IDs, separated by commas, whose Key Vaults may send expiry events to Keyring (KEYRING_EVENTGRID_SUBSCRIPTIONS). Defaults to this deployment\'s subscription; add the ID of any other subscription a watched vault is in. Empty accepts any subscription, which Keyring warns about at start-up.')
param eventGridSubscriptions string = subscription().subscriptionId

@description('With expiry in notifyTypes: the aud Event Grid\'s token must carry (KEYRING_EVENTGRID_AUDIENCE). Leave empty for api://<client ID>. Set it to the client ID when the app registration issues v2 access tokens (requestedAccessTokenVersion 2), since aud is then the bare client ID. Use the same value as entraAudience in infra/alerts.')
param eventGridAudience string = ''

param tags object = {}

// A private config vault is only reachable from inside the VNet, so the
// app must be in it and DNS must resolve the private endpoint.
var privateVaultNeedsVnet = empty(configVaultPrivateEndpointSubnetId) || (!empty(vnetIntegrationSubnetId) && !empty(vaultPrivateDnsZoneId))
var privateVaultCheck = privateVaultNeedsVnet ? 'ok' : fail('configVaultPrivateEndpointSubnetId needs vnetIntegrationSubnetId and vaultPrivateDnsZoneId too, or the app can\'t reach its own secrets.')

var publicInbound = empty(inboundPrivateEndpointSubnetId)
// Keyring is never open to the whole internet: private, or trusted ranges only.
var ingressCheck = (!publicInbound || !empty(allowedIpRanges)) && length(filter(allowedIpRanges, r => !contains(r, '/') || contains(r, ',') || contains(r, ':') || parseCidr(r).cidr < 16)) == 0 ? 'ok' : fail('Keyring must not be reachable from the whole internet. Set inboundPrivateEndpointSubnetId for private access, or allowedIpRanges to the trusted ranges (each one IPv4 CIDR, /16 or narrower, no commas).')
var expiryCheck = !contains(map(split(toLower(notifyTypes), ','), t => trim(t)), 'expiry') ? 'ok' : fail('expiry in notifyTypes needs Event Grid to reach Keyring from the internet, which this template never allows. Send expiry email with infra/alerts and notifyVia = \'actionGroup\' instead (docs/alerts.md).')
var identityName = '${name}-id'
// Known before deployment, as the site's identity block needs.
var identityId = resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', identityName)

// The deployment name depends on the checks, so a failed check stops the
// deployment before anything is created.
module config '../modules/config-vault.bicep' = {
  name: '${name}-config${privateVaultCheck == 'ok' && ingressCheck == 'ok' && expiryCheck == 'ok' ? '' : '-invalid'}'
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

// The audit sink, in the workspace's own resource group and subscription,
// which may be an existing Sentinel workspace elsewhere.
var auditWorkspaceParts = split(useAuditSink ? auditWorkspaceId : '/subscriptions/none/resourceGroups/none/providers/Microsoft.OperationalInsights/workspaces/none', '/')
resource auditWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (useAuditSink) {
  scope: resourceGroup(auditWorkspaceParts[2], auditWorkspaceParts[4])
  name: auditWorkspaceParts[8]
}

module audit '../modules/audit-sink.bicep' = if (useAuditSink) {
  name: '${name}-audit-sink${auditCheck == 'ok' ? '' : '-invalid'}'
  scope: resourceGroup(auditWorkspaceParts[2], auditWorkspaceParts[4])
  params: {
    workspaceName: auditWorkspaceParts[8]
    location: auditWorkspace!.location
    ruleName: '${name}-audit'
    identityPrincipalId: config.outputs.identityPrincipalId
    retentionInDays: auditRetentionInDays
    tags: tags
  }
}

// Where the sink writes, from the module, whether reads need it, and where
// the audit page reads Keyring's own events.
var auditSettings = useAuditSink
  ? [
      { name: 'KEYRING_AUDIT_INGESTION_ENDPOINT', value: audit!.outputs.ingestionEndpoint }
      { name: 'KEYRING_AUDIT_DCR_ID', value: audit!.outputs.ruleImmutableId }
      { name: 'KEYRING_AUDIT_STREAM', value: audit!.outputs.streamName }
      { name: 'KEYRING_AUDIT_REQUIRED', value: string(auditRequired) }
      // Where the audit page's Keyring activity view reads the table, as
      // the signed-in person. The identity can't read it.
      { name: 'KEYRING_AUDIT_WORKSPACE_ID', value: auditWorkspaceId }
    ]
  : []

// Email, in Keyring's own resource group, sent as Keyring's managed
// identity. Never an access key or connection string.
var useNotify = !empty(notifyDomain)
var notifyCheck = useNotify || (empty(notifyTypes) && empty(notifyAdmins) && empty(notifyAllowedDomains)) ? 'ok' : fail('notifyTypes, notifyAdmins and notifyAllowedDomains need notifyDomain.')
module notify '../modules/notify.bicep' = if (useNotify) {
  name: '${name}-notify${notifyCheck == 'ok' ? '' : '-invalid'}'
  params: {
    name: name
    notifyDomain: notifyDomain
    dataLocation: notifyDataLocation
    identityPrincipalId: config.outputs.identityPrincipalId
    tags: tags
  }
}

var notifySettings = useNotify
  ? concat(
      [
        { name: 'KEYRING_NOTIFY_ACS_ENDPOINT', value: notify!.outputs.endpoint }
        { name: 'KEYRING_NOTIFY_SENDER', value: notify!.outputs.senderAddress }
      ],
      empty(notifyTypes) ? [] : [{ name: 'KEYRING_NOTIFY_TYPES', value: notifyTypes }],
      empty(notifyAdmins) ? [] : [{ name: 'KEYRING_NOTIFY_ADMINS', value: notifyAdmins }],
      empty(notifyAllowedDomains) ? [] : [{ name: 'KEYRING_NOTIFY_ALLOWED_DOMAINS', value: notifyAllowedDomains }],
      // Keyring refuses the list without expiry in the types.
      empty(eventGridSubscriptions) || !contains(map(split(toLower(notifyTypes), ','), t => trim(t)), 'expiry')
        ? []
        : [{ name: 'KEYRING_EVENTGRID_SUBSCRIPTIONS', value: eventGridSubscriptions }],
      empty(eventGridAudience) || !contains(map(split(toLower(notifyTypes), ','), t => trim(t)), 'expiry')
        ? []
        : [{ name: 'KEYRING_EVENTGRID_AUDIENCE', value: eventGridAudience }]
    )
  : []

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${name}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: skuName
    capacity: replicas
  }
  properties: {
    reserved: true
    zoneRedundant: zoneRedundant
  }
}

// Key Vault references: App Service resolves these with the identity, so
// the values never appear in settings or templates.
var clientSecretRef = '@Microsoft.KeyVault(VaultName=${config.outputs.vaultName};SecretName=entra-client-secret)'
var sessionSecretRef = '@Microsoft.KeyVault(VaultName=${config.outputs.vaultName};SecretName=session-secret)'

// How Keyring proves itself to Entra: the client secret, or (with
// useFederatedCredential) the app's managed identity. Keyring's one managed
// identity is also what the audit sink and email are sent with, so it is
// named whenever any of them needs it.
var useAuditSink = !empty(auditWorkspaceId)
var auditCheck = useAuditSink || !auditRequired ? 'ok' : fail('auditRequired needs auditWorkspaceId.')
var credentialSettings = concat(
  useFederatedCredential || useAuditSink || !empty(notifyDomain)
    ? [{ name: 'KEYRING_MANAGED_IDENTITY_CLIENT_ID', value: config.outputs.identityClientId }]
    : [],
  useFederatedCredential ? [] : [{ name: 'ENTRA_CLIENT_SECRET', value: clientSecretRef }]
)

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: name
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientCertEnabled: false
    clientAffinityEnabled: replicas > 1
    publicNetworkAccess: publicInbound ? 'Enabled' : 'Disabled'
    keyVaultReferenceIdentity: identityId
    virtualNetworkSubnetId: empty(vnetIntegrationSubnetId) ? null : vnetIntegrationSubnetId
    siteConfig: {
      linuxFxVersion: 'DOCKER|${image}'
      acrUseManagedIdentityCreds: useManagedIdentityForRegistry
      acrUserManagedIdentityID: useManagedIdentityForRegistry ? config.outputs.identityClientId : null
      alwaysOn: true
      ftpsState: 'Disabled'
      http20Enabled: true
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      healthCheckPath: '/healthz'
      // Only the trusted ranges reach the app and its deployment (SCM) site.
      ipSecurityRestrictionsDefaultAction: 'Deny'
      ipSecurityRestrictions: [for (range, i) in allowedIpRanges: {
        name: 'trusted-${i}'
        ipAddress: range
        action: 'Allow'
        priority: 100 + i
      }]
      scmIpSecurityRestrictionsUseMain: true
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      vnetRouteAllEnabled: !empty(vnetIntegrationSubnetId)
      // Every setting is listed here, so one added by hand in the portal is
      // removed by the next deployment. Optional ones are left out when
      // empty.
      appSettings: concat(
        [
          { name: 'WEBSITES_PORT', value: '3000' }
          { name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'false' }
          // Time to stop before the container is killed: Keyring needs up to
          // 40 seconds to finish requests and send queued email and audit
          // events (src/main.rs).
          { name: 'WEBSITES_CONTAINER_STOP_TIME_LIMIT', value: '60' }
          { name: 'ENTRA_TENANT_ID', value: tenantId }
          { name: 'ENTRA_CLIENT_ID', value: clientId }
          { name: 'APP_BASE_URL', value: appBaseUrl }
        ],
        credentialSettings,
        [
          { name: 'SESSION_SECRET', value: sessionSecretRef }
          { name: 'KEYRING_ALLOW_PURGE', value: string(allowPurge) }
        ],
        empty(apiScope) ? [] : [{ name: 'ENTRA_API_SCOPE', value: apiScope }],
        empty(logLevel) ? [] : [{ name: 'KEYRING_LOG_LEVEL', value: logLevel }],
        staleAfterDays == 0 ? [] : [{ name: 'KEYRING_STALE_AFTER_DAYS', value: string(staleAfterDays) }],
        expiryWarnDays == 0 ? [] : [{ name: 'KEYRING_EXPIRY_WARN_DAYS', value: string(expiryWarnDays) }],
        empty(logFormat) ? [] : [{ name: 'KEYRING_LOG_FORMAT', value: logFormat }],
        [{ name: 'KEYRING_TRUSTED_PROXY_HOPS', value: string(trustedProxyHops) }],
        empty(stepUpAuthContext) ? [] : [{ name: 'KEYRING_STEP_UP_AUTH_CONTEXT', value: stepUpAuthContext }],
        stepUpMaxAge == 0 ? [] : [{ name: 'KEYRING_STEP_UP_MAX_AGE', value: string(stepUpMaxAge) }],
        empty(requireReason) ? [] : [{ name: 'KEYRING_REQUIRE_REASON', value: requireReason }],
        empty(reasonTicketPattern) ? [] : [{ name: 'KEYRING_REASON_TICKET_PATTERN', value: reasonTicketPattern }],
        empty(passwordPolicy) ? [] : [{ name: 'KEYRING_PASSWORD_POLICY', value: passwordPolicy }],
        requireOwner ? [{ name: 'KEYRING_REQUIRE_OWNER', value: 'true' }] : [],
        sharing ? [{ name: 'KEYRING_SHARING', value: 'true' }] : [],
        shareMaxDays == 0 ? [] : [{ name: 'KEYRING_SHARE_MAX_DAYS', value: string(shareMaxDays) }],
        auditSettings,
        notifySettings
      )
    }
  }
}

// Turn off basic auth for deployments (FTP and the SCM site).
resource ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'scm'
  properties: {
    allow: false
  }
}

// Keyring writes its audit events (who revealed, changed or deleted what) to
// standard output. App Service keeps none of it by default, so send it to
// Log Analytics, or failing that keep a short log on the app's own storage.
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: 'keyring-logs'
  scope: site
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
      }
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
      }
    ]
  }
}

resource localLogs 'Microsoft.Web/sites/config@2024-04-01' = if (empty(logAnalyticsWorkspaceId)) {
  parent: site
  name: 'logs'
  properties: {
    applicationLogs: {
      fileSystem: {
        level: 'Information'
      }
    }
    httpLogs: {
      fileSystem: {
        enabled: true
        retentionInDays: 7
        retentionInMb: 35
      }
    }
  }
}

module inbound '../modules/private-endpoint.bicep' = if (!publicInbound) {
  name: '${name}-inbound-pe'
  params: {
    location: location
    name: '${name}-pe'
    targetId: site.id
    groupId: 'sites'
    subnetId: inboundPrivateEndpointSubnetId
    privateDnsZoneId: appPrivateDnsZoneId
    tags: tags
  }
}

output appName string = site.name
output checks string = '${privateVaultCheck} ${ingressCheck} ${expiryCheck} ${auditCheck} ${notifyCheck}'
output defaultHostName string = site.properties.defaultHostName
output configVaultName string = config.outputs.vaultName
output identityPrincipalId string = config.outputs.identityPrincipalId
@description('The audit data collection rule\'s immutable ID, when the audit sink is on.')
output auditRuleId string = useAuditSink ? audit!.outputs.ruleImmutableId : ''
@description('The Communication Services resource\'s endpoint, when email is on.')
output notifyEndpoint string = useNotify ? notify!.outputs.endpoint : ''

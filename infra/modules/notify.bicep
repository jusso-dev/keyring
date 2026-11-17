// Email for Keyring's notifications: an Email Communication Service, one
// domain (Azure-managed or your own), a Communication Services resource
// linked to it, and the one role Keyring's managed identity needs to send
// from that resource.
//
// Deployed into Keyring's own resource group, so these resources aren't
// shared with any other workload: the role below lets its holder change
// the Communication Services resource's settings, and nothing else may
// depend on them.
//
// The role. Azure has no "send email" action or data action under
// Microsoft.Communication, so the narrowest role that can send is a custom
// one with exactly two actions:
//   Microsoft.Communication/CommunicationServices/Read
//   Microsoft.Communication/CommunicationServices/Write
// Nothing else: no EmailServices permission, no ListKeys or RegenerateKey,
// no data action, no wildcard. With it, Keyring's identity can send email
// from this one resource and change this one resource's settings (its
// linked domains, for example). It can't read or regenerate the resource's
// keys and has no other Communication or Email Service access. The limits
// on misuse are Keyring's recipient allow-list and rate limit, ACS's logs
// and the Azure Activity Log. See docs/architecture.md, "Threat model".
//
// The role is assigned directly to the identity (principalType
// ServicePrincipal), at the scope of the one Communication Services
// resource. An assignment through an Entra group doesn't work for managed
// identities with ACS. The role's assignable scope is this resource group,
// the narrowest a role definition allows from Bicep here.
//
// No connection string, access key or SMTP password is read, output or
// set anywhere. Custom domain DNS (SPF, DKIM, DMARC) is not automated: see
// docs/deploy.md, "Email".
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Short name used in resource names, for example keyring-prod.')
param name string

@description('AzureManaged for an Azure-managed domain (xxxx.azurecomm.net), or your own domain name, such as mail.example.com, which you then verify with DNS records.')
param notifyDomain string

@description('Where ACS keeps its data at rest. One of the ACS data locations, such as Australia, Europe or United States.')
param dataLocation string = 'Australia'

@description('Principal (object) ID of Keyring\'s user-assigned managed identity. It gets the two-action custom role on the Communication Services resource, and nothing else.')
param identityPrincipalId string

param tags object = {}

var azureManaged = notifyDomain == 'AzureManaged'
var domainCheck = azureManaged || (length(notifyDomain) >= 3 && contains(notifyDomain, '.') && !contains(notifyDomain, '/') && !contains(notifyDomain, '@') && !contains(notifyDomain, ' ')) ? 'ok' : fail('notifyDomain must be AzureManaged or a domain name such as mail.example.com.')

resource emailService 'Microsoft.Communication/emailServices@2023-04-01' = {
  name: '${name}-email${domainCheck == 'ok' ? '' : '-invalid'}'
  location: 'global'
  tags: tags
  properties: {
    dataLocation: dataLocation
  }
}

// An Azure-managed domain must be named AzureManagedDomain.
resource domain 'Microsoft.Communication/emailServices/domains@2023-04-01' = {
  parent: emailService
  name: azureManaged ? 'AzureManagedDomain' : notifyDomain
  location: 'global'
  tags: tags
  properties: {
    domainManagement: azureManaged ? 'AzureManaged' : 'CustomerManaged'
    // Open and click tracking off: Keyring's mail carries no tracking.
    userEngagementTracking: 'Disabled'
  }
}

resource communication 'Microsoft.Communication/communicationServices@2023-04-01' = {
  name: '${name}-acs'
  location: 'global'
  tags: tags
  properties: {
    dataLocation: dataLocation
    linkedDomains: [domain.id]
  }
}

// Exactly two actions. See the note at the top.
resource sendRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, name, 'keyring-acs-email-sender')
  properties: {
    roleName: 'Keyring email sender (${name})'
    description: 'Send email from one Azure Communication Services resource. Read and Write on Communication Services only: Azure has no narrower permission for sending. No key, Email Service or data actions.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.Communication/CommunicationServices/Read'
          'Microsoft.Communication/CommunicationServices/Write'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [resourceGroup().id]
  }
}

resource sender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(communication.id, identityPrincipalId, sendRole.id)
  scope: communication
  properties: {
    roleDefinitionId: sendRole.id
    principalId: identityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

@description('KEYRING_NOTIFY_ACS_ENDPOINT')
output endpoint string = 'https://${communication.properties.hostName}'
@description('KEYRING_NOTIFY_SENDER: the DoNotReply sender ACS makes on each domain.')
output senderAddress string = 'DoNotReply@${domain.properties.mailFromSenderDomain}'
@description('For DNS: the records a custom domain needs are in the portal under the domain\'s Provision domains page.')
output domainName string = domain.name

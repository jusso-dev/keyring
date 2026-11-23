// Keyring on an Azure Virtual Machine (Trusted Launch or Confidential VM).
//
// Creates: a hardened Azure Linux 3.0 Gen2 VM (or a pre-baked Azure Compute
// Gallery image built with infra/vm/packer/keyring.pkr.hcl), a private VNet
// NIC (no public IP), a restrictive NSG allowing port 3000 only from your
// reverse proxy / Application Gateway subnet, and Keyring's own config vault
// and user-assigned managed identity (modules/config-vault.bicep).
//
// Keyring runs in IMDS mode (`KEYRING_MANAGED_IDENTITY_MODE=imds`), fetching
// its own startup secrets from the config vault into RAM-only tmpfs on start.
// The managed identity has ZERO access to user vaults; every call to user
// vaults uses the signed-in person's on-behalf-of token.
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'resourceGroup'

@description('Azure region. Defaults to the resource group\'s.')
param location string = resourceGroup().location

@description('Short name used in resource names, for example keyring-prod.')
@minLength(3)
@maxLength(18)
param name string

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

@description('Resource ID of the VNet subnet for the VM NIC. No public IP is created; front Keyring with Application Gateway, Front Door Private Link or an internal load balancer.')
param subnetId string

@description('CIDR prefix allowed to reach port 3000 on the VM (for example your Application Gateway or reverse proxy subnet).')
param allowedProxySourcePrefix string = 'VirtualNetwork'

@description('Optional Azure Compute Gallery image version resource ID built with infra/vm/packer/keyring.pkr.hcl. Leave empty to boot stock Azure Linux 3.0 Gen2.')
param galleryImageId string = ''

@description('VM SKU. Standard_DC2as_v5 supports both TrustedLaunch and ConfidentialVM (AMD SEV-SNP).')
param vmSize string = 'Standard_DC2as_v5'

@description('VM security posture: TrustedLaunch (Secure Boot + vTPM) or ConfidentialVM (AMD SEV-SNP encrypted memory, protecting in-memory OBO sessions from host inspection).')
@allowed([
  'TrustedLaunch'
  'ConfidentialVM'
])
param securityType string = 'TrustedLaunch'

@description('Confidential VM OS disk encryption mode when securityType is ConfidentialVM.')
@allowed([
  'VMGuestStateOnly'
  'DiskWithVMGuestState'
])
param confidentialDiskEncryptionType string = 'VMGuestStateOnly'

@description('Enable Azure Encryption at Host on the VM (requires registering Microsoft.Compute/EncryptionAtHost on the subscription; ignored for ConfidentialVM).')
param encryptionAtHost bool = false

@description('Availability zone for the VM (1, 2, or 3). Leave empty for non-zonal placement.')
@allowed([
  ''
  '1'
  '2'
  '3'
])
param availabilityZone string = ''

@description('SSH admin username on the VM.')
param adminUsername string = 'azureuser'

@description('SSH public key for emergency break-glass access. Password authentication is disabled.')
param sshPublicKey string

@description('Subnet for a private endpoint to the config vault. Leave empty to use its public endpoint.')
param configVaultPrivateEndpointSubnetId string = ''

@description('Private DNS zone ID for privatelink.vaultcore.azure.net, used with the config vault private endpoint.')
param vaultPrivateDnsZoneId string = ''

@description('Allow permanent deletes (purge) in Keyring.')
param allowPurge bool = false

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

@description('How log lines are written: text (the default) or json.')
@allowed([
  ''
  'text'
  'json'
])
param logFormat string = 'json'

@description('Conditional Access authentication context ID (c1 to c99). Leave empty to disable.')
param stepUpAuthContext string = ''

@description('Minutes since sign-in for sensitive actions. 0 disables.')
@minValue(0)
@maxValue(720)
param stepUpMaxAge int = 0

@description('Ask for a reason before reveal or all changes.')
@allowed([
  ''
  'off'
  'reveal'
  'all'
])
param requireReason string = ''

@description('Regular expression a ticket reference must match as a whole. Needs requireReason.')
@maxLength(200)
param reasonTicketPattern string = ''

@description('Password policy for typed Password or Login secrets.')
@maxLength(200)
// Non-secret rule string (for example "min=14,upper"), not a password.
#disable-next-line secure-secrets-in-params
param passwordPolicy string = ''

@description('Refuse to save items without an owner tag.')
param requireOwner bool = false

@description('Enable per-secret sharing (KEYRING_SHARING).')
param sharing bool = false

@description('Longest share duration in days (1 to 365). 0 keeps default 30.')
@minValue(0)
@maxValue(365)
param shareMaxDays int = 0

@description('Number of reverse proxies in front of Keyring adding to X-Forwarded-For.')
@minValue(0)
@maxValue(8)
param trustedProxyHops int = 1

@description('Days without a new value before items show the stale badge. 0 keeps default 365.')
@minValue(0)
@maxValue(3650)
param staleAfterDays int = 0

@description('Days before expiry when items count as expiring soon. 0 keeps default 30.')
@minValue(0)
@maxValue(365)
param expiryWarnDays int = 0

@description('Sign in to Entra with the VM managed identity federated credential instead of a client secret.')
param useFederatedCredential bool = true

@description('Resource ID of a Log Analytics workspace for Keyring\'s audit sink. Leave empty for no sink.')
param auditWorkspaceId string = ''

@description('Days the KeyringAudit_CL table keeps rows.')
@minValue(30)
@maxValue(730)
param auditRetentionInDays int = 365

@description('Refuse reveals while the audit sink is degraded. Needs auditWorkspaceId.')
param auditRequired bool = false

@description('ACS email domain: AzureManaged, a custom domain, or empty to disable email.')
param notifyDomain string = ''

@description('Where ACS keeps data at rest.')
param notifyDataLocation string = 'Australia'

@description('Comma-separated notice types.')
param notifyTypes string = ''

@description('Comma-separated admin email addresses.')
param notifyAdmins string = ''

@description('Comma-separated allowed recipient domains.')
param notifyAllowedDomains string = ''

@description('Comma-separated subscription IDs allowed to send Event Grid expiry events.')
param eventGridSubscriptions string = subscription().subscriptionId

@description('Expected aud claim on Event Grid tokens. Leave empty for api://<clientId>.')
param eventGridAudience string = ''

param tags object = {}

var identityName = '${name}-id'
var identityId = resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', identityName)
var useAuditSink = !empty(auditWorkspaceId)
var auditCheck = useAuditSink || !auditRequired ? 'ok' : fail('auditRequired needs auditWorkspaceId.')
var useNotify = !empty(notifyDomain)
var notifyCheck = useNotify || (empty(notifyTypes) && empty(notifyAdmins) && empty(notifyAllowedDomains)) ? 'ok' : fail('notifyTypes, notifyAdmins and notifyAllowedDomains need notifyDomain.')
var privateVaultOk = empty(configVaultPrivateEndpointSubnetId) || !empty(vaultPrivateDnsZoneId)
var privateVaultCheck = privateVaultOk ? 'ok' : fail('configVaultPrivateEndpointSubnetId needs vaultPrivateDnsZoneId.')
var isConfidential = securityType == 'ConfidentialVM'

module config '../modules/config-vault.bicep' = {
  name: '${name}-config${privateVaultCheck == 'ok' ? '' : '-invalid'}'
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

var notifyTypesList = map(split(toLower(notifyTypes), ','), t => trim(t))
var hasExpiryNotify = contains(notifyTypesList, 'expiry')

var envLines = concat(
  [
    'ENTRA_TENANT_ID=${tenantId}'
    'ENTRA_CLIENT_ID=${clientId}'
    'APP_BASE_URL=${appBaseUrl}'
    'KEYRING_LISTEN=0.0.0.0:3000'
    'KEYRING_ALLOW_PURGE=${allowPurge ? 'true' : 'false'}'
    'KEYRING_TRUSTED_PROXY_HOPS=${string(trustedProxyHops)}'
    'KEYRING_MANAGED_IDENTITY_MODE=imds'
    'KEYRING_MANAGED_IDENTITY_CLIENT_ID=${config.outputs.identityClientId}'
    'KEYRING_CONFIG_VAULT_URI=${config.outputs.vaultUri}'
    'KEYRING_USE_FEDERATED_CREDENTIAL=${useFederatedCredential ? 'true' : 'false'}'
  ],
  empty(apiScope) ? [] : ['ENTRA_API_SCOPE=${apiScope}'],
  empty(logLevel) ? [] : ['KEYRING_LOG_LEVEL=${logLevel}'],
  empty(logFormat) ? [] : ['KEYRING_LOG_FORMAT=${logFormat}'],
  staleAfterDays == 0 ? [] : ['KEYRING_STALE_AFTER_DAYS=${string(staleAfterDays)}'],
  expiryWarnDays == 0 ? [] : ['KEYRING_EXPIRY_WARN_DAYS=${string(expiryWarnDays)}'],
  empty(stepUpAuthContext) ? [] : ['KEYRING_STEP_UP_AUTH_CONTEXT=${stepUpAuthContext}'],
  stepUpMaxAge == 0 ? [] : ['KEYRING_STEP_UP_MAX_AGE=${string(stepUpMaxAge)}'],
  empty(requireReason) ? [] : ['KEYRING_REQUIRE_REASON=${requireReason}'],
  empty(reasonTicketPattern) ? [] : ['KEYRING_REASON_TICKET_PATTERN=${reasonTicketPattern}'],
  empty(passwordPolicy) ? [] : ['KEYRING_PASSWORD_POLICY=${passwordPolicy}'],
  requireOwner ? ['KEYRING_REQUIRE_OWNER=true'] : [],
  sharing ? ['KEYRING_SHARING=true'] : [],
  shareMaxDays == 0 ? [] : ['KEYRING_SHARE_MAX_DAYS=${string(shareMaxDays)}'],
  useAuditSink
    ? [
        'KEYRING_AUDIT_INGESTION_ENDPOINT=${audit!.outputs.ingestionEndpoint}'
        'KEYRING_AUDIT_DCR_ID=${audit!.outputs.ruleImmutableId}'
        'KEYRING_AUDIT_STREAM=${audit!.outputs.streamName}'
        'KEYRING_AUDIT_REQUIRED=${auditRequired ? 'true' : 'false'}'
        'KEYRING_AUDIT_WORKSPACE_ID=${auditWorkspaceId}'
      ]
    : [],
  useNotify
    ? concat(
        [
          'KEYRING_NOTIFY_ACS_ENDPOINT=${notify!.outputs.endpoint}'
          'KEYRING_NOTIFY_SENDER=${notify!.outputs.senderAddress}'
        ],
        empty(notifyTypes) ? [] : ['KEYRING_NOTIFY_TYPES=${notifyTypes}'],
        empty(notifyAdmins) ? [] : ['KEYRING_NOTIFY_ADMINS=${notifyAdmins}'],
        empty(notifyAllowedDomains) ? [] : ['KEYRING_NOTIFY_ALLOWED_DOMAINS=${notifyAllowedDomains}'],
        empty(eventGridSubscriptions) || !hasExpiryNotify ? [] : ['KEYRING_EVENTGRID_SUBSCRIPTIONS=${eventGridSubscriptions}'],
        empty(eventGridAudience) || !hasExpiryNotify ? [] : ['KEYRING_EVENTGRID_AUDIENCE=${eventGridAudience}']
      )
    : []
)

// Non-secret cloud-init payload writing /etc/keyring/keyring.env and starting
// keyring.service. Uses root:root in write_files (since write_files runs before
// user creation on stock images) and fixes ownership in runcmd so both Packer
// gallery images and stock Azure Linux 3.0 images boot cleanly. Secrets are
// never placed in customData; they are fetched at boot from the config vault
// into tmpfs RAM by fetch-config-secrets.sh.
var cloudInit = '#cloud-config\nwrite_files:\n  - path: /etc/keyring/keyring.env\n    owner: root:root\n    permissions: "0640"\n    content: |\n      ${join(envLines, '\n      ')}\nruncmd:\n  - id -u keyring >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin keyring\n  - chown root:keyring /etc/keyring /etc/keyring/keyring.env\n  - chmod 0750 /etc/keyring\n  - chmod 0640 /etc/keyring/keyring.env\n  - systemctl daemon-reload\n  - test -f /etc/systemd/system/keyring.service && systemctl enable --now keyring.service || true\n'

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-03-01' = {
  name: '${name}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowKeyringHttpFromProxy'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: allowedProxySourcePrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '3000'
        }
      }
      {
        name: 'AllowAzureLoadBalancerProbe'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'AzureLoadBalancer'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3000'
        }
      }
      {
        name: 'DenyAllOtherInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-03-01' = {
  name: '${name}-nic'
  location: location
  tags: tags
  properties: {
    networkSecurityGroup: {
      id: nsg.id
    }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: '${name}-vm'
  location: location
  tags: tags
  zones: empty(availabilityZone) ? null : [availabilityZone]
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityId}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: securityType
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
      encryptionAtHost: (!isConfidential && encryptionAtHost) ? true : null
    }
    storageProfile: {
      imageReference: empty(galleryImageId)
        ? {
            publisher: 'MicrosoftCBLMariner'
            offer: 'azure-linux-3'
            sku: 'azure-linux-3-gen2'
            version: 'latest'
          }
        : {
            id: galleryImageId
          }
      osDisk: {
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          securityProfile: isConfidential
            ? {
                securityEncryptionType: confidentialDiskEncryptionType
              }
            : null
        }
      }
    }
    osProfile: {
      computerName: name
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        patchSettings: {
          patchMode: 'AutomaticByPlatform'
          assessmentMode: 'AutomaticByPlatform'
        }
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

output vmId string = vm.id
output vmName string = vm.name
output privateIpAddress string = nic.properties.ipConfigurations[0].properties.privateIPAddress
output configVaultName string = config.outputs.vaultName
output identityClientId string = config.outputs.identityClientId
output identityPrincipalId string = config.outputs.identityPrincipalId
output checks string = '${privateVaultCheck} ${auditCheck} ${notifyCheck}'
output auditRuleId string = useAuditSink ? audit!.outputs.ruleImmutableId : ''
output notifyEndpoint string = useNotify ? notify!.outputs.endpoint : ''

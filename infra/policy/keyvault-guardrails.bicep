// Enterprise Azure Policy Initiative: Key Vault Guardrails for Keyring.
//
// Companion to Keyring's Vault Health checks (src/health.rs). Whereas Keyring
// detects misconfigured vaults across subscriptions, this Azure Policy
// Initiative enforces the same baseline controls at the subscription or
// management-group level using Microsoft's built-in Azure Policy definitions:
//   - Azure RBAC authorisation enabled
//   - Soft delete enabled
//   - Purge protection enabled
//   - Public network access disabled
//   - Firewall enabled (defaultAction = Deny)
//   - Diagnostic logs configured
//   - Defender for Key Vault enabled
//
// All effects default to 'Audit' for safe initial rollout; switch to 'Deny'
// once existing vaults pass Keyring's Vault Health page.
//
// Validation only in CI. Nothing here is deployed by this repo.

targetScope = 'subscription'

@description('Name of the Azure Policy initiative (policy set definition).')
param initiativeName string = 'keyring-keyvault-guardrails'

@description('Display name shown in Azure Policy.')
param displayName string = 'Keyring — Azure Key Vault Security Guardrails'

@description('Effect for the RBAC, soft delete, purge protection, firewall and public access policies.')
@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
param enforcementEffect string = 'Audit'

@description('Effect for audit-only policies (diagnostic logs and Defender for Key Vault).')
@allowed([
  'AuditIfNotExists'
  'Disabled'
])
param auditIfNotExistsEffect string = 'AuditIfNotExists'

@description('Assign the initiative to the current subscription immediately.')
param createAssignment bool = true

@description('Assignment display name when createAssignment is true.')
param assignmentName string = 'keyring-kv-guardrails'

// Built-in Azure Policy definition IDs (Microsoft official GUIDs).
var builtInPolicies = {
  rbacEnabled: '/providers/Microsoft.Authorization/policyDefinitions/12d4fa5e-1f9f-4c21-97a9-b99b3c6611b5'
  softDeleteEnabled: '/providers/Microsoft.Authorization/policyDefinitions/1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d'
  purgeProtectionEnabled: '/providers/Microsoft.Authorization/policyDefinitions/0b60c0b2-2dc2-4e1c-b5c9-abbed971de53'
  disablePublicAccess: '/providers/Microsoft.Authorization/policyDefinitions/405c5871-3e91-4644-8a63-58e19d68ff5b'
  firewallEnabled: '/providers/Microsoft.Authorization/policyDefinitions/55615ac9-af46-4a59-874e-391ccbaace49'
  diagnosticsEnabled: '/providers/Microsoft.Authorization/policyDefinitions/cf820ca0-f99e-4f3e-84fb-66e913812d21'
  defenderForKeyVault: '/providers/Microsoft.Authorization/policyDefinitions/0e6763cc-5078-4e64-889d-ff4d9a839047'
}

resource initiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: initiativeName
  properties: {
    displayName: displayName
    description: 'Enforces the Azure Key Vault security posture checks surfaced on Keyring\'s Vault Health dashboard (RBAC, soft delete, purge protection, network isolation, audit diagnostics and Defender for Key Vault).'
    policyType: 'Custom'
    metadata: {
      category: 'Key Vault'
      version: '1.0.0'
    }
    parameters: {
      enforcementEffect: {
        type: 'String'
        defaultValue: enforcementEffect
        allowedValues: [
          'Audit'
          'Deny'
          'Disabled'
        ]
        metadata: {
          displayName: 'Enforcement effect'
          description: 'Audit or Deny for Key Vault RBAC, soft delete, purge protection, firewall and public network access.'
        }
      }
      auditIfNotExistsEffect: {
        type: 'String'
        defaultValue: auditIfNotExistsEffect
        allowedValues: [
          'AuditIfNotExists'
          'Disabled'
        ]
        metadata: {
          displayName: 'Audit-if-not-exists effect'
          description: 'AuditIfNotExists or Disabled for diagnostic logs and Defender for Key Vault.'
        }
      }
    }
    policyDefinitions: [
      {
        policyDefinitionReferenceId: 'kv-rbac-enabled'
        policyDefinitionId: builtInPolicies.rbacEnabled
        parameters: {
          effect: {
            value: '[parameters(\'enforcementEffect\')]'
          }
        }
      }
      {
        policyDefinitionReferenceId: 'kv-soft-delete-enabled'
        policyDefinitionId: builtInPolicies.softDeleteEnabled
        parameters: {
          effect: {
            value: '[parameters(\'enforcementEffect\')]'
          }
        }
      }
      {
        policyDefinitionReferenceId: 'kv-purge-protection-enabled'
        policyDefinitionId: builtInPolicies.purgeProtectionEnabled
        parameters: {
          effect: {
            value: '[parameters(\'enforcementEffect\')]'
          }
        }
      }
      {
        policyDefinitionReferenceId: 'kv-disable-public-access'
        policyDefinitionId: builtInPolicies.disablePublicAccess
        parameters: {
          effect: {
            value: '[parameters(\'enforcementEffect\')]'
          }
        }
      }
      {
        policyDefinitionReferenceId: 'kv-firewall-enabled'
        policyDefinitionId: builtInPolicies.firewallEnabled
        parameters: {
          effect: {
            value: '[parameters(\'enforcementEffect\')]'
          }
        }
      }
      {
        policyDefinitionReferenceId: 'kv-diagnostics-enabled'
        policyDefinitionId: builtInPolicies.diagnosticsEnabled
        parameters: {
          effect: {
            value: '[parameters(\'auditIfNotExistsEffect\')]'
          }
        }
      }
      {
        policyDefinitionReferenceId: 'defender-for-keyvault'
        policyDefinitionId: builtInPolicies.defenderForKeyVault
        parameters: {
          effect: {
            value: '[parameters(\'auditIfNotExistsEffect\')]'
          }
        }
      }
    ]
  }
}

resource assignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (createAssignment) {
  name: assignmentName
  properties: {
    displayName: displayName
    policyDefinitionId: initiative.id
    enforcementMode: 'Default'
    parameters: {
      enforcementEffect: {
        value: enforcementEffect
      }
      auditIfNotExistsEffect: {
        value: auditIfNotExistsEffect
      }
    }
  }
}

output initiativeId string = initiative.id
output assignmentId string = createAssignment ? assignment.id : ''

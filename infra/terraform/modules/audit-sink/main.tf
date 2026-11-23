# Keyring's Log Analytics audit sink: custom table KeyringAudit_CL, Direct Data
# Collection Rule, and Monitoring Metrics Publisher role for Keyring's managed
# identity only.
#
# Column list matches `COLUMNS` in src/audit/sink.rs and
# infra/modules/audit-sink.bicep (checked by tests/audit_events.rs).

locals {
  stream_name = "Custom-KeyringAudit_CL"
  stream_columns = [
    { name = "time", type = "datetime" },
    { name = "EventId", type = "string" },
    { name = "SchemaVersion", type = "int" },
    { name = "Action", type = "string" },
    { name = "Outcome", type = "string" },
    { name = "ReasonCode", type = "string" },
    { name = "ActorObjectId", type = "string" },
    { name = "ActorTenantId", type = "string" },
    { name = "ActorUpn", type = "string" },
    { name = "SessionRef", type = "string" },
    { name = "ClientIp", type = "string" },
    { name = "UserAgent", type = "string" },
    { name = "Vault", type = "string" },
    { name = "ItemKind", type = "string" },
    { name = "ItemName", type = "string" },
    { name = "ItemVersion", type = "string" },
    { name = "KvRequestId", type = "string" },
    { name = "Reason", type = "string" },
    { name = "Ticket", type = "string" },
    { name = "Role", type = "string" },
    { name = "RoleScope", type = "string" },
    { name = "RoleDuration", type = "string" },
    { name = "NotifyType", type = "string" },
    { name = "NotifyRecipientCount", type = "int" },
    { name = "NotifyRecipients", type = "string" },
    { name = "NotifyEventCount", type = "int" },
    { name = "RevealLimitFrom", type = "string" },
    { name = "RevealLimitTo", type = "string" },
    { name = "SharePrincipalId", type = "string" },
    { name = "SharePrincipalType", type = "string" },
    { name = "ShareUntil", type = "string" },
    { name = "SharePath", type = "string" },
    { name = "WriterIdentityClientId", type = "string" },
    { name = "KeyringInstance", type = "string" },
    { name = "KeyringVersion", type = "string" },
  ]
  table_columns = concat(
    [{ name = "TimeGenerated", type = "datetime" }],
    [for c in local.stream_columns : c if c.name != "time"]
  )
}

resource "azapi_resource" "audit_table" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = "KeyringAudit_CL"
  parent_id = var.workspace_id

  body = {
    properties = {
      plan                 = "Analytics"
      retentionInDays      = var.retention_in_days
      totalRetentionInDays = var.retention_in_days
      schema = {
        name        = "KeyringAudit_CL"
        description = "Keyring's own audit events, written by Keyring's managed identity. Actor columns name the person who acted."
        columns     = local.table_columns
      }
    }
  }
}

resource "azapi_resource" "dcr" {
  type      = "Microsoft.Insights/dataCollectionRules@2023-03-11"
  name      = var.rule_name
  location  = var.location
  parent_id = var.workspace_resource_group_id
  tags      = var.tags

  body = {
    kind = "Direct"
    properties = {
      description = "Keyring audit events into KeyringAudit_CL"
      streamDeclarations = {
        (local.stream_name) = {
          columns = local.stream_columns
        }
      }
      destinations = {
        logAnalytics = [
          {
            name                = "workspace"
            workspaceResourceId = var.workspace_id
          }
        ]
      }
      dataFlows = [
        {
          streams      = [local.stream_name]
          destinations = ["workspace"]
          transformKql = "source | extend TimeGenerated = todatetime(['time']) | project-away ['time']"
          outputStream = local.stream_name
        }
      ]
    }
  }

  response_export_values = [
    "properties.endpoints.logsIngestion",
    "properties.immutableId",
  ]

  depends_on = [azapi_resource.audit_table]
}

resource "azurerm_role_assignment" "metrics_publisher" {
  scope                = azapi_resource.dcr.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = var.identity_principal_id
  principal_type       = "ServicePrincipal"
}

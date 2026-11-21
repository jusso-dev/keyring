# Keyring Solution for Microsoft Sentinel

This directory packages Keyring's Microsoft Sentinel content following the official [Azure/Azure-Sentinel Solutions](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions) Content Hub V3 layout.

## Contents

| Content type | Count | Location |
| --- | --- | --- |
| ASIM Audit Event parsers | 2 | `Parsers/` (`vimAuditEventKeyring.yaml`, `ASimAuditEventKeyring.yaml`) |
| Scheduled analytic rules | 8 | `Analytic Rules/` |
| Hunting queries | 6 | `Hunting Queries/` |
| Workbooks | 1 | `Workbooks/KeyringAudit.json` |
| Playbooks | 0 | None (Keyring uses Azure Monitor action groups and Event Grid in `infra/alerts/`) |
| V3 Content Hub package | 2 | `Package/mainTemplate.json`, `Package/createUiDefinition.json` |

## Prerequisites

1. A Log Analytics workspace with Microsoft Sentinel enabled.
2. The `KeyringAudit_CL` custom table and data collection rule deployed via `infra/modules/audit-sink.bicep`.
3. Azure Key Vault diagnostic settings (`AzureDiagnostics` or `AZKVAuditLogs`) if you plan to enable the two cross-log correlation rules (`KeyringAuditGap.yaml` and `KeyringUnmatchedSecretGet.yaml`).

## Deployment options

### Option 1: One-click ARM template (Bicep-compiled, parameterised rules)

Use the **Deploy to Azure** button in the repository [README](../../README.md#deploying-to-azure) or [docs/sentinel.md](../../docs/sentinel.md), which deploys `infra/sentinel/azuredeploy.json` (compiled from `infra/sentinel/main.bicep`) into an existing Log Analytics workspace. All analytic rules are created disabled by default and can be enabled and tuned via parameters.

### Option 2: Content Hub V3 solution package

Deploy `Package/mainTemplate.json` directly into the Log Analytics workspace's resource group:

```sh
az deployment group create \
  --resource-group <workspace-resource-group> \
  --template-file Solutions/Keyring/Package/mainTemplate.json \
  --parameters workspace=<workspace-name> workspace-location=<workspace-location>
```

This registers the Keyring Content Hub solution (`contentPackages`) and its 17 `contentTemplates` (parsers, analytic rule templates, hunting queries and workbook) in Microsoft Sentinel. Enable individual analytic rules from **Microsoft Sentinel > Analytics > Rule templates** after reviewing thresholds and setting `keyringIps` for the two Key Vault correlation rules.

## Defender XDR note

All Keyring detections query `KeyringAudit_CL` and Key Vault's Log Analytics diagnostic tables (`AzureDiagnostics` or `AZKVAuditLogs`). None of the detections run on native Microsoft Defender XDR Advanced Hunting tables (`DeviceEvents`, `EmailEvents`, `IdentityLogonEvents`, `CloudAppEvents` or `EntraIdSignInEvents`), so no separate `defender-xdr/` custom detection rules are shipped. Organisations using the unified Microsoft Defender portal with Microsoft Sentinel onboarded can run the Sentinel rules and hunting queries there directly.

## Regenerating and validating

Run the packaging and validation scripts after editing any file in `infra/sentinel/` or `Solutions/Keyring/`:

```sh
az bicep build --file infra/sentinel/main.bicep --outfile infra/sentinel/azuredeploy.json
python3 tools/sentinel/package.py
python3 tools/sentinel/validate.py
```

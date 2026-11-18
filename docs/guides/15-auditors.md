# For auditors

This walkthrough is for security, risk and audit staff who need to know what Keyring records, where to read it, and how to check that what Keyring shows matches Azure's own records. You can do all of it with read-only roles.

## Who this is for

| To do this | Azure role | Where |
| --- | --- | --- |
| See vaults and their settings | Reader | The vaults, their resource groups or subscriptions |
| Read Key Vault's audit log | Log Analytics Reader | The workspaces the vaults send their logs to |
| Read Keyring's own audit table | Log Analytics Reader (or a table-level read role on `KeyringAudit_CL`) | The workspace that holds it |

You don't need a Key Vault data role. Keyring never shows you a value you couldn't read in Azure.

## Before you start

Know the three records that come up:

| Record | What it holds | Where |
| --- | --- | --- |
| Key Vault's audit log | Every call Key Vault receives, from Keyring or anything else | The vault's Log Analytics workspace (`AzureDiagnostics` or `AZKVAuditLogs`) |
| Keyring's own audit events | One per thing a person does through Keyring, including what Keyring refused before asking Key Vault, and the reason and ticket they gave | Keyring's log, and the `KeyringAudit_CL` table when set up |
| Azure role assignments and PIM | Who can reach what, and who turned a role on | Azure, read live by the **Access** and **My access** pages |

## Steps

### Check the vaults are set up to be audited

1. Select **Vault health** and look at **Audit logs** for each vault. A vault that warns keeps no record of who read or changed what.

2. Check **Soft delete** and **Purge protection**: with both on, nothing can be destroyed before the retention period ends.

### Read what happened

3. Run the reports across vaults on **Audit** (see [11 Audit](11-audit.md)): **Secret values read**, **Private keys downloaded**, **Deletes, purges and recoveries**, **Refused requests** and **Activity by one person**. Select **Download CSV** to keep each one.

4. On a vault, open **Keyring activity** to see what Keyring refused before Key Vault was asked (such as a name that didn't match, purge turned off, a missing reason) and the reasons people gave.

### Check Keyring against Azure

5. Pick a Keyring event, such as a `secret.reveal`, and note its `kv_request_id`, vault, item and time.

6. Find Key Vault's own row for it: same vault, item and time, with `CorrelationId` equal to the `kv_request_id`. The caller in Key Vault's row is the person, not Keyring: Keyring calls Key Vault with the person's own token.

   Not yet confirmed on a real tenant: that the ID lands in `CorrelationId`. See the "Request ID joins to Key Vault's log" rows in [real-vault-checklist.md](../real-vault-checklist.md).

7. Look for Key Vault reads with no Keyring event. Those came from somewhere else (the Azure CLI, the portal, an app). Whoever runs Keyring can turn on a Microsoft Sentinel rule for this.

### Know what Keyring's own controls are and aren't

8. Read Keyring's checks as controls on the Keyring path only: a reason before a value is shown, step-up sign-in, the password policy, an owner on every item, typed confirmation before a delete, no permanent delete unless turned on. Key Vault doesn't know about them, so someone with the same Azure role can avoid them with the Azure CLI or the portal. Azure roles and Conditional Access on Key Vault itself are the hard controls.

## What Keyring checks

Keyring writes an audit event for every reveal, private key download, create, change, delete, recover, purge, sign-in, failed sign-in, sign-out and session expiry, and for every refusal. Events name the person by Entra object ID, tenant ID and sign-in name, from their verified sign-in. They never hold a secret value, a token or Azure's error message.

## What is recorded

Reading audit pages, reports and CSVs writes no Keyring audit event. Key Vault's log shows your Log Analytics queries only in the workspace's own query log.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| A report says some workspaces couldn't be read | You need Log Analytics Reader on each. They are listed, not hidden |
| Keyring's events and Key Vault's rows don't line up in time | Both are UTC. Key Vault's events can take minutes to arrive |
| A reason looks odd | Reasons are free text a person typed, with line breaks turned into spaces. Treat them as statements, not evidence |

## Related walkthroughs

- [11 Audit](11-audit.md)
- [14 Access review report](14-access-review.md)
- [00 About these walkthroughs](00-about.md)

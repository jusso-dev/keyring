# Alerts

Two optional sets of alerts, both run by Azure. Keyring stores no credentials and runs no background jobs for either.

- [Expiry alerts](#expiry-alerts): an email when a secret, certificate or key is about to expire (`infra/alerts/main.bicep`).
- [Access alerts](#access-alerts): an email when a watched secret is read, when anything is purged, or when one caller is refused again and again (`infra/alerts/access.bicep`).

## Expiry alerts

Keyring's expiry dashboard shows what's about to run out when you look. For an email (or a chat message) without looking, use Key Vault's own events. Keyring stores no credentials and runs no background jobs for this; Azure does all of it.

Alerts are **off by default**. Set them up per vault if you want them.

### How it works

Key Vault raises events for secrets, certificates and keys:

| Event | When |
| --- | --- |
| `SecretNearExpiry`, `CertificateNearExpiry`, `KeyNearExpiry` | About 30 days before the expiry date |
| `SecretExpired`, `CertificateExpired`, `KeyExpired` | On the expiry date |

`infra/alerts/main.bicep` subscribes to these with Event Grid and sends them to an Azure Monitor action group, which emails the addresses you give and can call a webhook (for example a Teams or Slack workflow).

Only items with an expiry date raise events. The expiry dashboard's "No expiry set" group shows what won't.

For keys, a rotation policy can send the near-expiry event earlier than 30 days. Set it on the key's Rotation policy page in Keyring.

### Set it up

You need Contributor (or EventGrid Contributor and Monitoring Contributor) on the vault's resource group.

Azure allows one Event Grid system topic per vault. If the vault already has one (the portal makes one when you open the vault's **Events** page, and other tools may too), the template must use it. Check:

```sh
az eventgrid system-topic list --resource-group <vault's resource group> \
  --query "[?source=='$(az keyvault show -n <vault> --query id -o tsv)'].name" -o tsv
```

If that prints a name, set `existingSystemTopicName` to it. If it prints nothing, leave it empty and the template makes one, in the vault's own region.

Copy the example next to the template (its `using` path is relative to the file; `.gitignore` keeps the copy out of git) and deploy:

```sh
cp infra/alerts/main.example.bicepparam infra/alerts/main.bicepparam
# Edit infra/alerts/main.bicepparam: the vault name, email addresses and existingSystemTopicName.

az deployment group create \
  --resource-group <vault's resource group> \
  --template-file infra/alerts/main.bicep \
  --parameters infra/alerts/main.bicepparam
```

To add a webhook, pass it on the command line so it isn't saved in a file:

```sh
  --parameters webhookUrl='https://...'
```

Repeat for each vault you want alerts for.

### Cost

Small. Event Grid charges per million operations (a vault raises a handful of these events a month), and action group emails are free up to a generous monthly limit. Check current [Event Grid](https://azure.microsoft.com/pricing/details/event-grid/) and [Azure Monitor](https://azure.microsoft.com/pricing/details/monitor/) pricing for your region.

### Turn it off

Delete what the template made, in the vault's resource group:

```sh
az eventgrid system-topic delete --name <vault>-events --resource-group <rg>
az monitor action-group delete --name <vault>-expiry --resource-group <rg>
```

Deleting the system topic also removes its event subscription. If you used `existingSystemTopicName`, keep that topic and delete only the subscription:

```sh
az eventgrid system-topic event-subscription delete --name expiry-to-action-group \
  --system-topic-name <existing topic> --resource-group <rg>
```

Nothing in Keyring needs changing.

## Access alerts

Keyring's audit page shows who read what when you look. To hear about it without looking, `infra/alerts/access.bicep` sets up Azure Monitor log search alert rules on the Log Analytics workspace the vault sends its audit logs to. Each rule is optional:

| Rule | Raises an alert when | Parameter |
| --- | --- | --- |
| Watched secret read | A `SecretGet` of a listed name, or a `CertificateGet` of a listed certificate | `watchedSecretNames` (empty turns it off) |
| Purge | Any `SecretPurge`, `CertificatePurge` or `KeyPurge` | `alertOnPurge` (default on) |
| Repeated refusals | One caller gets more than N refusals (HTTP 403) in 15 minutes | `refusedThreshold` (default 10, 0 turns it off) |

The read and purge rules run every 5 minutes and look at the last 5 minutes (`evaluationFrequency` changes both). The refusal rule runs every 5 minutes and looks at the last 15.

Each alert goes to an action group, which emails the addresses you give and can call a webhook. The alert says who (UPN, app ID or object ID, the same as the audit page), what (the operation and the item's name), the caller's IP address and the time window. Key Vault's log has no values in it, so no alert can carry one. A refusal alert names the caller, the operations refused and the addresses they came from.

Logs take a few minutes to reach the workspace, so an alert usually arrives 5 to 15 minutes after the read.

Reading a certificate's private key goes through its backing secret, which has the certificate's name. So listing a certificate's name in `watchedSecretNames` catches both a `CertificateGet` and a read of its key.

### Before you start

The vault must send its `AuditEvent` logs to a Log Analytics workspace (the same setting Keyring's audit page needs). Find the workspace and the table:

```sh
az monitor diagnostic-settings list \
  --resource $(az keyvault show -n <vault> --query id -o tsv) \
  --query "[].{workspace:workspaceId, destinationType:logAnalyticsDestinationType}" -o table
```

- `workspace` is `workspaceId` for the template.
- `destinationType` `Dedicated` means the resource-specific table: set `table = 'AZKVAuditLogs'`. Empty or `AzureDiagnostics` means `table = 'AzureDiagnostics'` (the default). The audit page makes the same choice, and the rules read the same columns it does.

### Roles

| Who | Role | Scope | Why |
| --- | --- | --- | --- |
| You, deploying | Monitoring Contributor | The resource group you deploy into | Creates the action group and the alert rules |
| You, deploying | Owner, User Access Administrator or Role Based Access Control Administrator | The workspace | Gives each rule's identity its role (next row) |
| Each alert rule's system-assigned identity | Log Analytics Reader | The workspace | The rule runs its query as this identity |

The rule identities are Azure Monitor's, not Keyring's. They can read the workspace's logs and nothing in any vault. Keyring never uses them.

### Set it up

Copy the example next to the template (its `using` path is relative to the file; `.gitignore` keeps the copy out of git) and deploy:

```sh
cp infra/alerts/access.example.bicepparam infra/alerts/access.bicepparam
# Edit infra/alerts/access.bicepparam: the vault name, workspace ID, table,
# watched names, threshold and email addresses.

az deployment group create \
  --resource-group <resource group for the alert rules> \
  --template-file infra/alerts/access.bicep \
  --parameters infra/alerts/access.bicepparam \
  --query properties.outputs.rules.value
```

The deployment prints each rule's name and `principalId`. Give each one Log Analytics Reader on the workspace:

```sh
az role assignment create --assignee-object-id <principalId> \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" --scope <workspace ID>
```

Until that is done, the rule can't read the logs and Azure Monitor shows it as failing. Role assignments can take a few minutes to apply.

To add a webhook, pass it on the command line so it isn't saved in a file:

```sh
  --parameters webhookUrl='https://...'
```

Deploy again with a changed list to watch other names. Repeat for each vault you want alerts for.

### Choosing the refusal threshold

Keyring itself gets 403s when someone opens a vault they lack a role on, so one person browsing can be refused a few times. The default of 10 in 15 minutes is meant to catch a script or a person trying names, not someone clicking around. Look at a normal week on the audit page (the Result column shows `Forbidden`) before you lower it.

### Cost

Log search alert rules are charged per rule and per time series they watch (each distinct caller, operation and item in a run counts as one). Check current [Azure Monitor](https://azure.microsoft.com/pricing/details/monitor/) pricing for your region. Action group emails are free up to a generous monthly limit.

### Turn it off

Delete what the template made:

```sh
az monitor scheduled-query delete --name <vault>-access-reads --resource-group <rg>
az monitor scheduled-query delete --name <vault>-access-purges --resource-group <rg>
az monitor scheduled-query delete --name <vault>-access-refusals --resource-group <rg>
az monitor action-group delete --name <vault>-access --resource-group <rg>
```

Then remove the rules' Log Analytics Reader assignments on the workspace (deleting a rule deletes its identity, which leaves the assignment orphaned until removed). Nothing in Keyring needs changing.

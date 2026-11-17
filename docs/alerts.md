# Alerts

Two optional sets of alerts, both run by Azure. Keyring stores no credentials and runs no background jobs for either.

- [Expiry alerts](#expiry-alerts): an email when a secret, certificate or key is about to expire (`infra/alerts/main.bicep`), from an action group or, with `notifyVia = 'keyring'`, [from Keyring](#expiry-emails-from-keyring).
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

## Expiry emails from Keyring

The same Key Vault events can go to Keyring instead of an action group. Keyring then sends the email itself, through Azure Communication Services, with its own subject (`[Keyring] Expiry: secret db-password in kv-prod`), a line such as "db-password in kv-prod expires on 17 Dec 2026 (in 30 days).", the version, the expiry time, a link to the item in Keyring and a link to the expiry dashboard. Set `notifyVia = 'keyring'` in `infra/alerts/main.bicep`.

Keyring never reads the vault for this, and its managed identity has no vault access. The event carries the vault, the object type, the name, the version and the expiry time, which is all the email needs. So no email ever holds a value.

### What you need first

- Email on in Keyring ([deploy.md, Email](deploy.md#email)) with `expiry` in `KEYRING_NOTIFY_TYPES`. Without it, `/hooks/eventgrid` answers 404.
- Keyring reachable from Event Grid over HTTPS at its public address. A Keyring that only takes private traffic can't receive these events.
- The one-off Entra steps below, done once per tenant.

### One-off Entra steps

Event Grid authenticates each delivery with a Microsoft Entra token for Keyring's app registration. Keyring refuses any token that isn't from Event Grid's own application (`4962773b-9cdb-44cf-a8bf-237846a00ab7` in Azure's public cloud) holding the app role `AzureEventGridSecureWebhookSubscriber` on Keyring's app registration. These commands, from Microsoft's "Secure WebHook delivery with Microsoft Entra ID", make that role and give it to Event Grid. Run them yourself, as someone who owns the app registration or holds Application Administrator. Keyring never runs them.

```sh
APP_ID=<Keyring's ENTRA_CLIENT_ID>
EVENT_GRID_APP=4962773b-9cdb-44cf-a8bf-237846a00ab7
ROLE=AzureEventGridSecureWebhookSubscriber

# 1. Keyring's app registration needs an app ID URI (api://<client ID>).
#    README step 3 sets it. Check:
az ad app show --id "$APP_ID" --query identifierUris

# 2. Add the app role. Keep any roles it already has:
#    merge this one into the list `az ad app show --id "$APP_ID" --query appRoles` prints.
ROLE_ID=$(uuidgen | tr 'A-Z' 'a-z')
az ad app update --id "$APP_ID" --app-roles "[{
  \"allowedMemberTypes\": [\"Application\", \"User\"],
  \"description\": \"Event Grid delivers Key Vault expiry events to Keyring\",
  \"displayName\": \"$ROLE\",
  \"id\": \"$ROLE_ID\",
  \"isEnabled\": true,
  \"value\": \"$ROLE\"
}]"

# 3. Make sure the tenant has Event Grid's service principal.
az ad sp show --id "$EVENT_GRID_APP" --query id -o tsv \
  || az ad sp create --id "$EVENT_GRID_APP"

# 4. Give Event Grid the role on Keyring's service principal.
EG_SP=$(az ad sp show --id "$EVENT_GRID_APP" --query id -o tsv)
KEYRING_SP=$(az ad sp show --id "$APP_ID" --query id -o tsv)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$EG_SP/appRoleAssignments" \
  --body "{\"principalId\": \"$EG_SP\", \"resourceId\": \"$KEYRING_SP\", \"appRoleId\": \"$ROLE_ID\"}"
```

Microsoft also asks that whoever creates the event subscription be an owner of Keyring's service principal, or hold the same app role. With a person deploying the template, assign the role to them as well (or add them as an owner):

```sh
ME=$(az ad signed-in-user show --query id -o tsv)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/users/$ME/appRoleAssignments" \
  --body "{\"principalId\": \"$ME\", \"resourceId\": \"$KEYRING_SP\", \"appRoleId\": \"$ROLE_ID\"}"
```

Step 2 allows the role for users as well as applications for this, as Microsoft's script does. What the role allows: creating or changing an Event Grid subscription that delivers to Keyring's webhook, from any topic, including a custom topic whose events the holder writes. Event Grid's token is then the same as for the real subscription. Keyring refuses events whose `topic` isn't a Key Vault (see [What Keyring checks](#what-keyring-checks)), but anyone holding the role, or owning Keyring's service principal, can still make subscriptions to the webhook, so keep that list short.

**Once the subscription exists, remove your own role assignment.** Microsoft checks it only when a subscription is created or changed, so deliveries carry on without it. Assign it again for the next change, and remove it after:

```sh
ASSIGNMENT=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/users/$ME/appRoleAssignments" \
  --query "value[?resourceId=='$KEYRING_SP' && appRoleId=='$ROLE_ID'].id | [0]" -o tsv)
az rest --method DELETE \
  --uri "https://graph.microsoft.com/v1.0/users/$ME/appRoleAssignments/$ASSIGNMENT"
```

Event Grid's own assignment (step 4) stays: it is what gets the token. The app registration stays delegated-only for people: the role isn't an application permission on any API, and Keyring's identity still has no vault access.

### What Keyring checks

Every delivery, before anything in its body is read:

| Check | Refused with |
| --- | --- |
| A bearer token, RS256 only (never `none` or HS*), signed by one of the tenant's published keys (the same cached key set as sign-in; a key Keyring hasn't seen makes it fetch the keys again, at most once every 5 minutes whatever the token says, since claims are read before the signature) | 401 |
| `iss` is the tenant's v1 (`https://sts.windows.net/<tenant>/`) or v2 (`https://login.microsoftonline.com/<tenant>/v2.0`) issuer, and `tid` is the tenant | 401 |
| `aud` is exactly `KEYRING_EVENTGRID_AUDIENCE`, or `api://<ENTRA_CLIENT_ID>` when that's unset. Set the template's `entraAudience` to the same | 401 |
| `exp` and `nbf`, with a minute's leeway | 401 |
| `appid` (v1) or `azp` (v2) is Event Grid's application, and `roles` has `AzureEventGridSecureWebhookSubscriber`. No `scp` (a person's token) | 401 |
| A request whose token failed takes one from its own counter, 60 a minute. Under it: 401 and an audit event. Over it: 429 with no audit event; a `warn` line, written by the first bad token of a later minute, says how many were dropped. As on every route, each request still gets one line in the request log (method, path and status only). Bad tokens never touch Event Grid's budget below | 401, or 429 over the counter |
| At most 120 deliveries a minute whose token passed | 429 |
| `Content-Type: application/json`, POST only, at most 1 MB (refused before it is read) | 415, 405, 413 |

A 401 has no body. The log and the audit event get only a fixed code such as `token_audience`, never the token, its claims, the body or a header.

Then the delivery. It must be a JSON array of 1 to 50 events in the Event Grid schema, each one of the six expiry events with a vault and name that pass Key Vault's naming rules, an object type that matches, a 32-digit version and a numeric `EXP`. Its `topic` must be the Key Vault it names: `/subscriptions/<GUID>/resourceGroups/<name>/providers/Microsoft.KeyVault/vaults/<VaultName>`, compared in any case, with no extra or empty segments. Event Grid stamps `topic` itself on a Key Vault system topic's events, and a publisher can't write it; an event sent through a custom topic carries the custom topic's own ID and is refused (`bad_topic`). One bad event refuses the whole delivery with 400 and sends nothing, so a delivery is never half sent. Event Grid doesn't retry a 400; it dead-letters it if you gave a container. Nothing else from an event, such as its `subject`, `topic` or `Id` URL, ever reaches an email or a log line.

The subscription's validation handshake is answered only with a valid token, and Keyring echoes the validation code only if it is 1 to 64 letters, digits and hyphens.

### Who gets the email

- `keyringRecipients` in the template becomes the subscription's `keyring-notify` delivery header. Keyring uses it **only when `KEYRING_NOTIFY_ALLOWED_DOMAINS` is set**, takes at most 10 addresses, parses each strictly and drops any outside the allowed domains. A malformed header refuses the delivery with 400.
- Otherwise, or with no header, the email goes to `KEYRING_NOTIFY_ADMINS`.

Without an allow-list, whoever can change an Event Grid subscription could send Keyring's expiry notices anywhere, so the header is ignored. Each address is still held to `KEYRING_NOTIFY_RATE_PER_HOUR` (default 20 an hour per address). When nobody can be sent an event and at least one allowed recipient is over it, the delivery is answered 503 and the event isn't remembered, so Event Grid sends it again later (its 24 hours of retries cover the one-hour window for one event; if far more items expire together than the limit allows in a day, the rest are dead-lettered, so raise the setting). With no admins and no usable header there is nobody to send to: the delivery is answered 200 and nothing is sent, and Keyring warns about that at start. When some recipients are over it and others aren't, the email goes to those under it and counts as sent: it isn't retried, or they would get it twice, so the others miss that one.

An item's `owner` and `notify` tags can't be used here: reading them needs vault access, which Keyring's identity doesn't have and won't be given. A daily digest, read as a signed-in person, is a possible later option for per-item recipients.

### Repeats and answers

Keyring remembers each item, version and event type it has sent for 24 hours, in memory, and doesn't send it again in that time, so Event Grid's retries and repeats send one email. A restart forgets this, so one repeat can follow a restart. At most 10,000 are remembered. When that is full of entries less than a day old, a new event isn't sent and the delivery is answered 503, so Event Grid tries again later; entries are never dropped early, so filling the map can't make a repeat go out.

| Answer | When | Event Grid |
| --- | --- | --- |
| 200 | Every event queued, already sent, or with no allowed recipient | Done |
| 400 | Anything malformed, or an event whose `topic` isn't its Key Vault | Dead-letters it, if a container is set |
| 401 | A token check failed | Not retried for a webhook: dead-letters it if a container is set, otherwise drops it. So a wrong audience or a missing role loses events until it is fixed |
| 404 | Email off, or `expiry` not in `KEYRING_NOTIFY_TYPES` | Retries, then dead-letters |
| 429 | Over the 120 a minute for good tokens, or over the 60 a minute for bad ones | Retries later |
| 503 | Keyring's email queue (1,000) or the repeat map is full, or every recipient is over `KEYRING_NOTIFY_RATE_PER_HOUR` | Retries later. Events already queued are remembered, so the retry sends only the rest |

Each request that reaches the token check writes one `notify.webhook` audit event with the outcome, a reason code and `notify_event_count`, with no address, except requests over the 60 a minute for bad tokens, which write none. Each email then gets its own `notify.sent` or `notify.failed`.

### Troubleshooting

- **Every delivery is refused with `token_audience`.** If Keyring's app registration issues v2 access tokens (`requestedAccessTokenVersion` 2 in its manifest), `aud` is the client ID GUID, not `api://<client ID>`, so the default audience refuses every delivery. Set `KEYRING_EVENTGRID_AUDIENCE` to the client ID, or leave the registration on v1 tokens. The real-tenant checklist has a row to note which form arrives.
- **Deliveries refused with `bad_topic`.** The subscription isn't on the vault's own Key Vault system topic. Make it with `infra/alerts/main.bicep`, which uses the vault's system topic.
- **`recipient_rate_limited` with 503.** Every recipient had `KEYRING_NOTIFY_RATE_PER_HOUR` emails in the last hour. Event Grid retries; raise the setting if many items expire together.

### Set it up

```sh
cp infra/alerts/keyring.example.bicepparam infra/alerts/keyring.bicepparam
# Edit: vaultName, keyringBaseUrl, entraAudience, keyringRecipients,
# deadLetterContainerId and existingSystemTopicName.

az deployment group create \
  --resource-group <vault's resource group> \
  --template-file infra/alerts/main.bicep \
  --parameters infra/alerts/keyring.bicepparam
```

Event Grid sends the validation handshake when the subscription is made, so Keyring must already be running with `expiry` on. The template makes the subscription `expiry-to-keyring` with Entra authentication (`azureActiveDirectoryTenantId` and `azureActiveDirectoryApplicationIdOrUri`), the `keyring-notify` header when `keyringRecipients` is set, up to 10 events a delivery, retries for 24 hours, and dead-lettering to `deadLetterContainerId` when given. Event Grid's system topic needs **Storage Blob Data Contributor** on that container to write to it; that is Event Grid's identity, not Keyring's.

To switch a vault from the action group to Keyring, deploy with `notifyVia = 'keyring'`, then delete the old `expiry-to-action-group` subscription and the `<vault>-expiry` action group. To turn it off, delete the `expiry-to-keyring` subscription.

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

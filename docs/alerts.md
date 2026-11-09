# Expiry alerts

Keyring's expiry dashboard shows what's about to run out when you look. For an email (or a chat message) without looking, use Key Vault's own events. Keyring stores no credentials and runs no background jobs for this; Azure does all of it.

Alerts are **off by default**. Set them up per vault if you want them.

## How it works

Key Vault raises events for secrets, certificates and keys:

| Event | When |
| --- | --- |
| `SecretNearExpiry`, `CertificateNearExpiry`, `KeyNearExpiry` | About 30 days before the expiry date |
| `SecretExpired`, `CertificateExpired`, `KeyExpired` | On the expiry date |

`infra/alerts/main.bicep` subscribes to these with Event Grid and sends them to an Azure Monitor action group, which emails the addresses you give and can call a webhook (for example a Teams or Slack workflow).

Only items with an expiry date raise events. The expiry dashboard's "No expiry set" group shows what won't.

For keys, a rotation policy can send the near-expiry event earlier than 30 days. Set it on the key's Rotation policy page in Keyring.

## Set it up

You need Contributor (or Event Grid Contributor and Monitoring Contributor) on the vault's resource group.

```sh
cp infra/alerts/main.example.bicepparam alerts.bicepparam
# Edit alerts.bicepparam: the vault name and email addresses.

az deployment group create \
  --resource-group <vault's resource group> \
  --template-file infra/alerts/main.bicep \
  --parameters alerts.bicepparam
```

To add a webhook, pass it on the command line so it isn't saved in a file:

```sh
  --parameters webhookUrl='https://...'
```

Repeat for each vault you want alerts for.

## Cost

Small. Event Grid charges per million operations (a vault raises a handful of these events a month), and action group emails are free up to a generous monthly limit. Check current [Event Grid](https://azure.microsoft.com/pricing/details/event-grid/) and [Azure Monitor](https://azure.microsoft.com/pricing/details/monitor/) pricing for your region.

## Turn it off

Delete the two resources the template made, in the vault's resource group:

```sh
az eventgrid system-topic delete --name <vault>-events --resource-group <rg>
az monitor action-group delete --name <vault>-expiry --resource-group <rg>
```

Deleting the system topic also removes its event subscription. Nothing in Keyring needs changing.

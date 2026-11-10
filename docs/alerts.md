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

## Cost

Small. Event Grid charges per million operations (a vault raises a handful of these events a month), and action group emails are free up to a generous monthly limit. Check current [Event Grid](https://azure.microsoft.com/pricing/details/event-grid/) and [Azure Monitor](https://azure.microsoft.com/pricing/details/monitor/) pricing for your region.

## Turn it off

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

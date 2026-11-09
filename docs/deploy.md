# Deploying Keyring

This guide takes you from nothing to a running Keyring in Azure, on App Service or Container Apps. Allow about an hour the first time.

Nothing in this repository deploys anything by itself. You run each step.

## Before you start

You'll need:

- An Azure subscription and a resource group you can deploy to (Contributor, plus User Access Administrator or Owner so the template can give Keyring's identity read access to its own config vault).
- Permission to create an app registration in Entra ID, and an admin who can grant consent.
- The Azure CLI with Bicep (`az bicep install`).
- A container registry Keyring's image can be pulled from, or a public image.

Decide:

- **App Service or Container Apps.** App Service is simplest. Container Apps suits teams already using it, and supports internal-only ingress.
- **Public or private.** If any vaults people need are private, Keyring must run inside a network that can reach them. Read [private-vaults.md](private-vaults.md) first.
- **The address people will use**, for example `https://keyring.example.com`. You need it for the app registration.

## 1. Build and push the image

```sh
docker build -t <registry>/keyring:<version> .
docker push <registry>/keyring:<version>
docker buildx imagetools inspect <registry>/keyring:<version>   # note the sha256 digest
```

Use the image by digest (`<registry>/keyring@sha256:...`) in the templates, so a deployment always runs exactly what you tested.

If the registry is private, give the app's managed identity the `AcrPull` role on it after step 3, or configure registry credentials in the portal.

## 2. Register the app in Entra ID

Follow [Entra app registration in the README](../README.md#entra-app-registration). For a deployment, the redirect URI is `https://<your-host>/auth/callback`.

Note the tenant ID, client ID and client secret value.

## 3. Deploy

Copy the example parameters and fill them in. They hold no secrets.

App Service:

```sh
cp infra/app-service/main.example.bicepparam keyring.bicepparam
# Edit: name, image, clientId, appBaseUrl, configVaultName
az deployment group create -g <rg> -f infra/app-service/main.bicep -p keyring.bicepparam
```

Container Apps:

```sh
cp infra/container-apps/main.example.bicepparam keyring.bicepparam
# Edit: name, image, clientId, appBaseUrl, configVaultName, ingress
az deployment group create -g <rg> -f infra/container-apps/main.bicep -p keyring.bicepparam
```

This creates:

| Resource | Why |
| --- | --- |
| Config vault | Holds Keyring's client secret and session secret. RBAC, soft delete and purge protection on |
| Managed identity | Lets the app read those two secrets. **It has no access to any other vault.** Every call to people's vaults uses the signed-in person's own token |
| App Service plan and web app, or Log Analytics, Container Apps environment and app | Runs the container on port 3000, with `/healthz` probes and HTTPS only |
| Optional private endpoints, VNet integration | See [private-vaults.md](private-vaults.md) |

The app won't start properly yet: its secrets are empty.

### Parameters

App Service (`infra/app-service/main.bicep`):

| Parameter | What it's for | Default |
| --- | --- | --- |
| `name` | Short name used in resource names | Required |
| `image` | Image by digest | Required |
| `clientId` | App registration's client ID | Required |
| `appBaseUrl` | Public URL, matching the redirect URI | Required |
| `configVaultName` | Globally unique vault name | Required |
| `tenantId` | Entra tenant | The subscription's tenant |
| `location` | Region | The resource group's |
| `skuName` | Plan size | `P0v3` |
| `allowPurge` | Allow permanent deletes | `false` |
| `vnetIntegrationSubnetId` | Outbound VNet integration, to reach private vaults | None |
| `inboundPrivateEndpointSubnetId`, `appPrivateDnsZoneId` | Private inbound access only | None (public) |
| `configVaultPrivateEndpointSubnetId`, `vaultPrivateDnsZoneId` | Make the config vault private | None |
| `tags` | Tags on everything | None |

Container Apps (`infra/container-apps/main.bicep`) has the same required parameters, plus:

| Parameter | What it's for | Default |
| --- | --- | --- |
| `ingress` | `external` (internet) or `internal` (VNet only) | `external` |
| `infrastructureSubnetId` | Put the environment in your VNet. Needed for `internal` and for private vaults | None |
| `replicas` | Copies to run. Sessions are in memory, so more than 1 turns on sticky sessions | `1` |

## 4. Set the secrets

Give yourself Key Vault Secrets Officer on the new config vault, then:

```sh
az keyvault secret set --vault-name <configVaultName> --name entra-client-secret --value '<client secret value>'
az keyvault secret set --vault-name <configVaultName> --name session-secret --value "$(openssl rand -base64 48)"
```

Run these from a shell that doesn't save history, or clear it afterwards. Then restart the app:

```sh
az webapp restart -g <rg> -n <name>                                   # App Service
az containerapp revision restart -g <rg> -n <name> --revision <rev>   # Container Apps
```

## 5. Point your address at it

Add a custom domain and certificate for `appBaseUrl` (App Service: **Custom domains**; Container Apps: **Custom domains**), or set `appBaseUrl` to the default host name the deployment printed. It must match the redirect URI exactly.

## 6. Check it

1. Open `https://<your-host>/healthz`. It should say `ok`.
2. Open `https://<your-host>/` and sign in.
3. The vault list should show vaults you have Reader on. Open one and check you can see its secrets.

If something's wrong, see [troubleshooting.md](troubleshooting.md).

## Updating

Build and push a new image, change `image` to its digest, and run the same `az deployment group create`. Sessions are in memory, so people are signed out on each restart.

## Removing

Delete the resource group, or the resources listed in step 3. The config vault has purge protection, so its name stays reserved for 90 days.

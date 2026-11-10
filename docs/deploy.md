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

- **App Service or Container Apps.** App Service is simplest. Container Apps suits teams already using it, and supports an internal-only environment.
- **Public or private.** If any vaults people need are private, Keyring must run inside a network that can reach them. Read [private-vaults.md](private-vaults.md) first.
- **The address people will use**, for example `https://keyring.example.com`. You need it for the app registration. Keyring must be at the root of that host; it can't run under a path such as `/keyring`.

## 1. Build and push the image

Azure runs `linux/amd64` images. Build for that platform even on an Apple Silicon Mac, or the container won't start ("exec format error"):

```sh
docker buildx build --platform linux/amd64 \
  --build-arg VERSION=<version> --build-arg VCS_REF=$(git rev-parse HEAD) \
  -t <registry>/keyring:<version> --push .
docker buildx imagetools inspect <registry>/keyring:<version>   # note the sha256 digest
```

Use the image by digest (`<registry>/keyring@sha256:...`) in the templates, so a deployment always runs exactly what you tested.

**Private Azure Container Registry:** the app pulls with its managed identity. Set `useManagedIdentityForRegistry = true` (App Service) or `registryServer = '<name>.azurecr.io'` (Container Apps), and give the identity `AcrPull` on the registry. The identity exists after the config-only deploy in step 3, so grant AcrPull between the two runs:

```sh
az role assignment create --role AcrPull \
  --assignee-object-id <identityPrincipalId output> --assignee-principal-type ServicePrincipal \
  --scope $(az acr show -n <registry name> --query id -o tsv)
```

## 2. Register the app in Entra ID

Follow [Entra app registration in the README](../README.md#entra-app-registration). For a deployment, register two **Web** redirect URIs:

- `https://<your-host>/auth/callback`, for sign-in
- `https://<your-host>/auth/signed-out`, so Entra sends people back to Keyring after they sign out

Note the tenant ID, client ID and client secret value.

## 3. Deploy

Copy the example parameters next to the template and fill them in. The copy must stay in the template's folder, because its `using './main.bicep'` line is relative to the file. `.gitignore` keeps `*.bicepparam` files (other than the examples) out of git, since yours will hold your tenant's IDs and names. They hold no secrets. If you don't have a custom domain yet, set `appBaseUrl` to the address the app will get (`https://<name>.azurewebsites.net` for App Service), or deploy once, read the `defaultHostName` or `fqdn` output, then set it and deploy again.

App Service:

```sh
cp infra/app-service/main.example.bicepparam infra/app-service/main.bicepparam
# Edit: name, image, clientId, appBaseUrl, configVaultName, and logAnalyticsWorkspaceId (see Logs below)
az deployment group create -g <rg> -f infra/app-service/main.bicep -p infra/app-service/main.bicepparam
```

App Service starts the app straight away. Until step 4 sets the secrets, Keyring refuses to start (it won't run with an unresolved Key Vault reference), so expect it to show as unhealthy until then.

Container Apps reads the secrets when it creates the app, so deploy in two runs:

```sh
cp infra/container-apps/main.example.bicepparam infra/container-apps/main.bicepparam
# Edit: name, image, clientId, appBaseUrl, configVaultName, ingress

# First run: only the config vault and identity.
az deployment group create -g <rg> -f infra/container-apps/main.bicep -p infra/container-apps/main.bicepparam -p configOnly=true
# Now do step 4 (set the secrets), and AcrPull if you use a private registry.
# Second run: the app.
az deployment group create -g <rg> -f infra/container-apps/main.bicep -p infra/container-apps/main.bicepparam
```

This creates:

| Resource | Why |
| --- | --- |
| Config vault | Holds Keyring's client secret and session secret. RBAC, soft delete and purge protection on |
| Managed identity | Lets the app read those two secrets. **It has no access to any other vault.** Every call to people's vaults uses the signed-in person's own token |
| App Service plan and web app, or Log Analytics, Container Apps environment and app | Runs the container on port 3000, with `/healthz` probes and HTTPS only |
| Optional private endpoints, VNet integration | See [private-vaults.md](private-vaults.md) |

Until the secrets are set in step 4, the app has nothing to start with.

### Internal Container Apps

With `ingress = 'internal'` the environment only gets a private address in your VNet. The app still accepts traffic from outside the environment, so browsers in that VNet (or networks peered with it, or connected over VPN) can reach it; the internet can't.

The environment's default domain, for example `<random>.<region>.azurecontainerapps.io`, has no public DNS record. People's machines need a private DNS zone of that name with a wildcard record pointing at the environment's address. Either:

- set `privateDnsVnetId` to the VNet people's DNS is resolved in (often a hub VNet), and the template creates and links the zone, or
- do it yourself from the `defaultDomain` and `staticIp` outputs:

  ```sh
  az network private-dns zone create -g <rg> -n <defaultDomain>
  az network private-dns record-set a add-record -g <rg> -z <defaultDomain> -n '*' -a <staticIp>
  az network private-dns link vnet create -g <rg> -z <defaultDomain> -n keyring-vnet -v <VNet ID> -e false
  ```

With a custom domain, point its DNS name at `staticIp` instead, in whatever DNS serves that name inside your network.

### Parameters

App Service (`infra/app-service/main.bicep`):

| Parameter | What it's for | Default |
| --- | --- | --- |
| `name` | Short name used in resource names | Required |
| `image` | Image by digest | Required |
| `useManagedIdentityForRegistry` | Pull from a private ACR with the app's identity | `false` |
| `clientId` | App registration's client ID | Required |
| `appBaseUrl` | Public URL, matching the redirect URI | Required |
| `configVaultName` | Globally unique vault name | Required |
| `tenantId` | Entra tenant | The subscription's tenant |
| `location` | Region | The resource group's |
| `skuName` | Plan size. Basic (`B1`) and above support VNet integration and private endpoints | `P0v3` |
| `allowPurge` | Allow permanent deletes | `false` |
| `apiScope` | Sets `ENTRA_API_SCOPE`, if your app registration's scope isn't `api://<clientId>/access_as_user` | None |
| `logLevel` | Sets `KEYRING_LOG_LEVEL` | None (`info`) |
| `logAnalyticsWorkspaceId` | Send the container's output and HTTP logs to this workspace (see Logs) | None (7 days on the app's own storage) |
| `vnetIntegrationSubnetId` | Outbound VNet integration, to reach private vaults | None |
| `inboundPrivateEndpointSubnetId`, `appPrivateDnsZoneId` | Private inbound access only | None (public) |
| `configVaultPrivateEndpointSubnetId`, `vaultPrivateDnsZoneId` | Make the config vault private. Needs `vnetIntegrationSubnetId` too (the deployment stops if not) | None |
| `tags` | Tags on everything | None |

Container Apps (`infra/container-apps/main.bicep`) has the same required parameters, plus:

| Parameter | What it's for | Default |
| --- | --- | --- |
| `ingress` | `external` (public address) or `internal` (private address in the VNet only) | `external` |
| `privateDnsVnetId` | With `internal`: create the private DNS zone for the environment's default domain, linked to this VNet | None |
| `registryServer` | Private ACR login server, pulled with the app's identity | None (public image) |
| `configOnly` | Deploy only the config vault and identity (first of two runs) | `false` |
| `infrastructureSubnetId` | Put the environment in your VNet. Needed for `internal` and for private vaults | None |
| `replicas` | Copies to run. Sessions are in memory, so more than 1 turns on sticky sessions | `1` |

Container Apps takes `apiScope` and `logLevel` too, but not `skuName`, `logAnalyticsWorkspaceId` or the App Service network parameters. It always sends logs to the workspace it creates.

Both templates list every app setting, so a setting added by hand in the portal is removed by the next deployment. Use the parameters instead.

## 4. Set the secrets

Give yourself Key Vault Secrets Officer on the new config vault:

```sh
az role assignment create --role "Key Vault Secrets Officer" --assignee <your sign-in name> \
  --scope $(az keyvault show -n <configVaultName> --query id -o tsv)
```

Role assignments can take a few minutes. Then set the two secrets:

```sh
az keyvault secret set --vault-name <configVaultName> --name entra-client-secret --value '<client secret value>'
az keyvault secret set --vault-name <configVaultName> --name session-secret --value "$(openssl rand -base64 48)"
```

Run these from a shell that doesn't save history, or clear it afterwards. If you made the config vault private, run them from a machine inside the VNet (its public access is off).

App Service: restart so it reads the secrets.

```sh
az webapp restart -g <rg> -n <name>
```

Container Apps: go on to the second deployment run in step 3.

## 5. Point your address at it

Add a custom domain and certificate for `appBaseUrl` (**Custom domains** in either service), or use the default host name the deployment printed. If you change `appBaseUrl`, run step 3 again and add `https://<that host>/auth/callback` and `https://<that host>/auth/signed-out` as redirect URIs in the app registration. They must match exactly.

If a reverse proxy or gateway sits in front, `appBaseUrl` must be the address the browser uses, not the one the proxy calls. Keyring ignores `X-Forwarded-*` headers (see the README, "Behind a proxy").

## 6. Check it

1. Open `https://<your-host>/healthz`. It should say `ok`.
2. Open `https://<your-host>/` and sign in.
3. The vault list should show vaults you have Reader on. Open one and check you can see its secrets.

If something's wrong, see [troubleshooting.md](troubleshooting.md).

## Logs

Keyring writes plain text lines to standard output:

- one line per request: `request method=GET path=/secrets status=200 ms=12`. The path never has the query string. A 5xx is logged at `warn`
- an action line each time someone reveals, downloads, creates, changes, deletes, recovers or purges something, naming what (vault and item name) and who, as `subject=oid:<object ID>,tid:<tenant ID>`. Those are the same IDs as in Entra's sign-in logs and Key Vault's diagnostic logs, so you can match them up

Secret values, tokens, passwords, headers and query strings are never logged. Vault and item names are. Set the level with `logLevel` (`KEYRING_LOG_LEVEL`); `info`, the default, includes the action lines. Keyring won't start with any other value, including `off`.

Where they go:

| Host | Where | Table |
| --- | --- | --- |
| Container Apps | The Log Analytics workspace the template creates (`<name>-logs`) | `ContainerAppConsoleLogs_CL` (or `ContainerAppConsoleLogs` if the environment uses diagnostic settings) |
| App Service, with `logAnalyticsWorkspaceId` | That workspace, through a diagnostic setting | `AppServiceConsoleLogs`, and `AppServiceHTTPLogs` for the front end's own request log |
| App Service, without it | The app's own file system, kept 7 days. See them with `az webapp log tail` or download with `az webapp log download` | None |

Without a workspace, App Service's file log is the only record of who revealed what, and it's short. Use a workspace for anything you'd want to look back on.

Example query, who revealed secret values in the last week:

```kusto
// Container Apps: ContainerAppConsoleLogs_CL and Log_s.
// App Service: AppServiceConsoleLogs and ResultDescription.
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(7d)
| where Log_s contains "secret value revealed"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
```

Key Vault's own diagnostic logs (what the audit view reads) are separate and record every call, whether it came through Keyring or not.

## First run against a real tenant

Keyring's tests run against mock Azure services. Some behaviour only a real Entra tenant and Key Vault can confirm. Work through [real-vault-checklist.md](real-vault-checklist.md) after your first deployment, on a test vault, and record what you find there.

## Rotating secrets

### The Entra client secret

Entra client secrets expire. When one does, nobody can sign in (AADSTS7000222). Replace it before then:

1. In the app registration, **Certificates & secrets > New client secret**. The old one keeps working meanwhile.
2. Put the new value in the config vault, with its expiry date:

   ```sh
   az keyvault secret set --vault-name <configVaultName> --name entra-client-secret \
     --value '<new value>' --expires '<expiry, for example 2027-05-01T00:00:00Z>'
   ```

3. Restart so the app reads it: `az webapp restart -g <rg> -n <name>` (App Service) or `az containerapp revision restart -g <rg> -n <name> --revision <active revision>` (Container Apps). Everyone is signed out.
4. Check you can sign in, then delete the old secret in the app registration.

Giving the config vault's `entra-client-secret` an expiry date means it shows on Keyring's own expiry dashboard, and in [expiry alerts](alerts.md) if you set them up for the config vault.

### SESSION_SECRET

`SESSION_SECRET` only protects short-lived cookies (sign-in in progress and one-off messages). Sessions themselves are in memory. To change it, set a new value and restart:

```sh
az keyvault secret set --vault-name <configVaultName> --name session-secret --value "$(openssl rand -base64 48)"
```

The restart signs everyone out, and anyone partway through signing in has to start again. Nothing else is lost.

## Updating

Build and push a new image, change `image` to its digest, and run the same `az deployment group create`. Sessions are in memory, so people are signed out on each restart. To check what's running, read the image's `org.opencontainers.image.revision` label (see the README, "Which version am I running?").

## Removing

Delete the resource group, or the resources listed in step 3. The config vault has purge protection, so its name stays reserved for 90 days.

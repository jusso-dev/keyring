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

### Or use a published image

This applies once Keyring's releases are published. Until then, build your own as above. Each version tag (`vX.Y.Z`) is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml), which only runs for a commit on `main` that passed CI, repeats CI's image checks and attests where the image came from. The image is `ghcr.io/jusso-dev/keyring`. Take the digest from the release's workflow run summary and use the image by digest:

```
ghcr.io/jusso-dev/keyring@sha256:<digest>
```

Before you deploy it, check the attestation. This proves the image was built by that workflow from the repository's source:

```sh
gh attestation verify oci://ghcr.io/jusso-dev/keyring@sha256:<digest> --repo jusso-dev/keyring
```

There is no `latest` tag. If the package is public, Azure Container Apps and App Service can pull it without registry credentials. If you use a private registry, copy the image into it by digest, then run the check above against the original.

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

Note the tenant ID and client ID. For the proof of identity, choose between a client secret and the app's managed identity (step 2 of the README, options A and B). With a client secret, note its value too. With the managed identity, the federated credential needs the identity's principal ID, which exists only after the first deployment (step 3), so add it then and set `useFederatedCredential` for the final deployment.

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
| `logFormat` | Sets `KEYRING_LOG_FORMAT`: `text` or `json` (see Logs) | None (`text`) |
| `trustedProxyHops` | Sets `KEYRING_TRUSTED_PROXY_HOPS` (see Logs, "Client address") | `1` |
| `stepUpAuthContext` | Sets `KEYRING_STEP_UP_AUTH_CONTEXT` (see Step-up) | None (off) |
| `stepUpMaxAge` | Sets `KEYRING_STEP_UP_MAX_AGE` in minutes (see Step-up) | `0` (off) |
| `requireReason` | Sets `KEYRING_REQUIRE_REASON`: `off`, `reveal` or `all` (see Reasons) | None (`off`) |
| `reasonTicketPattern` | Sets `KEYRING_REASON_TICKET_PATTERN` (see Reasons) | None (no ticket) |
| `passwordPolicy` | Sets `KEYRING_PASSWORD_POLICY` (see Password policy) | None (no policy) |
| `requireOwner` | Sets `KEYRING_REQUIRE_OWNER=true`: no item created or edited without an owner (see Owners) | `false` |
| `staleAfterDays` | Sets `KEYRING_STALE_AFTER_DAYS`, the days before the "Not changed in over a year" badge. `0` leaves it unset | `0` (365 days) |
| `logAnalyticsWorkspaceId` | Send the container's output and HTTP logs to this workspace (see Logs) | None (7 days on the app's own storage) |
| `auditWorkspaceId` | Turn on the audit sink, writing to `KeyringAudit_CL` in this workspace, in any resource group or subscription, and the audit page's Keyring activity view, which reads it (see Logs, "Audit sink" and "Keyring activity") | None (off) |
| `auditRetentionInDays` | How long `KeyringAudit_CL` keeps rows | `365` |
| `auditRequired` | Sets `KEYRING_AUDIT_REQUIRED`: refuse reveals and private key downloads while the sink is degraded. Needs `auditWorkspaceId` | `false` |
| `notifyDomain` | Turn on email through Azure Communication Services: `AzureManaged` for an Azure-managed domain, or your own domain name, such as `mail.example.com` (see [Email](#email)) | None (off) |
| `notifyDataLocation` | Where ACS keeps its data at rest | `Australia` |
| `notifyTypes` | Sets `KEYRING_NOTIFY_TYPES`. Needs `notifyDomain` | None (no type on) |
| `notifyAdmins` | Sets `KEYRING_NOTIFY_ADMINS`. Needs `notifyDomain` | None |
| `notifyAllowedDomains` | Sets `KEYRING_NOTIFY_ALLOWED_DOMAINS`. Needs `notifyDomain` | None (any domain) |
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

Container Apps takes `apiScope`, `logLevel`, `logFormat`, `trustedProxyHops`, `stepUpAuthContext`, `stepUpMaxAge`, `requireReason`, `reasonTicketPattern`, `passwordPolicy`, `requireOwner`, `staleAfterDays`, `auditWorkspaceId`, `auditRetentionInDays`, `auditRequired` and the `notify*` parameters too, but not `skuName`, `logAnalyticsWorkspaceId` or the App Service network parameters. It always sends logs to the workspace it creates.

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

If you deployed with `useFederatedCredential` set to `true`, there is no client secret. Set only `session-secret`, and make sure the federated credential from the README (step 2, option B) is on the app registration.

Run these from a shell that doesn't save history, or clear it afterwards. If you made the config vault private, run them from a machine inside the VNet (its public access is off).

App Service: restart so it reads the secrets. If you're using the managed identity, first add the federated credential (README step 2, option B), then run the App Service deployment from step 3 again with `useFederatedCredential` set to `true`. A restart alone keeps the old settings, which still point at an `entra-client-secret` you never set, so Keyring wouldn't start.

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

Keyring writes to standard output, one line per entry:

- one line per request: method, path (never the query string), status and time taken. A 5xx is logged at `warn`
- one **audit event** for each thing a person does through Keyring: every reveal, private key download, create, change, delete, recover and purge, sign-in, failed sign-in, sign-out and session expiry. Refusals and failures get one too: a 403 from Key Vault, a refused form token, a cross-site post, a typed name that didn't match, a purge while purge is off. These are Keyring's own audit events, written by `src/audit/mod.rs`. They are not Key Vault's audit log, which the audit pages read

Secret values, tokens, passwords, headers, query strings and Azure's error messages are never logged. Vault and item names are. Set the level with `logLevel` (`KEYRING_LOG_LEVEL`). Audit events are written at every level, so `warn` or `error` can't drop them. Keyring won't start with any other level, including `off`.

### Format

`logFormat` (`KEYRING_LOG_FORMAT`) is `text` (the default) or `json`.

- `text`: `key=value` lines, as before. An audit event reads `audit kind=audit schema_version=1 time=... action=secret.reveal outcome=success ...`. Free text (user agent, UPN, reason, ticket) is quoted and escaped, so it can't start a new line.
- `json`: one JSON object per line, for every line. Each has `time`, `level`, `kind` and `message`. Audit events have `"kind":"audit"`; everything else has `"kind":"log"`. Use `json` if you query the logs: Container Apps and App Service console tables can then parse each line.

### Audit event fields

Schema version 1. Fields with no value are left out.

What changes the version: adding an optional field, one that is left out of the event when it isn't set, is backward compatible and keeps the version, so a query filtering on `schema_version == 1` still sees every row. Renaming or removing a field, or changing a field's meaning or type, is a new version, with a CHANGELOG line. `tests/audit_events.rs` enforces this: the field names version 1 shipped with are pinned and must all still be written under the same names, fields added since are listed separately, and a field in neither list fails the test, so an addition is always a deliberate change. A column added to `KeyringAudit_CL` after the table first shipped is read with `column_ifexists` in the Sentinel parser. Fields added to version 1 so far: `role`, `role_scope` and `role_duration`; `notify_type`, `notify_recipient_count` and `notify_recipients`; and `notify_event_count`.

| Field | What it holds |
| --- | --- |
| `kind` | `audit` |
| `schema_version` | `1` |
| `time` | UTC, RFC 3339 with milliseconds |
| `event_id` | A random UUID for this event |
| `action` | What was done (list below) |
| `outcome` | `success`; `denied` (Azure said 401 or 403); `refused` (Keyring's own check said no); `failed` (anything else) |
| `reason_code` | Azure's error code, such as `ForbiddenByRbac`, or Keyring's reason: `csrf`, `cross_site`, `typed_name_mismatch`, `purge_disabled`, `managed_item`, `tag_limit` (a bulk tag change would take an item past 15 tags), `no_session`, `invalid_request`, `stale_sign_in`, `id_token_rejected`, on `notify.*` events `status_unknown`, `delivery_failed`, `delivery_canceled`, `rejected`, `gave_up`, `gave_up_maybe_sent`, `queue_full` and `shutdown` (see [Email](#email)), on `notify.webhook` `queued`, `repeat`, `no_recipients`, `validation`, `queue_full`, `recipient_rate_limited`, `rate_limited`, `not_json`, `too_large`, `not_events`, `too_many_events`, `bad_validation`, `bad_event`, `bad_topic`, `bad_recipients` and the token codes `token_missing`, `token_malformed`, `token_algorithm`, `token_signature`, `token_issuer`, `token_audience`, `token_tenant`, `token_expired`, `token_caller`, `token_role` and `token_not_app_only` (see [Expiry emails from Keyring](alerts.md#expiry-emails-from-keyring)), `step_up_required` (a sensitive action stopped to ask the person to confirm it's them, see [Step-up](#step-up-before-sensitive-actions)), `step_up_not_met` (that sign-in came back without what was asked for), `audit_unavailable` (`KEYRING_AUDIT_REQUIRED` is on and the audit sink is degraded), `reason_required` (a reason or ticket was asked for and not given, or didn't meet the rules, see [Reasons](#a-reason-before-a-value-is-shown)), `password_policy` (a typed or imported password didn't meet `KEYRING_PASSWORD_POLICY`; which rule isn't recorded, see [Password policy](#password-policy)), `owner_required` (`KEYRING_REQUIRE_OWNER` is on and an item would have been saved, imported or copied without an owner; no address is recorded, see [Owners](#owners)). Also `timeout`, `server_error`, `cancelled` (the browser closed the connection before Keyring answered; check Key Vault's log by `kv_request_id` for whether the call went through), `network`, `unreadable`, `sign_in_again`, `consent_needed`, `entra_unreachable`, or Entra's OAuth error code on a failed sign-in. Never Azure's message |
| `actor_oid`, `actor_tid` | The person's Entra object ID and tenant ID, from the verified ID token. The same IDs as in Entra's sign-in logs and Key Vault's diagnostic log |
| `actor_upn` | The person's sign-in name, if the ID token has one |
| `session_ref` | A keyed hash of the session ID, so one session's events join up. The cookie value is never logged. The key comes from `SESSION_SECRET`, so it changes when that is rotated |
| `client_ip` | The browser's address. See "Client address" below |
| `user_agent` | The browser's user agent, cut to 256 characters |
| `vault`, `item_kind`, `item_name`, `item_version` | What was acted on. `item_version` is the version read on a reveal, or restored from on a rollback |
| `kv_request_id` | The `x-ms-client-request-id` Keyring sent on its last Key Vault call for this request. Joins the event to Key Vault's diagnostic log |
| `reason`, `ticket` | Why the person did it, and the ticket they named, when `KEYRING_REQUIRE_REASON` asked (see [Reasons](#a-reason-before-a-value-is-shown)). The reason has line breaks, tabs, escape and other control characters replaced by a space and is 5 to 200 characters. The ticket matched `KEYRING_REASON_TICKET_PATTERN` and is at most 64 characters. Both are escaped like any other free text in either format. Absent when no reason was asked for | On `role.activate` they are the PIM justification, cleaned the same way and at most 200 characters, and the ticket system and number.
| `role`, `role_scope`, `role_duration` | On `role.activate` and `role.deactivate`: the role definition GUID, the ARM scope it was turned on or off at, and (activate only) the time asked for in ISO 8601, such as `PT1H30M`. Added in schema version 1 as optional fields, so older readers can ignore them |
| `notify_type`, `notify_recipient_count`, `notify_recipients` | On `notify.sent` and `notify.failed`: the notification type (such as `expiry`), how many recipients the email had, and, only with `KEYRING_NOTIFY_AUDIT_RECIPIENTS=true`, their addresses separated by commas. `notify_type` is also on `notify.webhook`. Added in schema version 1 as optional fields |
| `notify_event_count` | On `notify.webhook`: how many events the Event Grid delivery held, when Keyring got far enough to read them. Column `NotifyEventCount`. Added in schema version 1 as an optional field |
| `keyring_version` | Keyring's version |
| `instance` | A random ID for this run of Keyring |

Actions: `secret.reveal`, `secret.create`, `secret.set`, `secret.update`, `secret.enabled.set`, `secret.rollback`, `secret.delete`, `secret.recover`, `secret.purge`, `secret.import`, `secret.bulk_update`, `secret.copy.read`, `secret.copy.write`, `certificate.download_private_key`, `certificate.upload`, `certificate.create`, `certificate.pending.cancel`, `certificate.renewal.set`, `certificate.enabled.set`, `certificate.update`, `certificate.delete`, `certificate.recover`, `certificate.purge`, `certificate.bulk_update`, `key.create`, `key.rotate`, `key.rotation_policy.set`, `key.enabled.set`, `key.update`, `key.delete`, `key.recover`, `key.purge`, `key.bulk_update`, `role.activate` and `role.deactivate` (a PIM role turned on or off from Keyring, see the README's role table), `session.sign_in`, `session.sign_in_failed`, `session.sign_out`, `session.expired`, `request.refused` for a form post refused before Keyring knew what it was for (a cross-site post, or one with no session), `notify.sent` and `notify.failed` for each email (see [Email](#email)), and `notify.webhook` for each request to `/hooks/eventgrid` that reaches the token check, whatever the outcome, except requests with a bad token over the 60 a minute counter (see [Expiry emails from Keyring](alerts.md#expiry-emails-from-keyring)). `notify.webhook` has no `actor_*`, `session_ref`, `user_agent` or address fields: the caller is Event Grid, checked by its Entra token.

`secret.import` is written once for the import request, and once more for each secret it writes, with that secret's `item_name` and its own outcome.

`secret.bulk_update`, `certificate.bulk_update` and `key.bulk_update` work the same way: one event for the request (`success`, or `failed` or `denied` with `partly_changed` or `none_changed`), and one for each item Keyring reached Key Vault for, with its `item_name` and its own outcome. An item already as asked is `success` with `no_change`; a certificate's backing secret or key is `refused` with `managed_item`; an item already at 15 tags is `refused` with `tag_limit`. The review page before it writes none.

A copy to another vault writes two events. `secret.copy.read` is the request's own, on the source vault and name, with the version read: `success` once the value was read, even if the write then failed. `secret.copy.write` is on the target vault and name, with the new version, or `denied` or `failed` with Key Vault's code. A refusal before the read (form token, step-up, reason, `audit_unavailable`, a target vault you can't see, a deleted target name) is a `secret.copy.read` event only, and nothing reached Key Vault. The reason and ticket go on both.

`session.sign_in_failed` has no `actor_*` fields: Keyring only believes who someone is once the ID token has passed every check. Entra's own sign-in log has the rest. `session.expired` is written when Keyring finds or sweeps an expired session, up to a minute after it ran out.

Pages that only read names and properties (lists, search, expiry, vault health, the audit pages) write no audit event. Each request is still in the request line.

### Client address

App Service and Container Apps put a front end in front of Keyring, so the address Keyring sees is the front end's. `trustedProxyHops` (`KEYRING_TRUSTED_PROXY_HOPS`) says how many proxies add to `X-Forwarded-For`. Keyring takes the address that many entries from the right of that header.

| Where Keyring runs | Value |
| --- | --- |
| App Service | `1` (the templates' default) |
| Container Apps ingress | `1` (the templates' default) |
| Another proxy (Front Door, Application Gateway) in front of either | `2` |
| Nothing in front, or run locally | `0` (Keyring's own default) |

With `0` Keyring ignores the header and records the socket peer, which behind a proxy is the proxy. Too high a value lets a browser choose the address recorded, by sending its own `X-Forwarded-For`. Confirm the value with the real-vault checklist.

### Where they go

| Host | Where | Table |
| --- | --- | --- |
| Container Apps | The Log Analytics workspace the template creates (`<name>-logs`) | `ContainerAppConsoleLogs_CL` (or `ContainerAppConsoleLogs` if the environment uses diagnostic settings) |
| App Service, with `logAnalyticsWorkspaceId` | That workspace, through a diagnostic setting | `AppServiceConsoleLogs`, and `AppServiceHTTPLogs` for the front end's own request log |
| App Service, without it | The app's own file system, kept 7 days. See them with `az webapp log tail` or download with `az webapp log download` | None |

Without a workspace, App Service's file log is the only record of who revealed what, and it's short. Use a workspace for anything you'd want to look back on.

### Audit sink

The audit sink also sends Keyring's own audit events straight to a custom table, `KeyringAudit_CL`, in a Log Analytics workspace, through the [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview). It is separate from the console log tables above, keeps its own retention, and gives Sentinel typed columns. It works on any host where Keyring has its managed identity's local token service: App Service and Container Apps today.

Three things are easy to mix up:

- **Keyring's own audit events**: what Keyring writes for each action (`src/audit/mod.rs`), always to standard output.
- **The audit sink**: the same events, also sent to `KeyringAudit_CL`. Optional.
- **Key Vault's audit log**: what Key Vault writes for every call it receives, which Keyring's audit pages read as you.

**Turning it on with the templates.** Set `auditWorkspaceId` to a workspace's resource ID: the one the Container Apps template makes, or an existing Sentinel workspace in any resource group or subscription you can deploy to. `infra/modules/audit-sink.bicep` then makes, in that workspace's resource group:

- the `KeyringAudit_CL` table, kept for `auditRetentionInDays` (default 365)
- a data collection rule of kind `Direct`, so no separate data collection endpoint is needed, with a stream for the table and a transform that sets `TimeGenerated` from the event's `time`
- **Monitoring Metrics Publisher** on that one rule for Keyring's managed identity (`<name>-id`). Nothing else, and no role for any person

and sets `KEYRING_MANAGED_IDENTITY_CLIENT_ID`, `KEYRING_AUDIT_INGESTION_ENDPOINT`, `KEYRING_AUDIT_DCR_ID`, `KEYRING_AUDIT_STREAM`, `KEYRING_AUDIT_REQUIRED` and `KEYRING_AUDIT_WORKSPACE_ID` on the app. Whoever deploys needs to be able to assign roles on the rule (Owner or User Access Administrator on that resource group). Role assignments can take a few minutes to apply, so the first events may be retried until it does.

**Who writes and who is named.** Keyring writes every row as its managed identity, and nothing else: no client secret, no second app registration, and never the signed-in person's token. Each row names the person who acted in `ActorObjectId`, `ActorTenantId` and `ActorUpn`, taken from Keyring's verified session at the moment of the action. They are empty only when nobody was signed in, such as a failed sign-in. `WriterIdentityClientId`, `KeyringInstance` and `KeyringVersion` name the writer. Only Keyring's identity can add rows, and no identity Keyring has can read, change or delete them.

**Columns.** The schema version 1 fields as columns: `TimeGenerated` (from `time`), `EventId`, `SchemaVersion`, `Action`, `Outcome`, `ReasonCode`, `ActorObjectId`, `ActorTenantId`, `ActorUpn`, `SessionRef`, `ClientIp`, `UserAgent`, `Vault`, `ItemKind`, `ItemName`, `ItemVersion`, `KvRequestId`, `Reason`, `Ticket`, `Role`, `RoleScope`, `RoleDuration`, `NotifyType`, `NotifyRecipientCount`, `NotifyRecipients`, plus the writer columns. A workspace set up before a column was added needs the template run again, or Logs Ingestion drops that field from each row (the rest of the row still arrives). The list lives in `COLUMNS` in `src/audit/sink.rs`, and a test fails if the module or the event fields drift from it.

**Sending.** One background task sends a batch every 5 seconds, or as soon as 500 events are waiting, gzipped and under the API's 1 MB a call. A 429 or 5xx is retried with backoff, honouring `Retry-After`. A 401 or 403 (the identity lost its role) gets a fresh token and is retried. Any other refusal drops that batch and counts it. Up to 10,000 events wait in memory; past that the oldest is dropped and counted. On shutdown (SIGTERM), Keyring sends what is left for up to 10 seconds. Every event is also on standard output, so nothing is lost from the console log while the sink is down. Only status codes and counts are logged, never a row or token.

**Health.** `/healthz/audit` needs no sign-in and shows only `status=ok`, `status=degraded` or `status=off` and counts since start (`queued`, `sent`, `dropped_queue_full`, `dropped_rejected`, `dropped_at_shutdown`, `failed_attempts`). It answers 503 while degraded: the sink has been failing for over a minute with no success. A batch Azure refuses outright (a 400, such as after the table's columns were changed) is dropped and counted in `dropped_rejected`, and counts as a failure too, so refusals one after another with nothing accepted in between also mean degraded. Point an availability test or alert at it. `/healthz` stays a liveness check and doesn't change.

**Requiring it.** With `auditRequired` (`KEYRING_AUDIT_REQUIRED=true`), Keyring refuses reveals and private key downloads while the sink is degraded, with a page that says auditing is unavailable. The refusal is itself an audit event (`reason_code` `audit_unavailable`). Off by default.

### Keyring activity

With `KEYRING_AUDIT_WORKSPACE_ID` set to the resource ID of the workspace that holds `KeyringAudit_CL` (the templates set it from `auditWorkspaceId`), each vault's audit page has two views: **Key Vault's log**, as before, and **Keyring activity**, the table's rows for that vault (`/v/<vault>/audit/keyring`). It shows what Keyring refused before Key Vault was asked, and the reason and ticket a person gave (#205), which Key Vault's log can't.

- It is read as the signed-in person, with their own Log Analytics token, the same as Key Vault's log. Keyring's managed identity can only write to the table and is never used to read it. Each person needs **Log Analytics Reader** on that workspace (or a table-level read role on `KeyringAudit_CL`); without it, the view says so and what to ask for.
- The same time ranges, filters (item, action, person), escaping and 500-row limit as the rest of the audit page.
- Without the setting, the view and its link aren't there, and nothing else changes.

Use a different workspace from the sink only if the table is copied there; Keyring reads the one you name.

**Sentinel.** `infra/sentinel` adds an ASIM parser, analytic rules (all off by default), hunting queries and a workbook for this table. See [sentinel.md](sentinel.md).

**Other hosts.** AKS workload identity and Azure VMs (IMDS) are still a managed identity but get tokens another way, and aren't supported yet. Hosts without a managed identity can't use the sink; their events still go to standard output.

```kusto
KeyringAudit_CL
| where TimeGenerated > ago(1d) and Action == "secret.reveal"
| project TimeGenerated, ActorUpn, ActorObjectId, Vault, ItemName, Outcome, ClientIp, WriterIdentityClientId
```

### Example queries

Who revealed secret values in the last week. With `json`:

```kusto
// Container Apps: ContainerAppConsoleLogs_CL and Log_s.
// App Service: AppServiceConsoleLogs and ResultDescription.
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(7d)
| extend e = parse_json(Log_s)
| where tostring(e.kind) == "audit" and tostring(e.action) == "secret.reveal"
| project TimeGenerated, actor_oid = tostring(e.actor_oid), vault = tostring(e.vault),
    item = tostring(e.item_name), outcome = tostring(e.outcome), client_ip = tostring(e.client_ip)
| order by TimeGenerated desc
```

With `text`:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(7d)
| where Log_s has "kind=audit" and Log_s has "action=secret.reveal"
| extend actor_oid = extract(@"actor_oid=(\S+)", 1, Log_s), vault = extract(@"vault=(\S+)", 1, Log_s),
    item = extract(@"item_name=(\S+)", 1, Log_s), outcome = extract(@"outcome=(\S+)", 1, Log_s)
| project TimeGenerated, actor_oid, vault, item, outcome
| order by TimeGenerated desc
```

Reveals and private key downloads with their reasons and tickets (`KEYRING_REQUIRE_REASON`), with `json`:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(7d)
| extend e = parse_json(Log_s)
| where tostring(e.kind) == "audit"
    and tostring(e.action) in ("secret.reveal", "certificate.download_private_key")
| project TimeGenerated, actor_upn = tostring(e.actor_upn), vault = tostring(e.vault),
    item = tostring(e.item_name), outcome = tostring(e.outcome), reason_code = tostring(e.reason_code),
    reason = tostring(e.reason), ticket = tostring(e.ticket)
| order by TimeGenerated desc
```

A refused one has `outcome` `refused` and `reason_code` `reason_required`, and no reason.

Everything Keyring refused or Azure denied in the last day, with `json`:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1d)
| extend e = parse_json(Log_s)
| where tostring(e.kind) == "audit" and tostring(e.outcome) in ("refused", "denied")
| summarize count() by tostring(e.actor_oid), tostring(e.action), tostring(e.reason_code)
```

An event joined to Key Vault's own log row by `kv_request_id`, with `json`. Key Vault records the caller's `x-ms-client-request-id` as its correlation ID: the `CorrelationId` column in both `AZKVAuditLogs` and `AzureDiagnostics`. That column is still to be confirmed on a real vault (see the real-vault checklist):

```kusto
let keyring = ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1d)
| extend e = parse_json(Log_s)
| where tostring(e.kind) == "audit" and isnotempty(e.kv_request_id)
| project TimeGenerated, action = tostring(e.action), kv_request_id = tostring(e.kv_request_id),
    client_ip = tostring(e.client_ip);
AZKVAuditLogs
| where TimeGenerated > ago(1d)
| join kind=inner keyring on $left.CorrelationId == $right.kv_request_id
| project TimeGenerated, action, OperationName, ResultSignature, CallerIpAddress, client_ip
```

Key Vault's own diagnostic logs (what the audit view reads) are separate and record every call, whether it came through Keyring or not.

## Email

Optional. Keyring can send email notices through Azure Communication Services (ACS), as its managed identity. Each kind of notice (expiry, access requests, watched reads, deletes and bulk changes, role use, health) is added by its own change. So far: `expiry`, pushed by Event Grid to `/hooks/eventgrid` (see [Expiry emails from Keyring](alerts.md#expiry-emails-from-keyring)), and health notices to the admins (see [Health notices](#health-notices)). The others send nothing yet.

**Turning it on with the templates.** Set `notifyDomain` to `AzureManaged` or to your own domain name. `infra/modules/notify.bicep` then makes, in Keyring's own resource group (so they aren't shared with any other workload):

- an Email Communication Service and one domain: an Azure-managed one (`<random>.azurecomm.net`) or yours
- a Communication Services resource linked to that domain
- a custom role, **Keyring email sender (`<name>`)**, holding exactly two actions, `Microsoft.Communication/CommunicationServices/Read` and `Microsoft.Communication/CommunicationServices/Write`, assigned directly to Keyring's managed identity on that one Communication Services resource

and sets `KEYRING_MANAGED_IDENTITY_CLIENT_ID`, `KEYRING_NOTIFY_ACS_ENDPOINT`, `KEYRING_NOTIFY_SENDER` (`DoNotReply@<domain>`) and, from `notifyTypes`, `notifyAdmins` and `notifyAllowedDomains`, the matching settings on the app. Whoever deploys needs to be able to create role definitions and assign roles in the resource group (Owner, or User Access Administrator plus Contributor).

**Why that role.** Azure has no "send email" permission under `Microsoft.Communication`, so Read and Write on the Communication Services resource is the narrowest role that can send (Microsoft's managed identity email sample uses the same pair). Write also lets the holder change that one resource's settings, such as its linked domains. The role has no `ListKeys` or `RegenerateKey`, no Email Service permission, no data action and no wildcard. It's assigned to the identity directly, not through an Entra group: group assignments don't work for managed identities with ACS. Keyring uses no access key, connection string or SMTP password, and the templates never read or output one.

**A custom domain.** The template makes the domain but doesn't verify it. In the portal, open the Email Communication Service, then the domain, then **Provision domains**, and add the TXT record it shows (domain ownership), the SPF record (`v=spf1 include:spf.protection.outlook.com -all`, merged with any SPF record you already have) and the two DKIM CNAME records, then select **Verify** for each. Add a DMARC record (`_dmarc.<domain>` TXT, `v=DMARC1; p=quarantine; rua=mailto:<your report address>`) as your mail policy says. Mail from an unverified domain is refused. An Azure-managed domain needs none of this, but its sender address can't be changed and it has the low limits below.

**ACS's own limits.** By default, per subscription: an Azure-managed domain sends at most 5 emails a minute and 10 an hour (fixed); a custom domain 30 a minute and 100 an hour, which a support request can raise once the domain's failure rate is under 1%. At most 50 recipients an email and 10 MB a request. Over a limit, ACS answers 429 with `Retry-After`, which Keyring honours. Keyring's own rate limit below is per recipient, so a busy deployment on a managed domain will meet ACS's limit first: use a custom domain for anything beyond a trial.

**Settings.**

| Variable | What it's for |
| --- | --- |
| `KEYRING_NOTIFY_ACS_ENDPOINT` | The Communication Services resource's endpoint, `https://<resource>.<geography>.communication.azure.com`. HTTPS, on `communication.azure.com`, with nothing after the host. Needs `KEYRING_MANAGED_IDENTITY_CLIENT_ID`: email is sent only as that identity. Every other `KEYRING_NOTIFY_*` setting is refused without it |
| `KEYRING_NOTIFY_SENDER` | Needed with the endpoint. The sender, a `DoNotReply@<verified domain>` address. One plain address: no display name |
| `KEYRING_NOTIFY_TYPES` | Which notices are on, separated by commas: `expiry`, `access-requests`, `watched-reads`, `destructive`, `role-use`, `health`. Default: none |
| `KEYRING_NOTIFY_ADMINS` | Addresses, separated by commas, for health and fallback notices. At most 20 |
| `KEYRING_NOTIFY_ALLOWED_DOMAINS` | Domains, separated by commas. Every recipient must be in one, exactly (a subdomain is a different domain). Admins must be too. Default: any domain |
| `KEYRING_NOTIFY_RATE_PER_HOUR` | Emails an hour to one recipient for one type, 1 to 1000. Default 20 |
| `KEYRING_NOTIFY_AUDIT_RECIPIENTS` | `true` to put recipients' addresses on the `notify.*` audit events. Off by default: addresses are personal data |
| `KEYRING_NOTIFY_OWNER_ON_READ` | With `watched-reads` on: `true` to send watched-read emails to the item's `owner` as well as its `notify` addresses. Off by default. See [Activity emails](#activity-emails) |
| `KEYRING_EVENTGRID_AUDIENCE` | With `expiry` in the types: the `aud` the Event Grid token on `/hooks/eventgrid` must have, compared exactly. An app ID URI (`api://...` or `https://...`) or a GUID. Default: `api://<ENTRA_CLIENT_ID>`. Refused without `expiry` |
| `KEYRING_NOTIFY_BURST_THRESHOLD` | With `health` on: more than this many refused or denied requests from one person or address in 15 minutes is a burst, 1 to 1000. Default 20. See [Health notices](#health-notices) |
| `KEYRING_CLIENT_SECRET_EXPIRES` | With `ENTRA_CLIENT_SECRET` only: the secret's expiry date, `YYYY-MM-DD` (Keyring can't read it from Entra). Keyring refuses to start with a malformed date, or with this set and no client secret (signing in with the managed identity has no secret to expire). Without email and `health` on, it is only logged at start |

Each address is parsed strictly: one `name@domain`, no display name, quotes, spaces, commas or line breaks. Keyring refuses to start on one that isn't.

**What an email holds.** The subject is `[Keyring]`, the type, and the item when there is one, such as `[Keyring] Expiry: secret db-password in kv-prod`, so mail rules can route it. The body (plain text and HTML) has a heading, a few lines, the item and vault, who and when, and a link to the item in Keyring. Never a secret value, token, private key, Azure error message or the reason a person typed. Any free text has control and invisible characters taken out, and the HTML part is escaped. Only `to` recipients are used, never cc or bcc. Open and click tracking is off.

**Sending.** One background task sends each email with `POST /emails:send?api-version=2025-09-01` and a token for `https://communication.azure.com` from Keyring's managed identity. Each email gets a `Repeatability-Request-Id` and `Repeatability-First-Sent`, and every retry sends the same ID, time and body, so ACS can tell a retry from a new email. A 429, 408 or 5xx is retried with backoff, honouring `Retry-After`; a 409 means ACS is still working on the first try and is checked again the same way; a 401 or 403 gets a fresh token and is retried. ACS only remembers a request for five minutes, so an email not accepted by then is given up (a 412 means the same), and is never sent again under a new ID, which could send it twice. Any other refusal drops it. Once accepted, Keyring checks its result at most three times and counts it as delivered, failed or unknown. Up to 1,000 emails wait in memory; when that is full, a new one is refused and the caller is told the queue is full. On shutdown, Keyring sends what is queued for up to 10 seconds.

**Audit.** Each email gets one audit event: `notify.sent` (`success`, or `status_unknown` when its result wasn't known after three checks) or `notify.failed` (`delivery_failed` or `delivery_canceled` from ACS, `rejected`, `gave_up`, `gave_up_maybe_sent` when a try may have reached ACS, `queue_full` or `shutdown`), with `notify_type`, `notify_recipient_count` and the item. A failed result's message from Azure is never read into an event, email or log line: only the status.

**Health.** `/healthz/notify` needs no sign-in and shows `status=ok`, `status=degraded` or `status=off` and counts since start (`queued`, `delivered`, `failed`, `unknown`, `dropped_queue_full`, `dropped_at_shutdown`, `rate_limited`, `not_allowed`, `invalid`, `failed_attempts`). No addresses. It answers 503 while degraded: sending has been failing for over a minute with no success.

### Activity emails

Three types, each on only when named in `KEYRING_NOTIFY_TYPES`. Each sends only when the action succeeded: a denied, refused or failed action sends nothing. The trigger is the audit event in memory, so it works with the audit sink off.

| Type | Actions | Who gets it |
| --- | --- | --- |
| `watched-reads` | `secret.reveal`, `certificate.download_private_key`, `secret.copy.read`, `secret.rollback` | The item's `notify` addresses, and its `owner` with `KEYRING_NOTIFY_OWNER_ON_READ=true`. An item with neither sends nothing. Read from the tags Keyring already had from the read, with no extra call |
| `destructive` | `secret.delete`, `certificate.delete`, `key.delete`, `secret.purge`, `certificate.purge`, `key.purge`, and `secret.bulk_update`, `certificate.bulk_update`, `key.bulk_update` | The vault's owners from its `keyring-owners` ARM tag, or `KEYRING_NOTIFY_ADMINS` when it has none or it can't be read. A bulk change is one email for the request, listing up to 50 changed item names and then "and N more"; one that changed some items and not others still sends, for the ones that changed |
| `role-use` | `role.activate` (once the role is on, not while it waits for approval) and `role.deactivate` | The vault's owners, or the admins, as above. With the role's name, the scope and the duration |

The person who acted isn't emailed about their own action (compared by mailbox, so case and `+tag` don't matter), unless they are the only address left. Each email says who (their sign-in name, or "an unnamed person" when it isn't one plain address), what (fixed words), when, the client address (only when it parses as an IP address) and links to the vault's audit view (Keyring activity when `KEYRING_AUDIT_WORKSPACE_ID` is set). It never holds a value, a token, a reason, a PIM justification, a description, a tag value or Azure's message: it says a reason or justification was given and that it is on the event in Keyring's audit log. A ticket is shown only when it matches `KEYRING_REASON_TICKET_PATTERN`.

**Set `KEYRING_NOTIFY_ALLOWED_DOMAINS` before turning `watched-reads` on.** Anyone who can write an item's tags can put any address in `notify` and then read the item to send that address mail. Besides the per-recipient limit (`KEYRING_NOTIFY_RATE_PER_HOUR`), one item sends at most 4 watched-read emails an hour.

The vault's owners are read from Resource Graph as the signed-in person, after the request has answered, in a task with a 10 second limit, so the action is never slowed or failed by it.

### Health notices

With `health` in `KEYRING_NOTIFY_TYPES`, Keyring emails `KEYRING_NOTIFY_ADMINS` (and nobody else) when it is in trouble itself. Each email has the subject `[Keyring] Health`. With `health` on and no admins, nothing is sent and a line at start says so.

| Email | When | What to do |
| --- | --- | --- |
| **Keyring's audit sink is failing** | The audit sink has been degraded (see [Audit sink](#audit-sink)) for over five minutes. Says how many events were dropped since then and how many are waiting | Check Keyring's identity still has Monitoring Metrics Publisher on the data collection rule, and that the ingestion endpoint can be reached. `/healthz/audit` shows the current state. With `KEYRING_AUDIT_REQUIRED` on, reveals and private key downloads are refused until it recovers |
| **Keyring's audit sink has recovered** | The sink is sending again after an incident that was emailed. Says roughly how long it failed and how many events were dropped in that time | Nothing, unless events were dropped: those are missing from `KeyringAudit_CL` but are still in Keyring's standard output log |
| **Many refused requests in a short time** | More than `KEYRING_NOTIFY_BURST_THRESHOLD` (default 20) audit events with outcome `refused` or `denied` from one person, or, with nobody signed in, from one client address, within 15 minutes. Names the person by sign-in name (or "an unnamed caller") or the address, the count, and the reason codes seen (such as `step_up_required`, `typed_name_mismatch` or Azure's `ForbiddenByRbac`). Links to that person's activity report, or to the refused requests report | Open the report and check whether it was them: a script with the wrong access, someone looking for what they can reach, a stolen session, or a scanner. You won't get another email about the same person or address until they have had no refusal for 15 minutes |
| **Keyring's client secret expires soon** | `KEYRING_CLIENT_SECRET_EXPIRES` is 30, 14, 7 or 1 days away. One email at each step | Make a new client secret, set `ENTRA_CLIENT_SECRET` and `KEYRING_CLIENT_SECRET_EXPIRES`, and restart (see [Rotating secrets](#rotating-secrets)), or move to the managed identity |
| **Keyring's client secret has expired** | The date has passed. One email | As above. Nobody can sign in until it is replaced |

Nothing is stored, so after a restart Keyring may send the current step of the secret's expiry once more, and starts each count afresh. A sink incident that began before the restart counts from when Keyring first sees it degraded.

When email itself can't be sent, there is no email about it. Keyring logs one `warn` line when sending starts failing and one `info` line when it works again, and `/healthz/notify` answers 503 meanwhile. Point an HTTP probe at `/healthz/notify` and `/healthz/audit` if you need to hear about either without email.

Refusals are counted in memory as each audit event is written, so this works with the audit sink off. Only `refused` and `denied` events count; email's own `notify.*` events never do. At most 10,000 people and addresses are tracked at once: past that, new ones aren't counted until older ones go quiet, and a `warn` line says so. At most 10 burst emails go out in an hour across everyone, on top of the per-recipient rate limit. The emails never hold a secret value, token, Azure error message or the reason a person typed: only fixed text, counts, dates, reason codes, the sign-in name or address, and a link Keyring built from `APP_BASE_URL`.

## Step-up before sensitive actions

Keyring can ask for a stronger or more recent sign-in before it reveals a secret value, downloads a certificate with its private key, rolls a secret back, copies a secret to another vault or purges anything. The person sees "Your organisation asks you to confirm it's you before showing values.", signs in with Microsoft again, and comes back to the same confirmation step. Nothing runs until they confirm again.

Two optional settings, which can be used alone or together. With neither, nothing changes.

- `stepUpAuthContext` (`KEYRING_STEP_UP_AUTH_CONTEXT`): a Conditional Access authentication context ID, `c1` to `c99`. Keyring asks Entra for it with the OpenID Connect `claims` parameter, `{"id_token":{"acrs":{"essential":true,"value":"c1"}}}`, and reads the answer from the `acrs` claim of the verified ID token. Needs Entra ID P1.
- `stepUpMaxAge` (`KEYRING_STEP_UP_MAX_AGE`): minutes since the person last entered their credentials (the ID token's `auth_time`). Older than that, and Keyring sends them to sign in with `prompt=login` and `max_age`. Works without Conditional Access.

A bad value (`c0`, `c100`, `15m`) stops Keyring at start rather than turning the check off.

**This is a check Keyring makes, not Key Vault.** Key Vault doesn't know about it, so anyone with access can still read the same values with the Azure CLI or the portal. It raises the bar for someone holding a stolen Keyring session cookie, but only while that session's own sign-in doesn't meet the settings. Once a person has confirmed it's them, their session meets an authentication context until it ends (12 hours at most), so a cookie stolen after that passes too. Set `stepUpMaxAge` as well to make it lapse sooner. To make Key Vault itself need the stronger sign-in, use a Conditional Access policy on Azure Key Vault (or Azure management) as a cloud app as well.

### Create the authentication context

1. In the Entra admin centre, go to **Protection > Conditional Access > Authentication contexts** and select **New authentication context**.
2. Give it a name people will understand, such as "Read secret values", and a description. Tick **Publish to apps**.
3. Note its ID (`c1` to `c99`). That is the value for `stepUpAuthContext`.

### Create a Conditional Access policy for it

1. Go to **Protection > Conditional Access > Policies** and select **New policy**.
2. **Users**: the people who use Keyring, or a pilot group first.
3. **Target resources**: choose **Authentication context** and pick the one you made.
4. **Grant**: what a sensitive action needs, for example **Require authentication strength** (phishing-resistant MFA) or **Require device to be marked as compliant**.
5. **Session**: optionally **Sign-in frequency**, **Every time**, so the context is only met by a sign-in made just now.
6. Start in **Report-only**, check the sign-in logs, then turn it on.

Then set `stepUpAuthContext` and redeploy. Test with an account in the policy and one outside it.

If Entra can't let the person through (an unregistered method, a device that isn't compliant), the sign-in page says the organisation's sign-in rules weren't met, with the AADSTS code. If Entra lets the sign-in through but `acrs` doesn't have the context (for example the context isn't published to apps), Keyring refuses it with "Couldn't confirm it's you" and a link back to the confirmation step. It doesn't send the person round again. Both write an audit event: `step_up_required` when an action is stopped to ask, and `step_up_not_met` on a `session.sign_in_failed` event when the sign-in came back without it.

Not yet confirmed on a real tenant: whether Entra puts `acrs` in the ID token (which is what Keyring reads), the AADSTS code it returns when the policy can't be met, and that `max_age` gives a fresh `auth_time`. See the step-up rows in [real-vault-checklist.md](real-vault-checklist.md).

## A reason before a value is shown

Keyring can ask for a reason, and optionally a ticket reference, before it shows a value or changes anything. The reason and ticket go on the action's audit event, so the log says why as well as who.

- `requireReason` (`KEYRING_REQUIRE_REASON`): `off` (the default), `reveal` (before a secret value is shown, copied to another vault, or a certificate is downloaded with its private key), or `all` (those, and every create, change, enable or disable, rotation, rollback, delete, recover and purge).
- `reasonTicketPattern` (`KEYRING_REASON_TICKET_PATTERN`): a regular expression the ticket must match, such as `(INC|CHG)[0-9]{7}`. It is always matched against the whole ticket (Keyring wraps it in `^(?:...)$`), and the ticket is at most 64 characters. Keyring only checks the shape. It doesn't call any ticket system. Leave it unset to ask for a reason only. Setting it while `requireReason` is `off` stops Keyring at start.

A bad value (`on`, `reveals`, a pattern that doesn't compile, or one over 200 characters or with large counted repeats) stops Keyring at start rather than turning the check off.

The reason is 5 to 200 characters, counted in characters, not bytes. Line breaks, tabs, the escape character and other control or invisible formatting characters become a single space before the reason is checked and logged, so a reason can't start a new log line, colour a terminal or forge a field in either log format. The form tells people not to type secrets, passwords or personal details into it. Treat the logged reason as free text a person typed: anyone who can read Keyring's logs can read it.

The reveal button and the confirmation pages show the reason field. Any other form that reaches an action needing a reason without one (for example the Show value buttons on the versions page) gets a page asking for it, which posts the same form again. Secret values are never carried to that page: a create or "set a new value" form, plain or typed, and any form with a value, goes back to the form. The check runs after the form token and step-up checks and before any Key Vault call. A step-up sign-in brings the person back to the confirmation step, where they give the reason again: it is never put in an address. A missing or bad reason writes an audit event with `reason_required`.

**This isn't a hard control.** Key Vault doesn't know about it. Anyone with access can still read the same value with the Azure CLI or the portal, and no reason. It's for the Keyring path and for audit.

## Password policy

`passwordPolicy` (`KEYRING_PASSWORD_POLICY`) sets rules for a password a person types or pastes into Keyring. It is one line of comma-separated parts, such as `min=14,upper,lower,digit,symbol,max-repeat=3,common`. Names are matched in any case and spaces around a part are ignored.

| Part | What it asks for | Default when left out |
|---|---|---|
| `min=N` | At least N characters, 1 to 256. Counted in characters (Unicode scalar values), not bytes, so `ü` or `日` is one. Only visible characters count: letters, numbers, punctuation, symbols and spaces. Invisible ones (control and format characters such as zero-width spaces and joiners, the soft hyphen and the byte order mark, fillers, private-use and unassigned code points), combining marks (such as the accent in a decomposed `é`) and line breaks aren't counted. A value may hold them; they just don't count | No minimum |
| `upper` | An upper case letter, in any alphabet | Not needed |
| `lower` | A lower case letter, in any alphabet | Not needed |
| `digit` | A digit, 0 to 9 | Not needed |
| `symbol` | A punctuation mark or symbol, such as `!`, `#`, `%` or `€` (Unicode categories P and S). Invisible characters, combining marks, spaces and unassigned code points are never a symbol | Not needed |
| `max-repeat=N` | No character more than N times in a row, 1 to 64. Characters that don't count are left out first, so an invisible character between two letters doesn't break up a run | No limit |
| `common` | Not on Keyring's built-in list of about 1,000 common passwords, compared in lower case with characters that don't count left out, so `password` followed by a zero-width space or a line break is still `password` | Not checked |

Unset means no policy: the forms behave as they did before. An unknown part, a part given twice, a number out of range, a value on a part that doesn't take one, or an empty part stops Keyring at start rather than turning the check off. 256 is the generator's longest password, so a policy can always be met by a generated value.

**Where it applies.** Every route that saves a new value into a Password secret (the plain type, with no Keyring content type) or the `password` field of a Login secret: Create a secret, Set a new value, and import from a file. On Set a new value the type comes from the secret's content type in Key Vault, never from the form, so a post can't dodge the check by naming another type. Import only ever writes plain secrets: a row with one of Keyring's own content types (`application/vnd.keyring.`) is refused whether or not a policy is set, and typed secrets are made on the Create form. Each row that would be written is checked as a Password, including a row that gives a new value to an existing Login or other typed secret, which becomes a plain secret. A row that misses the policy is skipped and named in the preview with "Its value doesn't meet Keyring's password policy.", which names no rule; the rest of the file is imported as usual, and the preview says once what the policy asks for. Edit details never sends a typed secret's content type, and refuses a Keyring content type typed onto a plain secret. So no route turns a secret into a Login without its password being checked.

**Every plain value counts as a Password.** With a policy on, anything typed into a plain secret's Value box, or imported, is checked, even when it isn't a password. A PEM block fails `max-repeat=3` (its five dashes in a row), and a connection string or token may miss a class rule. For those, choose the type that fits on the Create form (SSH private key, API key or Database), which the policy doesn't check, or set the value with the Azure CLI.

**Where it doesn't.** Database, API key and SSH private key secrets, including their password, key and passphrase fields: those are machine credentials or keys, often set by another system. Copy to another vault: it moves a value Keyring already holds, with its type. Rollback: it restores an old value as it was. Values from Keyring's generator are checked like any typed value. Its defaults (24 characters, lower, upper, digits and symbols) meet the example policy above nearly every time; a run of four of one character in a row is possible but rare, and if a generated value misses a rule the form says which and Generate makes another.

**What people see.** The form says what the policy asks for under the field before anyone types, and that the Azure CLI and portal don't apply it. The browser only gets a `minlength` hint; the check runs on the server, in memory, when the form is sent. A value that misses a rule gets an error on that field naming each rule it missed, in the rule's own words: never the value, its length or how close it came. A value on the common list gets the same message whatever the entry. The value box is empty again after any error, as on every field error, and the form asks the person to type it again.

**What is logged.** Nothing about the value. A refused create or set writes its audit event with `outcome` `refused` and `reason_code` `password_policy`, and no field says which rule failed. On an import, each refused row gets its own `secret.import` event with its name, `outcome` `refused` and `reason_code` `password_policy`, and nothing is sent to Key Vault for it. Those events are written when the import is confirmed, with the rest of its events. The preview writes no audit event, as before, so a file in which no row can be imported has no Import button and leaves no event: nothing was written to the vault. The list lookup is a hash set lookup on the whole lower-cased value, and every rule is checked on every submit, so the time taken doesn't depend on which rule failed or which entry matched.

**This isn't a hard control.** Key Vault doesn't know about it. Anyone with access can set any value with the Azure CLI, the portal or an SDK. It's for the Keyring path, like step-up and reasons.

## Owners

`requireOwner` (`KEYRING_REQUIRE_OWNER=true`) makes Keyring refuse to save a secret, certificate or key without an `owner` tag. Off by default. `true` or `false` in any case; anything else stops Keyring at start. The tags themselves, `owner`, `notify` and the vault's `keyring-owners`, are described in the README under "Well-known tags".

**Where it applies.** Every form that shows the Owner field: create a secret, certificate or key, upload a certificate, Set a new value and Edit details on a secret, and Edit details on a certificate or key. Each refuses an empty owner with an error on the Owner field, before Key Vault is called, including an edit of an item that never had one: the form shows the field, so it can be filled in on the same save. An owner set in the portal or the CLI that isn't one plain address counts as an owner, and is kept as it is. The import skips a row with no `owner` (a `.env` file has no owner column, so every row is skipped) and names it in the preview. Copy to another vault refuses a source with no owner, or a copy with Tags unticked, before the value is read: it brings the source's tags and nothing else. The bulk change doesn't offer **Remove the owner** and refuses it if posted.

**Where it doesn't.** Rotating a key, rolling back a secret, enable and disable, and certificate renewal keep the item's tags as they are and show no Owner field, so they aren't stopped by an item with no owner.

**What is logged.** Each refusal is an audit event with `outcome` `refused` and `reason_code` `owner_required`; an import writes one per skipped row when it is confirmed. Never the address: addresses in `owner` and `notify` are personal data, shown on the pages to people who can already read the tags (a plain address as a `mailto:` link), and never logged, put in an audit event or a flash message, or put in a URL Keyring builds. A person who types `owner=<address>` into a tag filter puts it in their own query string: Keyring never logs query strings, but a proxy in front of it may. The **Owned by me** filter posts `mine=1` and matches the address from the verified sign-in.

**This isn't a hard control.** Key Vault doesn't know about it. Anyone with access can create an item without an owner with the Azure CLI, the portal or an SDK, or remove the tag later.

**Checks on every address.** One plain address (`name@example.com`: no display name, spaces, commas or line breaks), and in `KEYRING_NOTIFY_ALLOWED_DOMAINS` when that is set, whether or not the policy is on. A refused field names the entry by place ("the second address in Notify"), never by quoting it. Notify holds up to 5 addresses within the tag's 256 characters. The emails that will use these tags check the allow-list again when they send.

## First run against a real tenant

Keyring's tests run against mock Azure services. Some behaviour only a real Entra tenant and Key Vault can confirm. Work through [real-vault-checklist.md](real-vault-checklist.md) after your first deployment, on a test vault, and record what you find there.

## Rotating secrets

### The Entra client secret

With the managed identity (`useFederatedCredential`, or `KEYRING_MANAGED_IDENTITY_CLIENT_ID` set without `ENTRA_CLIENT_SECRET`), there is no client secret to rotate, and nothing here applies. The identity's tokens are short-lived and the platform renews them. The federated credential on the app registration has no expiry. If you replace the managed identity, add a federated credential for the new one, deploy, and check that sign-in works. Then delete the old identity's federated credential from the app registration (**Certificates & secrets > Federated credentials**, or `az ad app federated-credential delete`). Until you do, the old identity can still act as the Keyring app.

### Moving an existing deployment to the managed identity

App Service: add the federated credential (README step 2, option B), then redeploy with `useFederatedCredential` set to `true`. Once sign-in works, delete the client secret from the app registration and `entra-client-secret` from the config vault.

Container Apps refuses to remove a secret that the running revision still uses, so this takes two deployments:

1. Add the federated credential, then deploy with `useFederatedCredential=true` and `keepClientSecretEntry=true`. The new revision signs in with the identity and no longer reads the client secret, but the secret entry stays defined.
2. Once the new revision is running and the old one is inactive (`az containerapp revision list -g <rg> -n <name> -o table`), deploy again with `keepClientSecretEntry=false`.

Then delete the client secret from the app registration and `entra-client-secret` from the config vault. A new deployment that starts with `useFederatedCredential=true` needs none of this.

With a client secret, Entra client secrets expire. When one does, nobody can sign in (AADSTS7000222). Replace it before then:

1. In the app registration, **Certificates & secrets > New client secret**. The old one keeps working meanwhile.
2. Put the new value in the config vault, with its expiry date:

   ```sh
   az keyvault secret set --vault-name <configVaultName> --name entra-client-secret \
     --value '<new value>' --expires '<expiry, for example 2027-05-01T00:00:00Z>'
   ```

3. Restart so the app reads it: `az webapp restart -g <rg> -n <name>` (App Service) or `az containerapp revision restart -g <rg> -n <name> --revision <active revision>` (Container Apps). Everyone is signed out.
4. Check you can sign in, then delete the old secret in the app registration.

Giving the config vault's `entra-client-secret` an expiry date means it shows on Keyring's own expiry dashboard, and in [expiry alerts](alerts.md) if you set them up for the config vault.

Set `KEYRING_CLIENT_SECRET_EXPIRES` to the same date (`YYYY-MM-DD`) as an app setting, and with email and `health` on, the admins get email at 30, 14, 7 and 1 days before it and once it has passed. Keyring can't read the date from Entra, so update the setting each time you rotate. See [Health notices](#health-notices).

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

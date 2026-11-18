# Operations

## Health endpoints

None needs sign-in, and none shows an address, token or row.

| Endpoint | Answers | Use |
|---|---|---|
| `/healthz` | `ok` while the process serves requests | Liveness and readiness probes (the templates set it) |
| `/healthz/audit` | `status=ok`, `degraded` or `off`, with counts (`queued`, `sent`, `dropped_queue_full`, `dropped_rejected`, `dropped_at_shutdown`, `failed_attempts`); 503 while degraded | An availability test or alert on the audit sink. Degraded means a minute of failure with no success |
| `/healthz/notify` | `status=ok`, `degraded` or `off`, with counts (`queued`, `delivered`, `failed`, `unknown`, `dropped_queue_full`, `dropped_at_shutdown`, `rate_limited`, `not_allowed`, `invalid`, `failed_attempts`); 503 while degraded | An availability test on email. A failing sender is never emailed about |

## Logs

Keyring writes to standard output only, one line per entry, as `key=value` text or, with `KEYRING_LOG_FORMAT=json`, one JSON object per line.

- One request line per request: method, path (never the query string), status and time. A 5xx is logged at `warn`.
- One audit event per audited request (section 5.4 and appendix B), at every log level, so `warn` or `error` can't drop them.

| Host | Where | Table |
|---|---|---|
| Container Apps | The workspace the template creates | `ContainerAppConsoleLogs_CL` (or `ContainerAppConsoleLogs`) |
| App Service, with `logAnalyticsWorkspaceId` | That workspace | `AppServiceConsoleLogs`, `AppServiceHTTPLogs` |
| App Service, without it | The app's own file system, 7 days | None |
| Audit sink, when on | Any workspace (`auditWorkspaceId`) | `KeyringAudit_CL`, typed columns, its own retention |

Without a workspace, App Service's file log is the only record of who revealed what, and it is short. Use a workspace for anything to look back on.

## Alerts and Sentinel

- **Expiry alerts** (`infra/alerts/main.bicep`): Event Grid to an action group, or to Keyring's webhook which emails through ACS.
- **Access alerts** (`infra/alerts/access.bicep`): watched secret reads, purges and repeated refusals, as Azure Monitor log search rules on the vault's workspace. Logs arrive 5 to 15 minutes late.
- **Sentinel** (`infra/sentinel`): the ASIM parser `vimAuditEventKeyring`, analytic rules (many reveals by one person, reveal from a new address, one person denied in several vaults, sensitive action outside working hours, forged or cross-site requests, no audit events while Key Vault saw Keyring, SecretGet with no audit event, and a share to a guest or more than `shareThreshold` shares by one person), hunting queries for each audit report and a workbook. Every rule is created off and turned on by its own parameter. Rows can arrive late; each rule looks back `ingestionDelayMinutes` further than it runs.

## Notification health

With `health` in `KEYRING_NOTIFY_TYPES`, Keyring emails `KEYRING_NOTIFY_ADMINS` (and nobody else) when:

| Email | When | What to do |
|---|---|---|
| Audit sink failing | Degraded for over five minutes | Check the identity still has Monitoring Metrics Publisher on the rule and the endpoint can be reached |
| Audit sink recovered | Sending again after an emailed incident | Events dropped meanwhile are still on standard output |
| Many refused requests | More than `KEYRING_NOTIFY_BURST_THRESHOLD` (default 20) refused or denied events from one person, or one address with nobody signed in, in 15 minutes | Open the linked report and check whether it was them, a script, someone probing, a stolen session or a scanner |
| Client secret expires soon | 30, 14, 7 and 1 days before `KEYRING_CLIENT_SECRET_EXPIRES` | Rotate the secret, or move to the managed identity |
| Client secret has expired | The date has passed | As above; nobody can sign in until it is replaced |

When email itself can't be sent, Keyring logs one `warn` line and `/healthz/notify` answers 503. Point a probe at both health endpoints to hear about either without email.

## Rotation of Keyring's own secrets

| Secret | How | Effect |
|---|---|---|
| Entra client secret | Make a new one in the app registration, set it in the config vault with its expiry, restart, check sign-in, delete the old one. Set `KEYRING_CLIENT_SECRET_EXPIRES` to the same date | Everyone is signed out by the restart |
| Federated credential | Nothing to rotate. The identity's tokens are short-lived and renewed by the platform. When replacing the identity, add a credential for the new one first, then delete the old one's | None |
| Moving to the managed identity | Add the federated credential, redeploy with `useFederatedCredential=true` (Container Apps: two runs with `keepClientSecretEntry`), then delete the client secret | Removes the only long-lived credential |
| `SESSION_SECRET` | Set a new value in the config vault and restart | Everyone is signed out; sign-ins in progress restart. `session_ref` values change |

## Upgrade

Build and push a new image (or take a released one and verify its attestation with `gh attestation verify`), change `image` to the new digest, and run the same `az deployment group create`. Sessions are in memory, so people are signed out on each restart. The image's `org.opencontainers.image.revision` label says which commit is running. Read `CHANGELOG.md` for changes, especially audit schema changes and new settings.

## Removal

Delete Keyring's resource group, or the resources listed in `docs/deploy.md`. Then remove the app registration (or its federated credential and secrets), the Event Grid subscriptions that point at the webhook, the Sentinel content and the access alert rules if they were deployed. The config vault has purge protection, so its name stays reserved for 90 days.

## Backup

**There is no Keyring data to back up.** Keyring has no database and writes nothing to disk; everything it holds is in memory and rebuilt from Azure on demand. People's secrets, certificates, keys and their tags (including descriptions and owners) live in their own vaults, under those vaults' own soft delete and backup arrangements.

What to keep:

- the filled-in Bicep parameter files (they hold tenant IDs and names, not secrets) and the image digest in use;
- the app registration's settings: redirect URIs, exposed scope, API permissions, app role and federated credential;
- the config vault (soft delete and purge protection are on), which holds the client secret and session secret;
- `KeyringAudit_CL` and the console log tables, under the workspace's own retention;
- Event Grid subscriptions, alert rules and Sentinel content, which are redeployable from `infra/`.

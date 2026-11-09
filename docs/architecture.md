# Architecture

Keyring is a stateless web app. It holds a session for the signed-in person and nothing else.

## Principles

- **Act as the user.** Every Azure call uses a token obtained through the on-behalf-of (OBO) flow. Keyring has no identity of its own with data-plane or control-plane access.
- **Store nothing.** No database. Secret values pass through memory on the way to the browser and are never logged, cached or written to disk.
- **Let Key Vault decide.** Authorisation is Key Vault RBAC (or access policies on older vaults). Keyring shows what Azure allows and explains clearly when it doesn't.
- **Safe by default.** Purge is off. Deletes need typed confirmation. Secret values are hidden until revealed and the clipboard clears itself.

## Request flow

1. The browser signs in with Entra ID using OIDC (authorisation code flow with PKCE).
2. The server keeps the user's tokens in an encrypted, http-only session cookie or a server-side memory session. Nothing is persisted.
3. For each Azure call, the server exchanges the user's token via OBO for a token scoped to:
   - `https://vault.azure.net/.default` for Key Vault data plane
   - `https://management.azure.com/.default` for ARM and Resource Graph
4. Results go back to the browser. Errors from Azure (403, 404, throttling) are mapped to plain-English messages.

## Components

| Part         | Job                                                                                                     |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| Web UI       | Pages for vaults, secrets, certificates, keys, expiry, generator and audit                              |
| Server / BFF | Session handling, OBO exchange, thin proxies to Azure SDKs                                              |
| Azure SDKs   | `@azure/keyvault-secrets`, `-certificates`, `-keys`, `@azure/arm-resourcegraph`, `@azure/monitor-query` |

## Stack

| Choice                                             | Why                                                                                                                                                       |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Next.js (App Router), TypeScript strict            | Pages render on the server, so tokens never reach the browser. Route handlers and server actions give us a backend for frontend without a second service. |
| Node.js runtime only                               | The Azure SDKs and MSAL need Node. No edge runtime.                                                                                                       |
| `@azure/msal-node`                                 | Maintained by Microsoft. Handles the auth code flow with PKCE, token validation and the on-behalf-of exchange. We don't hand-roll any of it.              |
| In-memory server session, sealed session ID cookie | Nothing is persisted. A restart signs everyone out, which is fine for this app.                                                                           |
| Tailwind CSS                                       | Small, no runtime, easy to keep contrast and focus styles consistent. Components are written in the repo rather than pulled from a large library.         |
| Vitest and Testing Library                         | Fast unit tests for server helpers and components.                                                                                                        |
| ESLint (Next config) and Prettier                  | Standard lint and format. `no-console` is on so nothing logs by accident.                                                                                 |

Cache Components is off. Every page depends on who's signed in, so there's nothing useful to prerender, and we don't want any response cached.

Folder layout:

```
app/          pages, layouts and route handlers
components/   shared UI
lib/auth/     sign-in, session and token handling (server only)
lib/azure/    thin wrappers over the Azure SDKs (server only)
```

## Vault discovery

Azure Resource Graph query over every subscription the user can see:

```kusto
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, resourceGroup, subscriptionId, location, properties.enableRbacAuthorization, properties.enableSoftDelete, properties.enablePurgeProtection
```

## Audit

The audit view reads Key Vault diagnostic logs (`AzureDiagnostics` or the `AZKVAuditLogs` resource-specific table) from the Log Analytics workspace linked to each vault, again as the signed-in user. If the user can't read the workspace, the page says so.

## Alerts

Expiry alerts are optional. Since Keyring stores nothing and has no identity of its own, alerts are delivered by Azure-native means (Event Grid `SecretNearExpiry` and `CertificateNearExpiry` events), set up through the deploy templates. The app itself never runs background jobs with stored credentials.

## Deploy

- Docker image, non-root, read-only filesystem friendly.
- Bicep for Azure App Service or Azure Container Apps, with optional private endpoint and VNet integration so Keyring can reach private vaults.

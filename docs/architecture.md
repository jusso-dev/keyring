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

| Part | Job |
| --- | --- |
| Web server | Axum on Tokio. Routes for vaults, secrets, certificates, keys, expiry, generator and audit |
| Pages | Askama templates compiled into the binary. Plain hand-written CSS |
| Browser script | One small hand-written vanilla JS file for copy to clipboard with auto clear and similar extras. Pages work without it |
| Sign-in | `openidconnect` crate, authorisation code flow with PKCE |
| Azure calls | `reqwest` with rustls, calling the Key Vault, Resource Graph, ARM and Log Analytics REST APIs. Official `azure_*` crates only where they're stable enough |
| Sessions | In-memory store keyed by a random cookie. Nothing persisted |

## Stack and why

Keyring is Rust so the dependency tree stays small and auditable. Next.js and the npm ecosystem were ruled out: a typical app pulls in hundreds of packages, many with install scripts, and that's a lot of trust to extend for a tool that handles secrets.

Rules for the codebase:

- No npm, no Node toolchain, no bundler, no CDN scripts, no Tailwind.
- Server-rendered HTML first. JavaScript is an optional extra, hand-written and served from the same origin under a strict CSP.
- No `unsafe` code in the crate (`forbid` lint).

## Code layout

| Path | What's in it |
| --- | --- |
| `src/main.rs` | Start-up: load config, start logging, bind and serve |
| `src/lib.rs` | `AppState` and the router, so tests can drive the app without a socket |
| `src/config.rs` | Typed config from environment variables. Fails fast with a list of what's missing |
| `src/secret.rs` | `Secret`, a string wrapper whose `Debug` and `Display` print `[redacted]` |
| `src/routes/` | Axum handlers, one file per area |
| `src/auth/` | Sign-in and sessions |
| `src/azure/` | On-behalf-of exchange and REST clients for Azure |
| `templates/` | Askama templates, compiled into the binary |
| `static/` | Hand-written CSS (and later one small JS file), embedded in the binary with `include_str!` |

Static files are compiled in rather than read from disk, so the container needs no writable or readable app directory and nothing can be swapped at run time.

Logging uses `tracing`. Only metadata is logged (method, path, status, timing). Request and response bodies, headers and query strings are never logged.

`unsafe_code` is set to `forbid` in `Cargo.toml` lints, which has the same effect as `#![forbid(unsafe_code)]` on every target in the crate.

## Sign-in and sessions

- `/auth/start` builds the Entra authorise URL with the `openidconnect` crate: authorisation code flow, PKCE (S256), random state and nonce. It asks for `openid profile offline_access` and Keyring's own API scope, so the access token can later be exchanged on behalf of the user.
- State, nonce, PKCE verifier and the return path go in a short-lived (10 minute) cookie, encrypted with AES-256-GCM using a key derived from `SESSION_SECRET` (HKDF-SHA256). The cookie name is bound in as associated data.
- `/auth/callback` checks the state in constant time, swaps the code for tokens and has the crate verify the ID token: signature against the tenant's published keys, issuer, audience, expiry and nonce. If the signature check fails the cached keys are dropped so a key rollover is picked up on the next try.
- Sessions live in server memory. The browser only gets a random 256-bit ID in an http-only, `SameSite=Lax` cookie (`Secure` and `__Host-` prefixed over HTTPS). Tokens never leave the server. Sessions end after an hour idle or 12 hours in total. A restart signs everyone out; running several copies needs sticky sessions.
- Every route except sign-in, callback, signed-out, `/healthz` and `/static` sits behind a middleware that requires a session. Without one, GET requests are sent to sign-in with the path remembered. Return paths must be local (`/` but not `//`, no backslashes or control characters).
- Sign-out is a form post with a per-session token. It drops the session here, then sends the browser to Entra's end-session endpoint, which returns to `/auth/signed-out`.
- `ENTRA_AUTHORITY_HOST` (default `https://login.microsoftonline.com`) exists so tests can point at a mock identity provider.

## On-behalf-of tokens

- `azure::TokenBroker` swaps the user's access token (issued for Keyring's own API scope at sign-in) for a token scoped to Key Vault, ARM or Log Analytics, using the OBO grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`, `requested_token_use=on_behalf_of`).
- If the user's own token has less than five minutes left, the broker refreshes it with the refresh token first, keeping any rotated refresh token.
- Exchanged tokens are cached in the session, in memory, per resource, and reused until five minutes before expiry. Sessions never share tokens.
- Entra errors are mapped: `interaction_required`, `invalid_grant` and `login_required` mean sign in again (MFA, conditional access, revoked or expired refresh token). `consent_required` and AADSTS 65001, 65004 and 650057 mean an admin must consent. Only the error code is logged, never the description.
- There is no client-credentials grant, managed identity or app-only token in the Azure data path. The client secret is only used to authenticate the OBO and refresh requests.
- Tokens live in `AccessToken` and `Secret` wrappers whose `Debug` and `Display` print `[redacted]`.

### Plain REST, not the `azure_*` crates

`azure::AzureClient` calls the Key Vault, ARM, Resource Graph and Log Analytics REST APIs directly with `reqwest`. The official Rust SDK crates are still in beta, change often between releases and pull in a large dependency tree of their own, including their own identity and HTTP layers we'd have to work around to plug in OBO tokens. The REST APIs Keyring uses are a handful of stable, versioned endpoints, so a thin typed wrapper is less code to trust. We'll revisit when the SDK reaches a stable 1.0.

The client attaches the user's token to every call. On a 401 it drops the cached token, gets a fresh one and tries once more. Error replies keep the status and Azure's error code for the UI; Azure's message is shown to the user but not logged, since it can name items.

Concurrent requests in one session can each refresh the user's token at the same moment. That's harmless (Entra keeps old refresh tokens valid for a while) and not worth a lock yet.

## HTTP client and TLS

All outbound calls use one `reqwest` client on rustls with the `ring` crypto provider (no OpenSSL, no aws-lc). It has connect and total timeouts, does not follow redirects and refuses plain HTTP except to localhost. Errors from the client are logged without URLs or bodies.

## Supply chain

- `Cargo.lock` committed. Builds use `--locked`.
- Toolchain pinned in `rust-toolchain.toml`.
- `cargo deny check` covers licences (allow-list), advisories, bans and sources (crates.io only). `cargo audit` runs as well. Both run in CI and fail the build.
- Adding a crate needs a reason in the PR. Prefer crates that are widely used, maintained and light on dependencies.
- Dependabot opens weekly, grouped updates for `cargo`, `docker` and `github-actions`.
- GitHub Actions are pinned by full commit SHA.
- CI produces a CycloneDX SBOM for the image (Syft) and keeps it as a build artifact. Signed build provenance is left for the deploy milestone, when there's an image to publish.

### Dependency policy

What CI checks, on every PR, every push to `main` and weekly:

| Check | Tool | Fails when |
| --- | --- | --- |
| Licences | `cargo deny` | A crate's licence isn't on the allow-list in `deny.toml` (permissive licences only) |
| Advisories | `cargo deny`, `cargo audit` | A crate has a RustSec advisory, is unmaintained or is yanked |
| Bans | `cargo deny` | A banned crate turns up (`openssl`, `native-tls`) or a dependency uses a `*` version |
| Sources | `cargo deny` | A crate comes from anywhere other than crates.io |
| Lock file | `--locked` | `Cargo.lock` is out of date |

Duplicate versions of the same crate are reported as warnings, not failures. Trim them when it's easy.

To add a crate:

1. Check you need it. A few lines of our own code often beat a new dependency.
2. Prefer crates that are widely used, actively maintained and pull in little else. Turn off default features and enable only what's used.
3. Run `cargo deny check` and `cargo audit` locally.
4. In the PR, say what the crate is for and what it adds to `Cargo.lock`.

To accept an advisory that doesn't affect Keyring, add its ID to `ignore` in `deny.toml` with a comment saying why, and link an issue to revisit it.

## Container

- Multi-stage Dockerfile. Builder and runtime images pinned by digest.
- Static binary (musl or static glibc) on `gcr.io/distroless/static` (nonroot) or `scratch`.
- Runs as non-root, with a read-only root filesystem and no extra capabilities. No shell in the runtime image.
- `/healthz` for probes.

## Local development

- `cargo run` with a `.env` file, or `docker build` and `docker run --env-file .env --read-only`.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass before a PR merges.

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

- The Docker image described above.
- Bicep for Azure App Service or Azure Container Apps, with optional private endpoint and VNet integration so Keyring can reach private vaults.

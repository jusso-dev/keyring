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
- `ENTRA_AUTHORITY_HOST` (default `https://login.microsoftonline.com`) exists so tests can point at a mock identity provider. `KEYRING_TEST_MANAGEMENT_URL` and `KEYRING_TEST_KEYVAULT_URL` do the same for ARM and Key Vault. Leave all three unset in real deployments. Plain `http://` is only accepted for localhost.

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
- CI produces two CycloneDX SBOMs as build artifacts: one from `Cargo.lock` listing every crate in the binary (`cargo cyclonedx`), and one for the image's base packages (Syft). An image scan alone can't see the crates, since they're compiled into one stripped binary. Signed build provenance is left for the deploy milestone, when there's an image to publish.

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

Built by `Dockerfile` and checked in CI on every change: non-root numeric user, no shell, under 30 MB, and a smoke test with `--read-only --cap-drop ALL --security-opt no-new-privileges` that checks `/healthz` answers without sign-in and `/` redirects to sign-in. Size today is about 15 MB.

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

Results are fetched in pages of 1000 (the Resource Graph maximum), following `$skipToken` up to 100 pages. A second query reads subscription names from `resourcecontainers`; if that fails the list still shows, with subscription IDs instead of names. Missing flags take Azure's defaults (soft delete on, RBAC and purge protection off).

The list is filtered on the server (name or resource group, subscription, tag as `key` or `key=value`) and shown 200 to a page. The one JavaScript file, `static/app.js`, also filters the visible rows as you type; without it the form submits and the server filters.

The chosen vault is kept in the session only. Its name is checked against Key Vault naming rules before it's stored or put into a URL. Seeing a vault in Resource Graph only needs the ARM Reader role, so opening it can still fail with 403 on the data plane; the secrets pages handle that with the role to ask for.

## Secrets

Keyring calls the Key Vault secrets REST API (version 7.5) directly as the user.

- The list uses `GET /secrets`, which returns properties only, in pages of 25 following `nextLink`. A `nextLink` is only followed if it points at the same vault.
- A secret's page reads `GET /secrets/{name}/versions` and shows the newest version. That call never returns values, so opening a page doesn't read the secret.
- Values are only read by the reveal action (next issue).
- Names from URLs are checked against Key Vault's rules (letters, digits and hyphens, up to 127) and versions must be 32 hex characters, before they go into a request.
- "Expiring soon" means within 30 days. Dates are shown in UTC.
- Filters (name, tag, expired or expiring, disabled) run on the server, with the same filter-as-you-type extra as the vault list.

## Certificates

- The list and pages use the certificates API (7.5), which only returns the public certificate. Subject, issuer, validity, serial and other names are read from the DER with `x509-cert` (RustCrypto, pure Rust, reuses `der` and `spki` already in the tree).
- Expiry bands: expired, within 30 days, within 90 days.
- `.cer` (DER) and PEM downloads are the public certificate only, and need certificate read access.
- The private key lives in the certificate's backing secret. "Download with private key" is only offered when the policy marks the key exportable. It shows a warning and needs the name typed, then reads the backing secret (so it also needs secret read access) and sends it with `no-store`. The backing secret URL from Key Vault is only used if it points at the same vault and name. Each download logs at `warn` with subject, vault and name.

## Keys

- Keyring only ever reads keys with `GET /keys/{name}` and the list and versions calls, which return the public part. There is no export, backup, release, decrypt, unwrap or sign call anywhere; a test checks the keys client source for them.
- The JWK type only has public fields (`n`, `e`, `crv`, `x`, `y`). Any private field Key Vault might send is dropped while parsing.
- Public keys are shown as JWK and as PEM (SubjectPublicKeyInfo). The PEM is built with a few lines of DER encoding and tested byte for byte against openssl output for RSA and EC.
- Create defaults to RSA 3072 with every RSA operation, or sign and verify for EC. Rotate now and the rotation policy (rotate after, expiry, near-expiry event) use Key Vault's own rotation API.

## Audit

The audit view reads Key Vault diagnostic logs (`AzureDiagnostics` or the `AZKVAuditLogs` resource-specific table) from the Log Analytics workspace linked to each vault, again as the signed-in user. If the user can't read the workspace, the page says so.

- The vault's diagnostic settings are read through ARM to find workspaces receiving `AuditEvent` (or the `audit` or `allLogs` category groups). "Dedicated" destinations use `AZKVAuditLogs`, others `AzureDiagnostics`.
- Queries go to the Log Analytics resource-centric endpoint (`/v1/<workspace ARM ID>/query`) with the user's OBO token for `https://api.loganalytics.io/.default`.
- **No query injection.** Filters are checked against strict patterns first (names: letters, digits and hyphens; people: letters, digits, `@ . _ -`; actions: a fixed list), so anything else is refused before a query is sent. Values then appear only as escaped string literals in `let` lines at the top of the query; the rest of the KQL is fixed text. Time ranges come from a fixed list.
- Operations are shown in plain words ("Viewed secret value" for `SecretGet`). Up to 500 most recent rows. CSV export uses the same query and rows, with formula guarding.
- Each secret, certificate and key page has "Who used it", which opens the audit view filtered to that item for the last 30 days.

## Alerts

Expiry alerts are optional. Since Keyring stores nothing and has no identity of its own, alerts are delivered by Azure-native means (Event Grid `SecretNearExpiry` and `CertificateNearExpiry` events), set up through the deploy templates. The app itself never runs background jobs with stored credentials.

## Deploy

- The Docker image described above.
- `infra/app-service` and `infra/container-apps`: Bicep that runs the image, with Keyring's own config vault and a user-assigned managed identity. That identity can only read Keyring's two config secrets (client secret and session secret) through Key Vault references. It has no role on any other vault, so it can't be used to reach user data.
- Optional VNet integration, private endpoints and private DNS so Keyring can reach private vaults (`docs/private-vaults.md`).
- `infra/alerts`: optional per-vault Event Grid subscription for near-expiry events (`docs/alerts.md`).
- CI runs `az bicep build` on every template and example parameter file. Nothing is deployed from this repository.

## Threat model

What Keyring protects, who it protects it from, and how. This is a summary for reviewers, not a guarantee.

### What's worth protecting

- **Secret values, private keys and certificates** in people's vaults.
- **People's Entra tokens**: their access token for Keyring's API, refresh tokens, and the Key Vault, ARM and Log Analytics tokens exchanged from them.
- **Keyring's own secrets**: the Entra client secret and the session secret.

### Trust boundaries

- **The browser** is trusted only with a random session ID in an http-only cookie. It never sees tokens.
- **Keyring's server** holds tokens in memory for each session and passes secret values through memory on the way to the browser. It has **no access of its own** to any vault.
- **Azure** (Entra ID, Key Vault, ARM, Log Analytics) makes every authorisation decision, as the signed-in person.

### Threats and what stops them

| Threat | Mitigation |
| --- | --- |
| Keyring used to reach vaults a person can't | Every Azure call carries the person's own OBO token. Keyring has no managed identity, service principal or app-only token with vault access. Its deployment identity can only read its own two config secrets |
| Stolen session cookie | Random 256-bit ID, http-only, `SameSite=Lax`, `Secure` and `__Host-` prefixed over HTTPS. One hour idle and 12 hour absolute timeouts. Sign-out removes the session server-side |
| Cross-site request forgery | Every state-changing form has a per-session token checked in constant time, **and** a middleware refuses any non-GET request whose `Origin` (or `Referer`) isn't Keyring's own. Tested for every mutating route |
| Open redirects after sign-in | Return paths must be local paths; absolute URLs, `//host`, backslashes and control characters fall back to `/` |
| Forged or replayed sign-in | PKCE (S256), state and nonce; ID token signature, issuer, audience and expiry checked by `openidconnect`. Sign-in state rides in an AES-256-GCM sealed cookie bound to its name |
| Cross-site scripting | Askama escapes all output. CSP `default-src 'none'` with scripts and styles from this site only, no inline code, no `eval`. The one script uses no `innerHTML` (tested) |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Log forging | OAuth error codes from query strings are only kept if they look like codes; error strings are logged with escaping so a crafted value can't start a new log line |
| Secret values or tokens in logs | Values and tokens live in `Secret` and `AccessToken`, which print `[redacted]`. Only metadata is logged. A test captures all `tracing` output at TRACE during reveals, uploads, generation and errors and checks no value, token, password or Azure message appears |
| Values cached by browsers or proxies | `Cache-Control: no-store` on every HTML page, reveal, download and CSV |
| Values left on screen or clipboard | Hidden until asked for; revealed values are wiped after 30 seconds or on leaving the page, and the clipboard is cleared if it still holds the value |
| Accidental or malicious deletes | Typed-name confirmation checked on the server. Purge is refused by the server unless `KEYRING_ALLOW_PURGE=true` |
| Private key leaks | Keys: no export, backup, release, decrypt, unwrap or sign calls exist (tested); the JWK type has no private fields. Certificates: private key download only for exportable policies, after a warning and typed name. A certificate's backing secret can't be revealed, rolled back, changed or deleted through the secrets pages |
| Query injection in the audit view | Filters checked against strict patterns, then used only as escaped string literals in `let` lines. The rest of the KQL is fixed |
| CSV injection in exports | Fields starting with `= + - @` are prefixed so spreadsheets don't run them |
| Path tricks in names | Vault, secret, certificate, key and version names are checked against Key Vault's own rules before they go in any URL. `nextLink` and backing secret URLs are only followed on the same vault |
| Large or slow requests | Request headers must arrive within 10 seconds (slow-header clients are cut off). 64 KB body limit on forms (256 KB for certificate uploads). 90 second limit per request. Outbound calls have 10 second connect and 30 second total timeouts, and don't follow redirects |
| Supply chain | Few crates, all from crates.io, licence allow-list, `cargo deny` and `cargo audit` on every change and weekly, `Cargo.lock` and toolchain pinned, actions pinned by SHA, images pinned by digest, SBOM per build. No npm |
| Memory safety | `unsafe` code is forbidden in the crate |
| Container escape or tampering | Distroless static image, no shell, non-root, read-only root filesystem, no capabilities |

### Known limits

- **Sessions are in memory.** A restart signs everyone out, and several copies need sticky sessions. Anyone who can read the server's memory can read active tokens.
- **The session secret** only protects short-lived cookies (sign-in state, flash messages, pending uploads). Rotating it signs no one out but cancels sign-ins in progress.
- Keyring trusts Azure's answers. A compromised Entra tenant or Key Vault is out of scope.

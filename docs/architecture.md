# Architecture

Keyring is a stateless web app. It holds a session for the signed-in person and nothing else.

## Principles

- **Act as the user.** Every Azure call uses a token obtained through the on-behalf-of (OBO) flow. Keyring has no identity of its own with data-plane or control-plane access.
- **Store nothing.** No database. Secret values pass through memory on the way to the browser and are never logged, cached or written to disk.
- **Let Key Vault decide.** Authorisation is Key Vault RBAC (or access policies on older vaults). Keyring shows what Azure allows and explains clearly when it doesn't.
- **Safe by default.** Purge is off. Deletes need typed confirmation. Secret values are hidden until revealed, and Keyring tries to clear the clipboard after a copy.

## Request flow

1. The browser signs in with Entra ID using OIDC (authorisation code flow with PKCE).
2. The server keeps the user's tokens in a server-side memory session. The browser only holds a random session ID. Nothing is persisted.
3. For each Azure call, the server exchanges the user's token via OBO for a token scoped to:
   - `https://vault.azure.net/.default` for Key Vault data plane
   - `https://management.azure.com/.default` for ARM and Resource Graph
   - `https://api.loganalytics.io/.default` for Log Analytics (the audit view)
4. Results go back to the browser. Errors from Azure (403, 404, throttling) are mapped to plain-English messages.

Keyring works with the Azure public cloud only: these hosts, `login.microsoftonline.com` and `<vault>.vault.azure.net` are fixed in the code. Sovereign clouds and managed HSM aren't supported.

## Components

| Part | Job |
| --- | --- |
| Web server | Axum on Tokio. Routes for vaults, secrets, certificates, keys, expiry, generator and audit |
| Pages | Askama templates compiled into the binary. Plain hand-written CSS |
| Browser script | One small hand-written vanilla JS file for copy to clipboard, clearing it again, and similar extras. Pages work without it |
| Sign-in | `openidconnect` crate, authorisation code flow with PKCE |
| Azure calls | `reqwest` with rustls, calling the Key Vault, Resource Graph, ARM and Log Analytics REST APIs directly. No `azure_*` crates (see below) |
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
| `static/` | Hand-written CSS and one small JS file, embedded in the binary with `include_str!` |

Static files are compiled in rather than read from disk, so the container needs no writable or readable app directory and nothing can be swapped at run time.

Logging uses `tracing`, as plain text lines on standard output. Two kinds of line are written:

- one per request, `request method=GET path=/secrets status=200 ms=12`. The path never has the query string. Requests that end in a 5xx are logged at `warn`, the rest at `info`.
- an action line for each change or read of a value, naming who did it and what (vault and item name). The person is `subject=oid:<object ID>,tid:<tenant ID>` from the ID token, the same IDs Entra's sign-in logs and Key Vault's diagnostic logs use. Without those claims it falls back to `sub:<subject>`.

Request and response bodies, headers, query strings, secret values, tokens and Azure's error messages are never logged. Vault and item names do appear. `KEYRING_LOG_LEVEL` is checked at start against `error`, `warn`, `info`, `debug` and `trace`; `off` and filter strings are refused, so the action lines can't be turned off by mistake. Where the lines end up on each host is in [deploy.md](deploy.md#logs).

Release builds unwind on a panic rather than abort, so one request that hits a bug gets a 500 page and every other session carries on. Keyring's own panic hook logs only where the panic happened, never its message, since that can hold request data.

Static files are served from `/static/` with a version in the query string, taken from a hash of the file's contents. A request with the current version is cached for a year (`immutable`), since a new build changes the URL. Without it, or with an old one, the current file comes back with a five-minute cache. HTML pages, reveals, downloads and CSVs are `no-store`.

`unsafe_code` is set to `forbid` in `Cargo.toml` lints, which has the same effect as `#![forbid(unsafe_code)]` on every target in the crate.

## Sign-in and sessions

- `/auth/start` builds the Entra authorise URL with the `openidconnect` crate: authorisation code flow, PKCE (S256), random state and nonce. It asks for `openid profile offline_access` and Keyring's own API scope, so the access token can later be exchanged on behalf of the user.
- State, nonce, PKCE verifier and the return path go in a short-lived (10 minute) cookie, encrypted with AES-256-GCM using a key derived from `SESSION_SECRET` (HKDF-SHA256). The cookie name is bound in as associated data.
- `/auth/callback` checks the state in constant time, swaps the code for tokens and has the crate verify the ID token: signature against the tenant's published keys, issuer, audience, expiry and nonce. An `error=` reply is only acted on when its `state` matches the sign-in in progress.
- Entra's metadata and signing keys are cached for an hour, and concurrent sign-ins share one fetch. If an ID token is signed with a key that isn't in the cache, the cache is marked out of date, the keys are fetched again and the same sign-in is checked once more, so a key rollover doesn't fail anyone. If a fetch fails, the last good copy is kept and Keyring waits 30 seconds before trying again.
- Sessions live in server memory. The browser only gets a random 256-bit ID in an http-only, `SameSite=Lax` cookie (`Secure` and `__Host-` prefixed over HTTPS). Tokens never leave the server. Sessions end after an hour idle or 12 hours in total. A task drops expired sessions, with their tokens, every minute. A restart signs everyone out; running several copies needs sticky sessions.
- Sealed cookies (sign-in state and one-off messages) carry the time they were made, and the server refuses them once they're too old (10 minutes for sign-in, one minute for messages), whatever the browser does with `Max-Age`.
- A form posted after the session ended goes back to sign-in, and then to the form's page, with a message that nothing was saved.
- Every route except sign-in, callback, signed-out, `/healthz` and `/static` sits behind a middleware that requires a session. Without one, GET requests are sent to sign-in with the path remembered. Return paths must be local (`/` but not `//`, no backslashes or control characters).
- Sign-out is a form post with a per-session token. It drops the session here, then sends the browser to Entra's end-session endpoint, which returns to `/auth/signed-out`.
- `ENTRA_AUTHORITY_HOST` (default `https://login.microsoftonline.com`) exists so tests can point at a mock identity provider. `KEYRING_TEST_MANAGEMENT_URL`, `KEYRING_TEST_KEYVAULT_URL` and `KEYRING_TEST_LOGANALYTICS_URL` do the same for ARM, Key Vault and Log Analytics. Leave all four unset in real deployments; Keyring logs a warning at start naming any that are set. Plain `http://` is only accepted for localhost.

## On-behalf-of tokens

- `azure::TokenBroker` swaps the user's access token (issued for Keyring's own API scope at sign-in) for a token scoped to Key Vault, ARM or Log Analytics, using the OBO grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`, `requested_token_use=on_behalf_of`).
- If the user's own token has less than five minutes left, the broker refreshes it with the refresh token first, keeping any rotated refresh token.
- Exchanged tokens are cached in the session, in memory, per resource, and reused until five minutes before expiry. Sessions never share tokens.
- Concurrent requests in one session, such as the expiry dashboard reading several vaults at once, share one refresh and one exchange per resource. If that call fails, the requests waiting on it get the same answer instead of each trying in turn. A request that arrives later tries again.
- Entra errors are mapped: `interaction_required` and `login_required` mean sign in again, and so does `invalid_grant` with an Entra error number a fresh sign-in fixes (MFA, conditional access, an expired or revoked refresh token). Any other `invalid_grant`, such as a wrong `ENTRA_API_SCOPE`, is shown as a setting for the admin. `consent_required` and AADSTS 65001, 65004 and 650057 mean an admin must consent. Only the error code is logged, never the description.
- There is no client-credentials grant, managed identity or app-only token in the Azure data path. Keyring's credential is only used to authenticate the sign-in code exchange, the refresh and the OBO request.
- That credential is either the client secret (`ENTRA_CLIENT_SECRET`) or, when `KEYRING_FEDERATED_IDENTITY_CLIENT_ID` is set, a short-lived token from a user-assigned managed identity that the app registration trusts as a federated credential. Keyring gets the token from the platform's local token service (`IDENTITY_ENDPOINT`, audience `api://AzureADTokenExchange`) and sends it as `client_assertion`, with `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, in place of `client_secret`. It never sends both. The token is cached until five minutes before it expires, one fetch at a time, and is held in a `Secret`.
- The local token service speaks plain HTTP, so it has its own HTTP client, separate from the HTTPS-only one. Keyring refuses to start unless `IDENTITY_ENDPOINT` is on `localhost`, `127.0.0.1` or `169.254.0.0/16`, so that client can't be pointed at the network.
- Tokens live in `AccessToken` and `Secret` wrappers whose `Debug` and `Display` print `[redacted]`.

### Plain REST, not the `azure_*` crates

`azure::AzureClient` calls the Key Vault, ARM, Resource Graph and Log Analytics REST APIs directly with `reqwest`. The official Rust SDK crates are still in beta, change often between releases and pull in a large dependency tree of their own, including their own identity and HTTP layers we'd have to work around to plug in OBO tokens. The REST APIs Keyring uses are a handful of stable, versioned endpoints, so a thin typed wrapper is less code to trust. We'll revisit when the SDK reaches a stable 1.0.

The client attaches the user's token to every call. On a 401 it drops the cached token, gets a fresh one and tries once more. Error replies keep the status and Azure's error code, which the UI maps to its own plain-English text.

Azure's own message is shown in one case only: a 400 on a write, under the form it came from, as "Key Vault said:". For a validation failure it is the only thing that names the field and the rule. The forms are certificate create and upload, key create and the key rotation policy. The message is cut to 500 characters and escaped as text, and the form keeps what was typed. It is never logged. It isn't shown on read paths or for 401, 403 and 404, where Keyring's own text is clearer and the message can name items the person can't see.

## HTTP client and TLS

All outbound calls use one `reqwest` client on rustls with the `ring` crypto provider (no OpenSSL, no aws-lc; `deny.toml` bans both). It has connect and total timeouts, does not follow redirects and refuses plain HTTP except to localhost. Errors from the client are logged without URLs or bodies.

- **Trust store.** Server certificates are checked against the operating system's roots (`rustls-platform-verifier`, which on Linux reads them with `rustls-native-certs`). Setting `SSL_CERT_FILE` (or `SSL_CERT_DIR`) replaces the system roots with that file or folder, which is how a private CA is trusted.
- **Proxies.** `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY` (and their lower-case forms) are read from the environment, as reqwest does by default. The managed identity's local token service is never reached through a proxy.
- **Inbound proxies.** `X-Forwarded-*` headers are ignored. `APP_BASE_URL` is the only source of Keyring's own origin.

## Supply chain

- `Cargo.lock` committed. Builds use `--locked`.
- Toolchain pinned in `rust-toolchain.toml`.
- `cargo deny check` covers licences (allow-list), advisories, bans and sources (crates.io only). `cargo audit` runs as well. Both run in CI and fail the build.
- Adding a crate needs a reason in the PR. Prefer crates that are widely used, maintained and light on dependencies.
- Dependabot opens weekly, grouped updates for `cargo`, `docker`, `rust-toolchain` and `github-actions`. The Rust toolchain and the Docker images share one pull request, so the builder image and `rust-toolchain.toml` move together. CI also fails if they differ.
- The repository has secret scanning with push protection and Dependabot security updates turned on, and its Actions settings refuse any action not pinned by SHA.
- GitHub Actions are pinned by full commit SHA. Tools that actions install are pinned by version, with no fallback download. The Bicep CLI is pinned by version and the Dockerfile frontend by digest.
- CI produces two CycloneDX SBOMs as build artifacts: one from `Cargo.lock` listing every crate in the binary (`cargo cyclonedx`), and one for the image's base packages (Syft). An image scan alone can't see the crates, since they're compiled into one stripped binary. Signed build provenance isn't set up, because this repository doesn't publish an image. Add it (for example GitHub artifact attestations) wherever you build and push your own.

### Dependency policy

What CI checks, on every PR, every push to `main` and weekly:

| Check | Tool | Fails when |
| --- | --- | --- |
| Licences | `cargo deny` | A crate's licence isn't on the allow-list in `deny.toml` (permissive licences only) |
| Advisories | `cargo deny`, `cargo audit` | A crate has a RustSec advisory, is unmaintained or is yanked |
| Bans | `cargo deny` | A banned crate turns up (`openssl`, `native-tls`, `aws-lc-rs`, `aws-lc-sys`) or a dependency uses a `*` version |
| Sources | `cargo deny` | A crate comes from anywhere other than crates.io |
| Lock file | `--locked` | `Cargo.lock` is out of date |

Duplicate versions of the same crate are reported as warnings, not failures, so they show in the CI log for review. There are several today. Trim them when it's easy.

To add a crate:

1. Check you need it. A few lines of our own code often beat a new dependency.
2. Prefer crates that are widely used, actively maintained and pull in little else. Turn off default features and enable only what's used.
3. Run `cargo deny check` and `cargo audit` locally.
4. In the PR, say what the crate is for and what it adds to `Cargo.lock`.

To accept an advisory that doesn't affect Keyring, add its ID to `ignore` in `deny.toml` with a comment saying why, and link an issue to revisit it.

## Container

Built by `Dockerfile` and checked in CI on every change: non-root numeric user, no shell, under 30 MB, and a smoke test with `--read-only --cap-drop ALL --security-opt no-new-privileges` that checks `/healthz` answers without sign-in and `/` redirects to sign-in. Size today is about 8 MB.

- Multi-stage Dockerfile. Builder and runtime images pinned by digest.
- Static musl binary on `gcr.io/distroless/static` (nonroot).
- `VERSION` and `VCS_REF` build arguments set the `org.opencontainers.image.version` and `org.opencontainers.image.revision` labels. CI passes the crate version and commit, and checks the labels.
- Runs as non-root, with a read-only root filesystem and no extra capabilities. No shell in the runtime image.
- `/healthz` for probes.

## Local development

- `cargo run` with a `.env` file, or `docker build` and `docker run --env-file .env --read-only`.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass before a PR merges. CI runs them with the supply chain, Bicep and container checks, and a ruleset on `main` requires a pull request with all four CI jobs passing on an up-to-date branch. Force pushes and deleting `main` are blocked.

## Vault discovery

Azure Resource Graph query over every subscription the user can see:

```kusto
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, resourceGroup, subscriptionId, location, properties.enableRbacAuthorization, properties.enableSoftDelete, properties.enablePurgeProtection
```

Results are fetched in pages of 1000 (the Resource Graph maximum), following `$skipToken` up to 100 pages. A second query reads subscription names from `resourcecontainers`; if that fails the list still shows, with subscription IDs instead of names. Missing flags take Azure's defaults (soft delete on, RBAC and purge protection off).

The list is filtered on the server (name or resource group, subscription, tag as `key` or `key=value`) and shown 200 to a page. The one JavaScript file, `static/app.js`, also filters the visible rows as you type; without it the form submits and the server filters.

The vault is in the address: every secrets, certificates, keys and audit page lives under `/v/{vault}/` (for example `/v/kv-prod/secrets/db-password`), and the vault in the address is the one that request acts on. So a link can be sent to a colleague, and two tabs can hold two vaults. Its name is checked against Key Vault naming rules before it's used or put into a URL, and a name that fails is "not found" without a request leaving Keyring. Keyring doesn't check Resource Graph for that name: Key Vault's own 403 or 404 on the first call covers a vault the person can't see, and the pages handle that with the role to ask for. Seeing a vault in Resource Graph only needs the ARM Reader role, so opening it can still fail with 403 on the data plane.

The session also remembers the vault last used. That is only for the side navigation links, and for the old addresses without a vault (`/secrets/db-password`), which answer with a 308 to the same page under that vault, or ask for a vault if none has been used. Handlers never read it to decide which vault to act on. The audit view keeps the vault's ARM resource ID with it, and only uses that copy when the address names the same vault.

## Secrets

Keyring calls the Key Vault secrets REST API (version 7.5) directly as the user.

- The list uses `GET /secrets`, which returns properties only, in pages of 25 following `nextLink`. A `nextLink` is only followed if it points at the same vault.
- A secret's page reads `GET /secrets/{name}/versions` and shows the newest version. That call never returns values, so opening a page doesn't read the secret.
- Values are only read by the reveal action, and by rollback, which copies an older version's value into a new version on the server without showing it.
- Names from URLs are checked against Key Vault's rules (letters, digits and hyphens, up to 127) and versions must be 32 hex characters, before they go into a request.
- "Expiring soon" means within 30 days. Dates are shown in UTC.
- Editing properties changes the current version. Key Vault can change a version's start and expiry dates but never remove them: it keeps a date sent as `null`. So the edit form refuses a removed date and says to set a new value with the date left blank, which makes a new version without it.
- Filters (name, tag, expired or expiring, disabled) run on the server, with the same filter-as-you-type extra as the vault list.

## Certificates

- The list and pages use the certificates API (7.5), which only returns the public certificate. Subject, issuer, validity, serial and other names are read from the DER with `x509-cert` 0.3 (RustCrypto, pure Rust). It brings its own `der` 0.8, `spki` 0.8 and `const-oid` 0.10, alongside the older versions other crates use, plus `tls_codec`.
- The list is read 25 at a time from Key Vault and shown 100 to a page.
- **Create.** The issuer is a select: Self, plus the vault's own issuers from `GET /certificates/issuers`. `Unknown` is refused on the server, since Keyring can't show the signing request or merge a signed certificate. If the issuer list can't be read (403 without Certificates Officer), only Self is offered, with a note saying why. A self-signed create comes back `inProgress` and shows as "Being created" until Key Vault finishes it, usually within seconds. `days_before_expiry` is checked against Key Vault's limit of 27 days per month of validity.
- **Pending requests.** A request waiting for its issuer can be stopped with "Cancel this request": a PATCH with `cancellation_requested: true`, then a DELETE of the operation, which frees the name.
- **Upload.** The file is read and shown as a preview before anything is sent: the leaf certificate's subject, issuer and dates, and if the name already exists, that the upload becomes a new version of it. A PEM must hold the certificate and an unencrypted PKCS #8 key (`BEGIN PRIVATE KEY`); PKCS #1 and SEC1 keys are refused with the openssl command that converts them, and the key must match the certificate. A BER-encoded PFX, which Keyring's own parser can't read, can still be uploaded, with a note that there's no preview. The file waits in the server-side session, never a cookie.
- **Enable and disable** set `attributes.enabled` on the current version.
- Expiry bands: expired, within 30 days, within 90 days.
- `.cer` (DER) and PEM downloads are the public certificate only, and need certificate read access.
- The private key lives in the certificate's backing secret. "Download with private key" is only offered when the policy marks the key exportable. It shows a warning and needs the name typed, then reads the backing secret (so it also needs secret read access) and sends it with `no-store`. The backing secret URL from Key Vault is only used if it is exactly `/secrets/{name}/{version}` on the same vault, with the certificate's name and a 32 hex character version. Each download logs at `warn` with subject, vault and name.

## Keys

- Keyring only ever reads keys with `GET /keys/{name}` and the list and versions calls, which return the public part. There is no export, backup, release, decrypt, unwrap or sign call anywhere; a test checks the keys client source for them.
- The JWK type only has public fields (`n`, `e`, `crv`, `x`, `y`). Any private field Key Vault might send is dropped while parsing.
- Public keys are shown as JWK and as PEM (SubjectPublicKeyInfo). The PEM is built with a few lines of DER encoding and tested byte for byte against openssl output for RSA and EC.
- Create defaults to RSA 3072 with every RSA operation, or sign and verify for EC. An HSM key on a Standard vault is refused by Key Vault (403, inner code `HardwareKeysNotSupported`), and the form says the vault needs the Premium tier.
- The list is read 25 at a time from Key Vault and shown 100 to a page.
- Rotate now and the rotation policy use Key Vault's own rotation API. The policy form rotates either a number of days after each version is made or a number of days before it expires, with an expiry and a near-expiry event. Durations Key Vault already holds (for example `P18M`) are sent back unchanged if the field wasn't changed. A policy with parts the form can't show, such as a time in hours, is listed on the page, and saving needs "Replace the whole policy" ticked. Key Vault's default policy (one Notify 30 days before expiry, no expiry) is shown as no policy set.
- **Enable and disable** set `attributes.enabled` on the current version.
- **Managed keys**, the ones Key Vault made for a certificate (`managed: true`), are refused on the server for delete, rotate, rotation policy and enable or disable, with a page that sends you to the certificate.

## Audit

The audit view reads Key Vault diagnostic logs (`AzureDiagnostics` or the `AZKVAuditLogs` resource-specific table) from the Log Analytics workspace linked to each vault, again as the signed-in user. If the user can't read the workspace, the page says so.

- The vault's diagnostic settings are read through ARM to find workspaces receiving `AuditEvent` (or the `audit` or `allLogs` category groups). "Dedicated" destinations use `AZKVAuditLogs`, others `AzureDiagnostics`.
- Queries go to the Log Analytics resource-centric endpoint (`/v1/<workspace ARM ID>/query`) with the user's OBO token for `https://api.loganalytics.io/.default`.
- **No query injection.** Filters are checked against strict patterns first (names: letters, digits and hyphens; people: letters, digits, `@ . _ -`; actions: a fixed list), so anything else is refused before a query is sent. Values then appear only as escaped string literals in `let` lines at the top of the query; the rest of the KQL is fixed text. Time ranges come from a fixed list.
- Operations are shown in plain words ("Viewed secret value" for `SecretGet`). Up to 500 most recent rows. CSV export uses the same query and rows, with formula guarding.
- When a vault logs to several workspaces and some can't be read, the others are still shown, and the page and the CSV say how many were left out and why. If none can be read, the CSV answers 403 or 404 with an explanation instead of an empty file.
- Each secret, certificate and key page has "Who used it", which opens the audit view filtered to that item for the last 30 days.

## Expiry dashboard

The dashboard reads secrets, certificates and keys from every vault the person can see, six vaults at a time. Each vault has 20 seconds and the whole page 60, so one slow or private vault can't hold up the rest. Vaults that couldn't be read, or ran out of time, are listed with the reason, on the page and in the CSV.

## Alerts

Expiry alerts are optional. Since Keyring stores nothing and has no identity of its own, alerts are delivered by Azure-native means (Event Grid `SecretNearExpiry` and `CertificateNearExpiry` events), set up through the deploy templates. The app itself never runs background jobs with stored credentials.

## Deploy

- The Docker image described above.
- `infra/app-service` and `infra/container-apps`: Bicep that runs the image, with Keyring's own config vault and a user-assigned managed identity. That identity can only read Keyring's two config secrets (client secret and session secret) through Key Vault references. It has no role on any other vault, so it can't be used to reach user data. With `useFederatedCredential`, the app registration also trusts this identity as a federated credential, so there is no client secret to read.
- Optional VNet integration, private endpoints and private DNS so Keyring can reach private vaults (`docs/private-vaults.md`).
- `infra/alerts`: optional per-vault Event Grid subscription for near-expiry events (`docs/alerts.md`).
- CI runs `az bicep build` on every template and example parameter file, and on each example copied next to its template the way the docs say. Nothing is deployed from this repository.

## Threat model

What Keyring protects, who it protects it from, and how. This is a summary for reviewers, not a guarantee.

### What's worth protecting

- **Secret values, private keys and certificates** in people's vaults.
- **People's Entra tokens**: their access token for Keyring's API, refresh tokens, and the Key Vault, ARM and Log Analytics tokens exchanged from them.
- **Keyring's own secrets**: the Entra client secret and the session secret.
- **The managed identity**, when Keyring uses it in place of a client secret. Whoever controls it can act as the Keyring app registration.

### Trust boundaries

- **The browser** is trusted only with a random session ID in an http-only cookie. It never sees tokens.
- **Keyring's server** holds tokens in memory for each session and passes secret values through memory on the way to the browser. It has **no access of its own** to any vault.
- **Azure** (Entra ID, Key Vault, ARM, Log Analytics) makes every authorisation decision, as the signed-in person.
- **The managed identity** (when used as the credential) can act as the Keyring app registration. That gives it no vault access today: the registration has only delegated permissions, and the on-behalf-of exchange needs a signed-in person's token. This holds only while the app registration has **no application permissions**. If one is ever added, the identity could use it with nobody signed in, so keep the registration delegated-only and treat a new application permission as a security change.

### Threats and what stops them

| Threat | Mitigation |
| --- | --- |
| Keyring used to reach vaults a person can't | Every Azure call carries the person's own OBO token. Keyring has no managed identity, service principal or app-only token with vault access. Its deployment identity can only read its own two config secrets |
| Stolen session cookie | Random 256-bit ID, http-only, `SameSite=Lax`, `Secure` and `__Host-` prefixed over HTTPS. One hour idle and 12 hour absolute timeouts. Sign-out removes the session server-side |
| Cross-site request forgery | Every state-changing form has a per-session token checked in constant time, **and** a middleware refuses any non-GET request whose `Origin` (or `Referer`) isn't Keyring's own. Tested for every mutating route. The token is bound to the vault in the address of the page the form was rendered on, and checked against the vault in the address it is posted to. A form posted to another vault's address is refused ("You switched vaults") instead of acting on that vault |
| Open redirects after sign-in | Return paths must be local paths; absolute URLs, `//host`, backslashes and control characters fall back to `/` |
| Forged or replayed sign-in | PKCE (S256), state and nonce; ID token signature, issuer, audience and expiry checked by `openidconnect`. Sign-in state rides in an AES-256-GCM sealed cookie bound to its name |
| Cross-site scripting | Askama escapes all output. CSP `default-src 'none'` with scripts and styles from this site only, no inline code, no `eval`. The one script uses no `innerHTML` (tested) |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Log forging | OAuth error codes from query strings are only kept if they look like codes; error strings are logged with escaping so a crafted value can't start a new log line |
| Secret values or tokens in logs | Values and tokens live in `Secret` and `AccessToken`, which print `[redacted]`, and are zeroised when dropped. The request log has method, path, status and duration only; action lines add the person's Entra `oid` and `tid` and the vault and item names. A panic logs only its location. A test captures all `tracing` output at TRACE during reveals, uploads, generation and errors and checks no value, token, password or Azure message appears |
| Values cached by browsers or proxies | `Cache-Control: no-store` on every HTML page, reveal, download and CSV |
| Values left on screen or clipboard | Hidden until asked for; revealed values are wiped after 30 seconds or on leaving the page. Keyring tries to clear the clipboard if it still holds the value. Browsers only allow that while the tab has focus, so a clear that fails in a background tab is tried again when you come back |
| Accidental or malicious deletes | Typed-name confirmation checked on the server. Purge is refused by the server unless `KEYRING_ALLOW_PURGE=true` |
| Private key leaks | Keys: no export, backup, release, decrypt, unwrap or sign calls exist (tested); the JWK type has no private fields. Certificates: private key download only for exportable policies, after a warning and typed name. A certificate's backing secret can't be revealed, rolled back, changed or deleted through the secrets pages |
| Query injection in the audit view | Filters checked against strict patterns, then used only as escaped string literals in `let` lines. The rest of the KQL is fixed |
| CSV injection in exports | Fields starting with `= + - @` are prefixed so spreadsheets don't run them |
| Path tricks in names | Vault, secret, certificate, key and version names are checked against Key Vault's own rules before they go in any URL. `nextLink` and backing secret URLs are only followed on the same vault |
| Large or slow requests | Request headers must arrive within 10 seconds (slow-header clients are cut off). 64 KB body limit on forms (256 KB on the two forms that carry a secret value, and 272 KB for a certificate upload of up to 256 KB). 90 second limit per request. At most 512 connections at once; past that, new ones wait in the listen backlog. Each connection is asked to close after 5 minutes and cut off 2 minutes later. Outbound calls have 10 second connect and 30 second total timeouts, and don't follow redirects |
| Supply chain | Few crates, all from crates.io, licence allow-list, `cargo deny` and `cargo audit` on every change and weekly, `Cargo.lock` and toolchain pinned, actions pinned by SHA, images pinned by digest, SBOM per build. No npm |
| Memory safety | `unsafe` code is forbidden in the crate |
| Container escape or tampering | Distroless static image, no shell, non-root, read-only root filesystem, no capabilities |

### Known limits

- **Sessions are in memory.** A restart signs everyone out, and several copies need sticky sessions. Anyone who can read the server's memory can read active tokens.
- **The session secret** only protects short-lived cookies (sign-in state and flash messages), which the server also refuses once they're past their age limit. Pending certificate uploads are kept in the server-side session. Rotating it means a restart, which signs everyone out (sessions are in memory), and cancels sign-ins in progress.
- Keyring trusts Azure's answers. A compromised Entra tenant or Key Vault is out of scope.
- **The connection cap is shared** by every client, and idle keep-alive connections and slow request bodies aren't limited beyond the 90 second request limit and the 5 minute connection age. A front-end proxy or the platform's load balancer normally covers this.
- **Zeroising covers Keyring's own copies.** Copies of tokens held inside `openidconnect` and `reqwest` aren't zeroised.
- **A panic** gives that one request a 500 page. Sessions survive it, since release builds unwind.
- **Nothing has run against a real tenant yet.** The tests use mock Entra, ARM, Key Vault and Log Analytics servers that follow Microsoft's REST reference. [real-vault-checklist.md](real-vault-checklist.md) lists what the first real run has to confirm.

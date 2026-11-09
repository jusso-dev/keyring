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
| Sessions | Encrypted, signed cookie or in-memory store. Nothing persisted |

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

## Supply chain

- `Cargo.lock` committed. Builds use `--locked`.
- Toolchain pinned in `rust-toolchain.toml`.
- `cargo deny check` covers licences (allow-list), advisories, bans and sources (crates.io only). `cargo audit` runs as well. Both run in CI and fail the build.
- Adding a crate needs a reason in the PR. Prefer crates that are widely used, maintained and light on dependencies.
- Dependabot opens weekly, grouped updates for `cargo`, `docker` and `github-actions`.
- GitHub Actions are pinned by full commit SHA.
- CI produces an SBOM for the image. Signed build provenance is optional.

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

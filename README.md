# Keyring

Keyring is a small web app that sits in front of Azure Key Vault. It lets people who don't use the Azure portal find a vault, look up a secret, add a certificate or rotate a key, in plain English.

It's a thin layer. Keyring stores nothing. Every call to Key Vault is made as the person who's signed in, so Key Vault's own Entra RBAC decides what they can see and change. If you can't do it in the portal, you can't do it in Keyring.

Keyring is written in Rust (Axum and Askama) and ships as a single Docker image. There's no Node.js or npm anywhere in the build.

> Status: early development. Every planned feature is built and tested against mock Azure services, but it hasn't yet been run against a real tenant. [docs/real-vault-checklist.md](docs/real-vault-checklist.md) lists what that first run has to confirm. Work is tracked in [issues](https://github.com/jusso-dev/keyring/issues).

## What it does

- **Sign in with Entra ID** (OpenID Connect).
- **Find your vaults** across every subscription you can see, using Azure Resource Graph.
- **Secrets**: list, search, reveal and copy (Keyring tries to clear the clipboard afterwards), create, edit, view versions and roll back, enable or disable, set expiry and tags, soft-delete and recover. Purge is off unless an admin turns it on.
- **Certificates**: list, upload `.pfx` or `.pem`, download `.cer` or `.pfx`, create with a policy, enable or disable, see what's expiring. A new certificate is self-signed or signed by an issuer already set up on the vault (see [Certificate issuers](#certificate-issuers)).
- **Keys**: list, create, rotate, enable or disable, set a rotation policy and view. Raw key material is never exported.
- **Expiry dashboard** across vaults, with CSV export and optional alerts.
- **Generator** for passwords, GUIDs and API keys.
- **Audit view** built from Key Vault diagnostic logs, per vault and per item.
- Deletes need you to type the item's name first.

## How access works

```
Browser ──OIDC──> Keyring ──on-behalf-of──> Entra ID ──token──> Key Vault / ARM / Resource Graph
```

1. You sign in with Entra ID. Keyring gets an access token for its own API.
2. Keyring swaps that token for Key Vault and Azure Resource Manager tokens using the [on-behalf-of flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow).
3. Each request goes to Azure as you. Keyring has no managed identity or service principal with vault access of its own.

That's why Keyring uses OIDC and not SAML. A SAML assertion can't be exchanged for a downstream token.

See [docs/architecture.md](docs/architecture.md) for more.

## Entra app registration

Keyring needs one app registration in your tenant. It acts as both the app people sign in to and the API whose token Keyring swaps for Key Vault and Azure tokens. You'll need to be able to create app registrations, and an admin to grant consent.

### 1. Register the app

1. In the [Entra admin centre](https://entra.microsoft.com), go to **Identity > Applications > App registrations > New registration**.
2. **Name**: anything, for example `Keyring`.
3. **Supported account types**: *Accounts in this organisational directory only* (single tenant).
4. **Redirect URI**: platform **Web**, value `http://localhost:3000/auth/callback` for local use.
5. Select **Register**. From the overview page, note the **Application (client) ID** and **Directory (tenant) ID**.
6. Go to **Authentication** and add a second **Web** redirect URI, `http://localhost:3000/auth/signed-out`. Sign-out sends people to Entra, and Entra only sends them back to an address registered here.

For a real deployment, add `https://<your-host>/auth/callback` and `https://<your-host>/auth/signed-out` as well.

### 2. Add a client secret

1. Go to **Certificates & secrets > Client secrets > New client secret**.
2. Pick an expiry and select **Add**.
3. Copy the **Value** (not the Secret ID) straight away. It's only shown once.

Keyring uses this secret for the on-behalf-of exchange. Keep it in your host's secret store or a Key Vault, never in this repo. Certificate credentials aren't supported yet.

Client secrets expire (after two years at most, often sooner by policy). When one runs out, nobody can sign in and Entra reports AADSTS7000222. Note the expiry date, and see [Rotating secrets](docs/deploy.md#rotating-secrets) for replacing it without downtime.

### 3. Expose an API

1. Go to **Expose an API**. Next to **Application ID URI** select **Add** and accept the default, `api://<client ID>`.
2. Select **Add a scope**:
   - **Scope name**: `access_as_user`
   - **Who can consent**: *Admins and users* (or *Admins only*)
   - Fill in the display names and descriptions, for example *Use Keyring as you*.
3. Save. If you use a different Application ID URI or scope name, set `ENTRA_API_SCOPE` to the full scope.

### 4. Add API permissions

Go to **API permissions > Add a permission** and add these **delegated** permissions:

| API | Permission | Why |
| --- | --- | --- |
| Azure Key Vault | `user_impersonation` | Read and change secrets as you |
| Azure Service Management | `user_impersonation` | List vaults with Resource Graph as you |
| Log Analytics API | `Data.Read` | Read Key Vault's audit logs for the audit view, as you |
| Microsoft Graph | `openid`, `profile`, `offline_access` | Sign in, show your name, stay signed in |

Log Analytics API is under **APIs my organization uses**; search for "Log Analytics".

Then select **Grant admin consent for <your tenant>**. Without it, sign-in or the first vault page will say your organisation needs to approve Keyring. If only the audit page says so, the Log Analytics API permission is missing or hasn't been consented to.

### 5. Give people access to vaults

Keyring has no access of its own. Each person needs Azure roles, the same as they would in the portal. Azure RBAC is recommended; vaults on access policies work too.

| To do this in Keyring | Role | Where |
| --- | --- | --- |
| See vaults in the vault list | Reader | Subscription, resource group or vault |
| List secrets and see their details | Key Vault Secrets User (or Key Vault Reader for names and dates only) | Vault |
| Show and copy a secret's value | Key Vault Secrets User | Vault |
| Add secrets, set new values, edit details, enable or disable | Key Vault Secrets Officer | Vault |
| Roll back to an older version | Key Vault Secrets Officer | Vault |
| Delete, see deleted secrets, recover | Key Vault Secrets Officer | Vault |
| Permanently delete secrets (only if `KEYRING_ALLOW_PURGE=true`) | Key Vault Secrets Officer | Vault |
| List and view certificates, download `.cer` | Key Vault Reader | Vault |
| Download a certificate with its private key | Key Vault Certificate User (this can also read secret values, see below) | Vault, or just that certificate |
| Upload, create, enable or disable, delete and recover certificates | Key Vault Certificates Officer | Vault |
| List the vault's certificate issuers (to offer them when creating a certificate) | Key Vault Certificates Officer (without it, only self-signed is offered) | Vault |
| List and view keys, copy public keys | Key Vault Reader (or Key Vault Crypto User) | Vault |
| Create, rotate, enable or disable, edit rotation policy, delete and recover keys | Key Vault Crypto Officer | Vault |
| See where a vault sends its logs (audit view) | Reader | Vault or resource group |
| Read audit events | Log Analytics Reader | The workspace the vault's diagnostic setting uses |

These roles apply to the whole vault unless you assign them on a single item. **Key Vault Certificate User and Key Vault Secrets User can both read secret values.** Certificate User needs to, because a certificate's private key is kept in its backing secret, but at vault scope it can read every secret in the vault. Where that matters, assign it on the one certificate (its scope is `<vault ID>/certificates/<name>`, or `<vault ID>/secrets/<name>` for the backing secret) instead of the vault.

For access-policy vaults, the matching permissions are: secrets Get and List for reading, plus Set, Delete, Recover and Purge to change them; certificates Get and List, plus Create, Import, Update, Delete, Recover and Purge (and List Issuers); keys Get and List, plus Create, Rotate, Update, Delete, Recover and Purge (and Get rotation policy, Set rotation policy).

Role changes can take a few minutes to apply.

## Configuration

Set these as environment variables. Don't commit them.

| Variable | What it's for |
| --- | --- |
| `ENTRA_TENANT_ID` | Directory (tenant) ID, a GUID |
| `ENTRA_CLIENT_ID` | Application (client) ID, a GUID |
| `ENTRA_CLIENT_SECRET` | The client secret value from step 2 |
| `APP_BASE_URL` | Public URL of this app, used for redirects and to check that form posts come from Keyring. Must be `https://` except for `http://localhost`. Scheme, host and port only: Keyring must be at the root of its host, not under a path like `/keyring` |
| `SESSION_SECRET` | At least 32 random characters, used to encrypt short-lived cookies. Generate one with `openssl rand -base64 48`. Keyring won't start if it's shorter, still the `replace-me` placeholder, or an unresolved Key Vault reference. See [Rotating secrets](docs/deploy.md#rotating-secrets) |
| `ENTRA_API_SCOPE` | Optional. Defaults to `api://<client ID>/access_as_user` |
| `KEYRING_ALLOW_PURGE` | Optional. `true` to allow permanent deletes. Off by default |
| `KEYRING_LISTEN` | Optional. Address to listen on. Defaults to `0.0.0.0:3000` |
| `KEYRING_LOG_LEVEL` | Optional. `error`, `warn`, `info` (default), `debug` or `trace`, in any case. Checked at start: anything else, including `off` and filter strings such as `info,keyring=trace`, stops Keyring starting |

Four more variables exist for the test suite only: `ENTRA_AUTHORITY_HOST`, `KEYRING_TEST_MANAGEMENT_URL`, `KEYRING_TEST_KEYVAULT_URL` and `KEYRING_TEST_LOGANALYTICS_URL`. They send people's tokens (and, for the authority host, the client secret) to another server. Leave them unset. Keyring logs a warning at start naming any that are set.

Sessions live in memory, so restarting Keyring signs everyone out. A request that hits a bug (a panic) gets an error page; other people's sessions carry on. If you run more than one copy, use sticky sessions. A session ends after one hour without a request, or 12 hours after sign-in. With JavaScript on, the page warns a few minutes before the hour runs out and offers to keep you signed in.

### Behind a proxy

- **Reverse proxy or load balancer in front.** Keyring ignores `X-Forwarded-*` headers. Set `APP_BASE_URL` to exactly the origin the browser uses (scheme, host and any port). If it differs, sign-in redirects go to the wrong place and every form post is refused with "This request didn't come from Keyring".
- **Outbound proxy.** Calls to Entra ID and Azure honour `HTTPS_PROXY` and `NO_PROXY` (and their lower-case forms).
- **Private CA**, for example a firewall that inspects TLS. Keyring trusts the operating system's certificate store. The distroless image has only the public roots, so point `SSL_CERT_FILE` at a PEM file in the container that holds the public roots plus your CA. When `SSL_CERT_FILE` is set, only that file is used.

## Why Rust

Keyring handles secrets, so the less code we pull in from strangers, the better. A typical JavaScript web app installs hundreds of npm packages, any of which can run code at install time. Keyring keeps that list short and checked:

- **Rust, with few crates.** Axum on Tokio for the web server, Askama for HTML templates compiled into the binary, `openidconnect` for sign-in and `reqwest` with rustls for calls to Azure.
- **Server-rendered pages.** Pages are plain HTML and CSS. The only JavaScript is one small hand-written file for extras like copy to clipboard. No npm, no bundler, no CDN scripts.
- **Locked and checked.** `Cargo.lock` is committed, the toolchain is pinned in `rust-toolchain.toml`, and CI runs `cargo deny` (licences, advisories, banned crates, allowed sources) and `cargo audit` on every change.
- **Small image.** A multi-stage Docker build, the build frontend and base images pinned by digest, a static musl binary on a distroless base, running as non-root with a read-only filesystem.
- **Pinned automation.** GitHub Actions are pinned by commit SHA, and CI tools and the Bicep CLI by version. Dependabot proposes updates for crates, the Rust toolchain, Docker images and actions.

## Running it locally

1. Do the app registration above, with the `http://localhost:3000/auth/callback` redirect URI.
2. Copy the example settings and fill them in:

   ```sh
   cp .env.example .env
   ```

   Set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` and `SESSION_SECRET`. Leave `APP_BASE_URL=http://localhost:3000`.

### With Rust

Install Rust with [rustup](https://rustup.rs). The right toolchain is picked up from `rust-toolchain.toml`. Keyring doesn't read `.env` itself, so load it into your shell first:

```sh
set -a; . ./.env; set +a
cargo run
```

### With Docker

```sh
docker build -t keyring .
docker run --rm -p 3000:3000 --env-file .env --read-only --cap-drop ALL --security-opt no-new-privileges keyring
```

The image is about 8 MB: a static binary on `gcr.io/distroless/static` with CA certificates and nothing else. It has no shell or package manager, runs as UID 65532, and needs no writable filesystem or Linux capabilities. Templates, CSS and JavaScript are compiled into the binary. `/healthz` answers `ok` without sign-in for health probes.

Then open http://localhost:3000 and sign in.

### Checks before a pull request

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

The tests run against mock Entra ID, Resource Graph, Key Vault and Log Analytics servers, so they need no Azure account. CI runs all of these plus the Bicep and container checks, and `main` only takes changes through a pull request with CI passing.

### Which version am I running?

Images built by CI carry the commit in the `org.opencontainers.image.revision` label and the crate version in `org.opencontainers.image.version`. Pass the same build arguments when you build your own (see the top of `Dockerfile`), then check with:

```sh
docker inspect <image> --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Common problems

| What you see | What to do |
| --- | --- |
| `Keyring can't start: missing environment variables` | The variables weren't loaded. With `cargo run`, run `set -a; . ./.env; set +a` in the same shell first |
| `SESSION_SECRET is not valid` | Use at least 32 random characters, for example `openssl rand -base64 48`. The `replace-me` placeholder is refused |
| Entra says the redirect URI doesn't match (AADSTS50011) | Add exactly `APP_BASE_URL` + `/auth/callback` as a **Web** redirect URI. Check `http` vs `https`, the port and any trailing slash |
| Entra says the client secret is wrong (AADSTS7000215) | Use the secret's **Value**, not its Secret ID, and check it hasn't expired |
| Entra says the client secret has expired (AADSTS7000222) | Make a new one and update `ENTRA_CLIENT_SECRET`. See [Rotating secrets](docs/deploy.md#rotating-secrets) |
| After signing out you're left on Microsoft's "You signed out" page | Add `APP_BASE_URL` + `/auth/signed-out` as a **Web** redirect URI |
| "Your organisation needs to approve Keyring" | An admin needs to select **Grant admin consent** on the API permissions page |
| "Microsoft sign-in didn't finish" | Entra stopped the sign-in. Try again; if it keeps happening, check the app registration and redirect URI |
| "Microsoft sign-in said no" with `invalid_scope` or AADSTS65005 | Check step 3: the `access_as_user` scope exists, or `ENTRA_API_SCOPE` matches the scope you made |
| "Sign-in expired" right after signing in | The sign-in took more than 10 minutes, was started in another tab, or cookies are blocked for the site |
| Vault list is empty | Ask for Reader on the subscription or resource group. New role assignments can take a few minutes |
| "You don't have access" when opening secrets | Seeing a vault only needs Reader. Ask for the Key Vault role named on the page |
| "This vault is blocked from here" | The vault's firewall doesn't allow your network. Ask an admin to allow it or use a private endpoint |
| Everyone is signed out after a restart | Expected. Sessions are only kept in memory |

More, including other AADSTS codes, in [docs/troubleshooting.md](docs/troubleshooting.md).

## Certificate issuers

Keyring offers a short list of issuers when you create a certificate: **Self** (self-signed) and any issuer already set up on the vault, read from the vault's issuer list. Keyring refuses Key Vault's `Unknown` issuer (a request you have signed somewhere else, then merge back in), because it has no way to download the signing request or merge the signed certificate. Do those, and set up issuers, in the Azure portal or with the Azure CLI.

While a request waits for its issuer, the certificate's page shows it as pending and offers **Cancel this request**, which asks Key Vault to cancel it and then deletes it, so the name can be used again.

## What Keyring doesn't support

- **Sovereign clouds.** Keyring works with the Azure public cloud only. The Entra ID, Resource Manager, Key Vault (`vault.azure.net`) and Log Analytics hosts are fixed in the code, so Azure Government and Azure China won't work.
- **Managed HSM** (`managedhsm.azure.net`). Only Key Vault vaults.
- **More than one tenant.** One Keyring serves one Entra tenant.
- **Hosting under a path.** Keyring must be at the root of its host.
- **Certificates signed outside Key Vault.** No `Unknown` issuer, signing request download or merge. See [Certificate issuers](#certificate-issuers).
- **Managing issuers.** Set them up in the Azure portal.

## Deploying to Azure

Bicep templates for App Service and Container Apps are in `infra/`, with optional private networking and expiry alerts. See:

- [docs/deploy.md](docs/deploy.md): step-by-step deployment
- [docs/private-vaults.md](docs/private-vaults.md): reaching vaults that only accept private traffic
- [docs/alerts.md](docs/alerts.md): optional expiry emails with Event Grid
- [docs/troubleshooting.md](docs/troubleshooting.md): common problems
- [docs/real-vault-checklist.md](docs/real-vault-checklist.md): what to check on the first run against a real tenant and vault

## Accessibility

Pages work with a keyboard and without JavaScript. Every form control has a label, each page has one main heading, errors are listed at the top with links to the fields and get focus, and colours meet WCAG AA contrast. Copy countdowns are announced at the start and near the end rather than every second. A test checks labels, headings and landmarks on every page.

If something doesn't work with your assistive technology, please open an issue.

## Prior art

Keyring learned from these projects. It doesn't copy their code.

- [akv-manager](https://www.npmjs.com/package/akv-manager)
- [TarasKovalenko/AzVault](https://github.com/TarasKovalenko/AzVault)
- [microsoft/AzureKeyVaultExplorer](https://github.com/microsoft/AzureKeyVaultExplorer)

## Licence

MIT. See [LICENSE](LICENSE).

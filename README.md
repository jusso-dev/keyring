# Keyring

Keyring is a small web app that sits in front of Azure Key Vault. It lets people who don't use the Azure portal find a vault, look up a secret, add a certificate or rotate a key, in plain English.

It's a thin layer. Keyring stores nothing. Every call to Key Vault is made as the person who's signed in, so Key Vault's own Entra RBAC decides what they can see and change. If you can't do it in the portal, you can't do it in Keyring.

Keyring is written in Rust (Axum and Askama) and ships as a single Docker image. There's no Node.js or npm anywhere in the build.

> Status: early development. Work is tracked in [issues](https://github.com/yumaitau/keyring/issues) and [milestones](https://github.com/yumaitau/keyring/milestones), starting with the MVP (sign-in and secrets).

## What it does

- **Sign in with Entra ID** (OpenID Connect).
- **Find your vaults** across every subscription you can see, using Azure Resource Graph.
- **Secrets**: list, search, reveal and copy (the clipboard clears itself), create, edit, view versions and roll back, enable or disable, set expiry and tags, soft-delete and recover. Purge is off unless an admin turns it on.
- **Certificates**: list, upload `.pfx` or `.pem`, download `.cer` or `.pfx`, create with a policy, see what's expiring.
- **Keys**: list, create, rotate and view. Raw key material is never exported.
- **Expiry dashboard** with optional alerts.
- **Generator** for passwords, GUIDs and API keys.
- **Audit view** built from Key Vault diagnostic logs.
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
4. **Redirect URI**: platform **Web**, value `http://localhost:3000/auth/callback` for local use. Add `https://<your-host>/auth/callback` later for a real deployment.
5. Select **Register**. From the overview page, note the **Application (client) ID** and **Directory (tenant) ID**.

### 2. Add a client secret

1. Go to **Certificates & secrets > Client secrets > New client secret**.
2. Pick an expiry and select **Add**.
3. Copy the **Value** (not the Secret ID) straight away. It's only shown once.

Keyring uses this secret for the on-behalf-of exchange. Keep it in your host's secret store or a Key Vault, never in this repo. Certificate credentials aren't supported yet.

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
| Microsoft Graph | `openid`, `profile`, `offline_access` | Sign in, show your name, stay signed in |

Then select **Grant admin consent for <your tenant>**. Without it, sign-in or the first vault page will say your organisation needs to approve Keyring.

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
| List and view certificates, download `.cer` | Key Vault Certificate User (or Key Vault Reader) | Vault |
| Download a certificate with its private key | Key Vault Certificate User and Key Vault Secrets User | Vault |
| Upload, create, delete and recover certificates | Key Vault Certificates Officer | Vault |
| List and view keys, copy public keys | Key Vault Reader (or Key Vault Crypto User) | Vault |
| Create, rotate, edit rotation policy, delete and recover keys | Key Vault Crypto Officer | Vault |

For access-policy vaults, the matching secret permissions are Get and List for reading, plus Set, Delete, Recover and Purge for the rest.

Role changes can take a few minutes to apply.

## Configuration

Set these as environment variables. Don't commit them.

| Variable | What it's for |
| --- | --- |
| `ENTRA_TENANT_ID` | Directory (tenant) ID, a GUID |
| `ENTRA_CLIENT_ID` | Application (client) ID, a GUID |
| `ENTRA_CLIENT_SECRET` | The client secret value from step 2 |
| `APP_BASE_URL` | Public URL of this app, used for redirects. Must be `https://` except for `http://localhost` |
| `SESSION_SECRET` | At least 32 random characters, used to encrypt short-lived cookies. Generate one with `openssl rand -base64 48` |
| `ENTRA_API_SCOPE` | Optional. Defaults to `api://<client ID>/access_as_user` |
| `KEYRING_ALLOW_PURGE` | Optional. `true` to allow permanent deletes. Off by default |
| `KEYRING_LISTEN` | Optional. Address to listen on. Defaults to `0.0.0.0:3000` |
| `KEYRING_LOG_LEVEL` | Optional. `error`, `warn`, `info` (default), `debug` or `trace` |

`ENTRA_AUTHORITY_HOST`, `KEYRING_TEST_MANAGEMENT_URL` and `KEYRING_TEST_KEYVAULT_URL` exist for the test suite only. Leave them unset.

Sessions live in memory, so restarting Keyring signs everyone out. If you run more than one copy, use sticky sessions.

## Why Rust

Keyring handles secrets, so the less code we pull in from strangers, the better. A typical JavaScript web app installs hundreds of npm packages, any of which can run code at install time. Keyring keeps that list short and checked:

- **Rust, with few crates.** Axum on Tokio for the web server, Askama for HTML templates compiled into the binary, `openidconnect` for sign-in and `reqwest` with rustls for calls to Azure.
- **Server-rendered pages.** Pages are plain HTML and CSS. The only JavaScript is one small hand-written file for extras like copy to clipboard. No npm, no bundler, no CDN scripts.
- **Locked and checked.** `Cargo.lock` is committed, the toolchain is pinned in `rust-toolchain.toml`, and CI runs `cargo deny` (licences, advisories, banned crates, allowed sources) and `cargo audit` on every change.
- **Small image.** A multi-stage Docker build, base images pinned by digest, a static binary on a distroless or scratch base, running as non-root with a read-only filesystem.
- **Pinned automation.** GitHub Actions are pinned by commit SHA. Dependabot proposes updates for crates, Docker images and actions.

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

The image is about 15 MB: a static binary on `gcr.io/distroless/static` with CA certificates and nothing else. It has no shell or package manager, runs as UID 65532, and needs no writable filesystem or Linux capabilities. Templates, CSS and JavaScript are compiled into the binary. `/healthz` answers `ok` without sign-in for health probes.

Then open http://localhost:3000 and sign in.

### Checks before a pull request

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

The tests run against mock Entra ID, Resource Graph and Key Vault servers, so they need no Azure account.

## Common problems

| What you see | What to do |
| --- | --- |
| `Keyring can't start: missing environment variables` | The variables weren't loaded. With `cargo run`, run `set -a; . ./.env; set +a` in the same shell first |
| `SESSION_SECRET is not valid` | Use at least 32 characters, for example `openssl rand -base64 48` |
| Entra says the redirect URI doesn't match (AADSTS50011) | Add exactly `APP_BASE_URL` + `/auth/callback` as a **Web** redirect URI. Check `http` vs `https`, the port and any trailing slash |
| Entra says the client secret is wrong (AADSTS7000215) | Use the secret's **Value**, not its Secret ID, and check it hasn't expired |
| "Your organisation needs to approve Keyring" | An admin needs to select **Grant admin consent** on the API permissions page |
| "Microsoft sign-in said no" with `invalid_scope` or AADSTS65005 | Check step 3: the `access_as_user` scope exists, or `ENTRA_API_SCOPE` matches the scope you made |
| "Sign-in expired" right after signing in | The sign-in took more than 10 minutes, was started in another tab, or cookies are blocked for the site |
| Vault list is empty | Ask for Reader on the subscription or resource group. New role assignments can take a few minutes |
| "You don't have access" when opening secrets | Seeing a vault only needs Reader. Ask for the Key Vault role named on the page |
| "This vault is blocked from here" | The vault's firewall doesn't allow your network. Ask an admin to allow it or use a private endpoint |
| Everyone is signed out after a restart | Expected. Sessions are only kept in memory |

## Deploying to Azure

Bicep templates for App Service and Container Apps are in `infra/`, with optional private networking and expiry alerts. See:

- [docs/deploy.md](docs/deploy.md): step-by-step deployment
- [docs/private-vaults.md](docs/private-vaults.md): reaching vaults that only accept private traffic
- [docs/alerts.md](docs/alerts.md): optional expiry emails with Event Grid
- [docs/troubleshooting.md](docs/troubleshooting.md): common problems

## Prior art

Keyring learned from these projects. It doesn't copy their code.

- [akv-manager](https://www.npmjs.com/package/akv-manager)
- [TarasKovalenko/AzVault](https://github.com/TarasKovalenko/AzVault)
- [microsoft/AzureKeyVaultExplorer](https://github.com/microsoft/AzureKeyVaultExplorer)

## Licence

MIT. See [LICENSE](LICENSE).

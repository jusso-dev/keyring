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

You'll need one app registration. A full walkthrough lands with the deploy milestone; the short version:

1. **Register an app** in Entra ID. Single tenant is the usual choice.
2. **Redirect URI** (Web): `https://<your-host>/auth/callback`. Add `http://localhost:3000/auth/callback` for local development.
3. **Client secret or certificate**: create one. Keyring needs it for the on-behalf-of exchange. Keep it in Key Vault or your host's secret store, never in this repo.
4. **Expose an API**: set the Application ID URI and add a scope such as `access_as_user`.
5. **API permissions** (delegated):
   - Azure Key Vault: `user_impersonation`
   - Azure Service Management: `user_impersonation`
   - Microsoft Graph: `openid`, `profile`, `offline_access`, `User.Read`
6. **Grant admin consent** for the tenant, or let users consent.
7. **Give people access** to vaults with Key Vault RBAC roles, for example `Key Vault Secrets User` to read secrets or `Key Vault Secrets Officer` to manage them. Vaults that still use access policies work too, but RBAC is recommended.

## Configuration

Set these as environment variables. Don't commit them.

| Variable | What it's for |
| --- | --- |
| `ENTRA_TENANT_ID` | Your tenant ID |
| `ENTRA_CLIENT_ID` | The app registration's client ID |
| `ENTRA_CLIENT_SECRET` | Client secret (or use a certificate) |
| `APP_BASE_URL` | Public URL of this app, used for redirects |
| `SESSION_SECRET` | Random string used to encrypt the session cookie |
| `KEYRING_ALLOW_PURGE` | `true` to allow permanent deletes. Off by default |

## Why Rust

Keyring handles secrets, so the less code we pull in from strangers, the better. A typical JavaScript web app installs hundreds of npm packages, any of which can run code at install time. Keyring keeps that list short and checked:

- **Rust, with few crates.** Axum on Tokio for the web server, Askama for HTML templates compiled into the binary, `openidconnect` for sign-in and `reqwest` with rustls for calls to Azure.
- **Server-rendered pages.** Pages are plain HTML and CSS. The only JavaScript is one small hand-written file for extras like copy to clipboard. No npm, no bundler, no CDN scripts.
- **Locked and checked.** `Cargo.lock` is committed, the toolchain is pinned in `rust-toolchain.toml`, and CI runs `cargo deny` (licences, advisories, banned crates, allowed sources) and `cargo audit` on every change.
- **Small image.** A multi-stage Docker build, base images pinned by digest, a static binary on a distroless or scratch base, running as non-root with a read-only filesystem.
- **Pinned automation.** GitHub Actions are pinned by commit SHA. Dependabot proposes updates for crates, Docker images and actions.

## Running it

You'll need the Entra app registration above and a `.env` file based on `.env.example`.

With Rust installed (the right toolchain is picked up from `rust-toolchain.toml`):

```sh
cargo run
```

With Docker:

```sh
docker build -t keyring .
docker run --rm -p 3000:3000 --env-file .env --read-only keyring
```

Then open http://localhost:3000.

Bicep templates for App Service or Container Apps, with private endpoint support, are on the roadmap.

## Prior art

Keyring learned from these projects. It doesn't copy their code.

- [akv-manager](https://www.npmjs.com/package/akv-manager)
- [TarasKovalenko/AzVault](https://github.com/TarasKovalenko/AzVault)
- [microsoft/AzureKeyVaultExplorer](https://github.com/microsoft/AzureKeyVaultExplorer)

## Licence

MIT. See [LICENSE](LICENSE).

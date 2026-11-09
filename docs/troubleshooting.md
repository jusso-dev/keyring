# Troubleshooting

Most problems show a plain message in Keyring that says what's wrong and who to ask. This page goes a little further.

## Starting up

| What you see | What to do |
| --- | --- |
| `Keyring can't start: missing environment variables` | Set the listed variables. Locally, load `.env` into your shell first (`set -a; . ./.env; set +a`). In Azure, check the app settings and that the config vault secrets exist |
| `SESSION_SECRET is not valid` | Use at least 32 characters, for example `openssl rand -base64 48` |
| App Service shows a Key Vault reference error on the settings page | The managed identity can't read the config vault. Check it has Key Vault Secrets User on the config vault, and that the vault is reachable (private endpoint and DNS if public access is off) |
| `/healthz` doesn't answer | Check the container logs. App Service needs `WEBSITES_PORT=3000`, which the template sets |

## Signing in

| What you see | What to do |
| --- | --- |
| Entra says the redirect URI doesn't match (AADSTS50011) | The redirect URI must be exactly `APP_BASE_URL` + `/auth/callback`. Check `https`, the host, any port, and no trailing slash |
| Entra says the client secret is wrong (AADSTS7000215) | Use the secret's **Value**, not its Secret ID. Check it hasn't expired |
| "Your organisation needs to approve Keyring" | An admin needs to select **Grant admin consent** on the app's API permissions page |
| "Microsoft sign-in didn't finish" | Entra stopped the sign-in. Try again; if it keeps happening, check the app registration and its redirect URI |
| "Microsoft sign-in said no" with `invalid_scope` (AADSTS65005 or 70011) | The `access_as_user` scope isn't exposed, or `ENTRA_API_SCOPE` doesn't match it |
| "Please sign in again" while using Keyring | Your organisation wants a fresh sign-in, for example for MFA or a conditional access policy. Sign in again |
| "Sign-in expired" straight after signing in | Sign-in took over 10 minutes, was started in another tab, or the browser blocked cookies |
| Signed out after a restart or deployment | Expected. Sessions are only in memory |
| Signed out at random with more than one copy running | Turn on sticky sessions (session affinity). Container Apps does this for `replicas` over 1 |

## Vaults and access

| What you see | What to do |
| --- | --- |
| The vault list is empty | You need Reader on the subscription, resource group or vault. New role assignments take a few minutes |
| "You don't have access" | The page names the role to ask for, for example Key Vault Secrets User. For access-policy vaults, ask for the matching access policy |
| "This vault is blocked from here" | The vault firewall doesn't allow Keyring's address. Add it, or use a private endpoint |
| "Can't reach this vault" | The vault probably has public access off. See [private-vaults.md](private-vaults.md) |
| "Azure asked Keyring to slow down" | Key Vault throttles busy vaults. Keyring already waits and retries a couple of times; wait a few seconds and try again |
| Expiry dashboard lists vaults it couldn't read | Each one says why. Usually a missing role or a private vault |

## Certificates and keys

| What you see | What to do |
| --- | --- |
| "Key Vault couldn't open the file" when uploading | Wrong password or a damaged file. Check the password, or re-export the .pfx |
| "This PEM file has a certificate but no private key" | Put the private key in the same file, or upload a .pfx |
| "The private key can't be downloaded" | The certificate's policy keeps the key in Key Vault. You can still download the public .cer |
| A new CA certificate stays "Waiting for the issuer" | The CA hasn't signed it yet. Check the issuer set up on the vault, and the CA's own portal |
| "This vault can't make HSM-protected keys" | The vault is Standard tier. Untick HSM, or use a Premium vault |

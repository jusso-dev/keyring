# Troubleshooting

Most problems show a plain message in Keyring that says what's wrong and who to ask. This page goes a little further.

## Starting up

| What you see | What to do |
| --- | --- |
| `Keyring can't start: missing environment variables` | Set the listed variables. Locally, load `.env` into your shell first (`set -a; . ./.env; set +a`). In Azure, check the app settings and that the config vault secrets exist |
| `SESSION_SECRET is not valid` | Use at least 32 random characters, for example `openssl rand -base64 48`. The `replace-me` placeholder from `.env.example` is refused, and so is a Key Vault reference App Service couldn't resolve |
| `KEYRING_LOG_LEVEL is not valid` | Use `error`, `warn`, `info`, `debug` or `trace`. `off` and filter strings such as `info,keyring=trace` are refused |
| App Service shows a Key Vault reference error on the settings page | The managed identity can't read the config vault. Check it has Key Vault Secrets User on the config vault, and that the vault is reachable (private endpoint and DNS if public access is off) |
| `/healthz` doesn't answer | Check the container logs. App Service needs `WEBSITES_PORT=3000`, which the template sets |
| A setting you added in the portal is gone after a deployment | The templates list every setting. Use the `apiScope` and `logLevel` parameters instead (see [deploy.md](deploy.md#parameters)) |
| Internal Container Apps: the address doesn't resolve or times out from the VNet | The environment's default domain needs a private DNS zone with a wildcard record for its `staticIp`. See [deploy.md](deploy.md#internal-container-apps) |
| Every form post says "This request didn't come from Keyring" | `APP_BASE_URL` doesn't match the address in the browser, often because of a proxy in front. See the README, "Behind a proxy" |

## Signing in

| What you see | What to do |
| --- | --- |
| Entra says the redirect URI doesn't match (AADSTS50011) | The redirect URI must be exactly `APP_BASE_URL` + `/auth/callback`. Check `https`, the host, any port, and no trailing slash |
| Entra says the client secret is wrong (AADSTS7000215) | Use the secret's **Value**, not its Secret ID. Check it hasn't expired |
| Entra says the client secret has expired (AADSTS7000222) | Make a new client secret and put it in the config vault. See [Rotating secrets](deploy.md#rotating-secrets) |
| Entra can't find the application (AADSTS700016) | `ENTRA_CLIENT_ID` is wrong, or `ENTRA_TENANT_ID` is a different tenant from the app registration's |
| Entra can't find the resource (AADSTS500011) | The Application ID URI isn't set on **Expose an API**, or `ENTRA_API_SCOPE` names a different one |
| Entra says the person isn't assigned to the app (AADSTS50105) | The app's enterprise application has **Assignment required** on. Assign the person, or a group they're in, under **Users and groups** |
| After signing out you're left on Microsoft's "You signed out" page | Add `APP_BASE_URL` + `/auth/signed-out` as a **Web** redirect URI in the app registration |
| "Your organisation needs to approve Keyring" | An admin needs to select **Grant admin consent** on the app's API permissions page |
| "Your organisation needs to approve Keyring" on the audit page only (AADSTS65001) | The app registration is missing the delegated **Log Analytics API > Data.Read** permission, or it hasn't been consented to. Add it and grant admin consent |
| "Microsoft sign-in didn't finish" | Entra stopped the sign-in. Try again; if it keeps happening, check the app registration and its redirect URI |
| "Microsoft sign-in said no" with `invalid_scope` (AADSTS65005 or 70011) | The `access_as_user` scope isn't exposed, or `ENTRA_API_SCOPE` doesn't match it |
| "Please sign in again" while using Keyring | Your organisation wants a fresh sign-in, for example for MFA or a conditional access policy. Sign in again |
| "Sign-in expired" straight after signing in | Sign-in took over 10 minutes, was started in another tab, or the browser blocked cookies |
| Signed out after a restart or deployment | Expected. Sessions are only in memory |
| Signed out after a break | A session ends after one hour without a request, or 12 hours after sign-in. With JavaScript on, the page warns a few minutes before the hour is up |
| Signed out at random with more than one copy running | Turn on sticky sessions (session affinity). Container Apps does this for `replicas` over 1 |

## Vaults and access

| What you see | What to do |
| --- | --- |
| The vault list is empty | You need Reader on the subscription, resource group or vault. New role assignments take a few minutes |
| "You don't have access" | The page names the role to ask for, for example Key Vault Secrets User. For access-policy vaults, ask for the matching access policy |
| "This vault is blocked from here" | The vault firewall doesn't allow Keyring's address. Add it, or use a private endpoint |
| "Can't reach this vault" | The vault probably has public access off. See [private-vaults.md](private-vaults.md) |
| "Azure asked Keyring to slow down" | Key Vault throttles busy vaults. Keyring already waits and retries a couple of times; wait a few seconds and try again |
| Expiry dashboard lists vaults it couldn't read | Each one says why. Usually a missing role or a private vault. "Not read in time" means the vault took over 20 seconds or the dashboard reached its one minute limit; pick that vault on its own to see it |
| "You switched vaults" or "The page was out of date" after posting a form | The form was opened for one vault and you've since picked another, usually in another tab. Nothing was changed. Go back, refresh the page and try again |
| "You were signed out before that was saved, so nothing changed" | The session ended (an hour idle, or 12 hours after sign-in) while the form was open. Sign in again and enter it again |

## Certificates and keys

| What you see | What to do |
| --- | --- |
| "Key Vault couldn't open the file" when uploading | Wrong password or a damaged file. Check the password, or re-export the .pfx |
| "This PEM file has a certificate but no private key" | Put the private key in the same file, or upload a .pfx |
| "The private key is in an RSA key format" (or "an EC key format") | Key Vault only takes an unencrypted PKCS #8 key (`BEGIN PRIVATE KEY`). Convert it with `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem` and put the new key in the file with the certificate |
| "The private key in this PEM file doesn't belong to its certificate" | The key is for a different certificate. Find the key that was made with this certificate's request |
| "Key Vault couldn't read this PEM file" | Key Vault refused it after the preview. It needs the certificate and an unencrypted PKCS #8 key that belongs to it. "Key Vault said:" under the form gives its reason |
| "Key Vault said:" under a form | Key Vault refused what was sent (a 400) and this is its own reason, cut to 500 characters. It usually names the field and the rule. What you typed is kept, so fix that field and send it again |
| "The private key can't be downloaded" | The certificate's policy keeps the key in Key Vault. You can still download the public .cer |
| A new self-signed certificate shows "Being created" | Key Vault is still making it, which usually takes a few seconds. Refresh the page |
| A new CA certificate stays "Waiting for the issuer" | The CA hasn't signed it yet. Check the issuer set up on the vault, and the CA's own portal. To give up on it, select **Cancel this request** on the certificate's page |
| Only "Self" is offered as the issuer | You can't list the vault's issuers (that needs Key Vault Certificates Officer), or the vault has none set up. The page says which. Issuers are set up in the Azure portal |
| "This key belongs to a certificate" | Key Vault made this key for the certificate of the same name and manages it, so Keyring won't delete, rotate, disable or set a rotation policy on it. Make the change on the certificate's page instead |
| "This vault can't make HSM-protected keys" | The vault is Standard tier. Untick HSM, or use a Premium vault |

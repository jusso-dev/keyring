# Real tenant and vault checklist

Every test in this repository runs against mock Entra ID, Resource Graph, ARM, Key Vault and Log Analytics servers (`tests/support/`). The mocks follow Microsoft's REST reference. The Key Vault REST rows have been run against real vaults, by hand and with the opt-in `tests/real_vault.rs` (see "Record of runs" below). Sign-in, on-behalf-of, RBAC role, browser and deployment rows haven't been run against a real tenant yet. This page lists what only a real Entra tenant, a real Key Vault or a real browser can confirm.

Use a test tenant or a test resource group, and test vaults that hold nothing that matters. Some checks delete, purge or disable things.

## How to use it

1. Deploy Keyring as in [deploy.md](deploy.md), or run it locally against your tenant (see the README, "Running it locally").
2. Make two test vaults: one Standard with soft delete and **no** purge protection, and one with purge protection on. Give yourself Key Vault Administrator on both, plus Reader on the resource group.
3. Work through each section. For each row, do what it says and compare with "Expected".
4. Record what happened in the **Result** column: `ok`, or what Key Vault actually did. Keep IDs, names and messages that identify your tenant out of it.
5. Where the result differs, open an issue naming the row, and change the mock in `tests/support/` to match what Key Vault really did, with a test.

The "Code" column names where Keyring depends on the behaviour, so you know what to change if it differs.

Six of the Key Vault REST rows (four secrets rows, the HSM key row and the self-signed create row) can be re-run by a test against a throwaway vault. See [real-vault-automation.md](real-vault-automation.md).

## Sign-in and tokens

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Sign-in | Open Keyring and sign in | You land on the vault list with your name shown | `src/routes/auth.rs`, `src/auth/oidc.rs` | |
| On-behalf-of | Open a vault and its secrets | Secrets list loads. Key Vault's diagnostic log shows the call made as you, not as an app | `src/azure/token.rs` | |
| `oid` and `tid` in the ID token | Reveal a secret, then read Keyring's log | The action line has `subject=oid:<GUID>,tid:<GUID>`, matching your object ID and tenant ID in Entra. Not `sub:` | `src/auth/session.rs` (`UserId`), `src/auth/oidc.rs` | |
| Lower-case GUIDs in the issuer | Sign in with `ENTRA_TENANT_ID` set in upper case | Sign-in works. Keyring lower-cases the tenant ID to match Entra's issuer | `src/config.rs`, `src/auth/oidc.rs` | |
| Sign-out redirect | Select **Sign out** | Entra signs you out and returns to `/auth/signed-out` (needs that redirect URI registered) | `src/routes/auth.rs` (`sign_out`) | |
| `invalid_grant` sub-codes | With a conditional access policy that needs fresh MFA, let a session's token need refreshing | "Please sign in again", not a configuration error. Note the AADSTS number Entra sent | `src/auth/entra.rs` (`SIGN_IN_AGAIN_CODES`) | |
| Wrong `ENTRA_API_SCOPE` | Start Keyring with a scope that doesn't exist on the app registration, sign in | A configuration error naming the code for the admin, not a loop of "sign in again" | `src/auth/entra.rs` | |
| Twelve parallel exchanges | Open the expiry dashboard with at least six vaults straight after signing in | All vaults load. Entra sign-in logs show one on-behalf-of request per resource, and no throttling | `src/azure/token.rs` | |
| Signing key rollover | Not something you can trigger. If Entra rolls its keys during the test window, sign in once afterwards | Sign-in works first time | `src/auth/oidc.rs` (`forget_metadata`) | |
| Admin consent missing for Log Analytics | Remove consent for **Log Analytics API > Data.Read**, open the audit page | "Your organisation needs to approve Keyring" on the audit page only, with AADSTS65001 | `src/routes/audit.rs`, `src/auth/entra.rs` | |
| AADSTS codes in the troubleshooting page | Cause each code in [troubleshooting.md](troubleshooting.md) you safely can (wrong redirect URI, wrong secret value, unassigned user) | The page shows the row's message, and the code matches | `src/routes/auth.rs`, `src/auth/entra.rs` | |
| Idle warning and keep-alive | Leave a page open, with JavaScript on, until a few minutes before the one hour idle limit | A notice offers more time. Selecting it calls `/auth/keepalive` (204) and the session carries on | `static/app.js` (`idleNotice`), `src/routes/auth.rs` | |

## Secrets

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Versions of a name that doesn't exist | Add a secret with a new name | Key Vault answers "List secret versions" with 200 and an empty list (a 404 is handled too), so Keyring treats the name as free and creates it. Note which answer came | `src/azure/secrets.rs` (`versions`), `src/routes/secrets/edit.rs` (`create`) | ok: 200 with an empty list |
| Clearing an expiry date | Edit a secret with an expiry, clear the date, save | Keyring says Key Vault can't remove a version's expiry and to set a new value with Expires blank. The expiry is unchanged | `src/azure/secrets.rs` (`DateChange`) | **Differs.** 200, but the expiry is kept. Key Vault ignores `"exp": null` (API 7.0 to 7.6, secrets and keys). Fixed: the edit form refuses a removed date and says to set a new value instead |
| Recover then read | Delete a secret, recover it, open it straight away | Recover answers at once and Keyring says it can take a few seconds to show. The secret may answer 404 until then. Note how long it took | `src/routes/lifecycle.rs`, `src/routes/secrets/delete.rs` | ok: readable after about 2 seconds |
| Write straight after a recover | Recover a secret and set a new value within a few seconds | Note whether Key Vault answers 409, and with what code and message. Keyring says "Key Vault couldn't do that right now" for a 409 that isn't about a deleted item | `src/routes/error.rs` (`is_deleted_but_recoverable`) | 409 `Conflict`, inner `ObjectIsBeingRecovered`, "is currently being recovered and cannot be re-created; retry later." Keyring shows the retry page, as expected |
| 409 for a soft-deleted name | Delete a secret, then create one with the same name | 409 `Conflict`, message containing "is currently in a deleted but recoverable state", and maybe inner code `ObjectIsDeletedButRecoverable`. Keyring says "A deleted item has this name" | `src/routes/error.rs` | ok: inner code `ObjectIsDeletedButRecoverable` |
| Purge on a purge-protected vault | With `KEYRING_ALLOW_PURGE=true`, delete a secret on the protected vault and try to purge it | Keyring doesn't offer **Permanently delete**. If you post to the purge address anyway, Key Vault answers 403 with a message containing "purge protection" | `src/routes/lifecycle.rs`, `src/routes/secrets/delete.rs` | ok: 403 `Forbidden`, message names purge protection. `recoveryLevel` is `CustomizedRecoverable` |
| `recoverableDays` | On a vault with a retention period other than 90 days, open a secret's delete page | The warning names that vault's own period. Key Vault sends `recoverableDays` on the secret | `src/routes/lifecycle.rs` (`Recovery`) | ok: 7 on a 7-day vault, on secrets, certificates, keys and their deleted items |
| Disabled version's value | Disable an older version in the portal, try to roll back to it in Keyring | Keyring refuses before calling Key Vault. Confirm that Key Vault itself refuses to read the value (403) | `src/routes/secrets/versions.rs` | ok: 403, inner `SecretDisabled` |

## Certificates

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Versions of a name that doesn't exist | Create a certificate, and a key, each with a new name | 200 with an empty list, or 404. Either way the name is free and the create goes ahead. Note which answer came | `src/azure/certs.rs` (`versions`), `src/routes/certs/create.rs`, `src/routes/keys/edit.rs` | ok: 200 with an empty list for both |
| Self-signed create | Create a self-signed certificate | 202 with `status: inProgress`. Keyring shows "Being created", then the certificate a few seconds later | `src/routes/certs/mod.rs` (pending status), `src/routes/certs/create.rs` | ok: 202 `inProgress`, completed within 1 to 2 seconds |
| `days_before_expiry` limit | Create a 1 month certificate with renewal 27 days before expiry, then try 28 | 27 is accepted, 28 is refused by Keyring. Confirm Key Vault accepts 27 | `src/routes/certs/create.rs` (`DAYS_PER_MONTH_LIMIT`) | ok: 27 accepted, 28 refused by Key Vault (400 `BadParameter`) |
| Issuer list | Open **Create** on a vault with an issuer set up | The issuer is offered after Self. `Unknown` isn't offered | `src/routes/certs/create.rs` (`load_issuers`), `src/azure/certs.rs` (`issuers`) | Only the empty case run (no CA issuer in the test vault): 200 with an empty list |
| Issuer list without rights | As someone with Key Vault Certificate User only, open **Create** | Key Vault answers 403. Keyring offers Self only and says why | `src/routes/certs/create.rs` | |
| Cancel a pending request | Create a certificate with a real CA issuer you won't complete, select **Cancel this request** | PATCH `/certificates/{name}/pending` with `cancellation_requested: true` then DELETE both succeed, and the name can be used again | `src/azure/certs.rs` (`cancel_pending`) | ok, tested with an `Unknown` issuer request: PATCH 200 then DELETE 200, the name is free straight away |
| PEM import formats | Upload a PEM with an unencrypted PKCS #8 key; then one with a PKCS #1 key past Keyring's check; then a key that doesn't match | PKCS #8 imports. Note Key Vault's 400 text for the other two | `src/routes/certs/upload.rs` | ok: PKCS #8 imports. PKCS #1: 400 "PEM X.509 certificate content is in an unexpected format". Mismatched key: 400 "public key ... does not match" |
| Wrong PFX password | Upload a .pfx with the wrong password | Key Vault answers 400. Keyring says the password is probably wrong, and "Key Vault said:" shows its message | `src/routes/certs/upload.rs` | ok: 400 `BadParameter`, "PKCS#12 X.509 certificate content can not be read" |
| BER-encoded PFX | Upload a .pfx exported by an older Windows tool (BER encoding) | Keyring has no preview but uploads it. Key Vault imports it | `src/routes/certs/upload.rs`, `src/pkcs12.rs` | |
| Import onto a soft-deleted name | Delete a certificate, then upload one with the same name | 409, and Keyring says "A deleted item has this name" | `src/routes/error.rs` | |
| Enable and disable | Disable a certificate, then enable it | PATCH `attributes.enabled` on `/certificates/{name}/{version}` works both ways | `src/azure/certs.rs` (`set_enabled`) | ok |
| Change renewal | On a self-signed certificate, use **Change** next to "Near expiry": save email at 14 days, then auto at 30 days, then do nothing. Read the policy after each | Policy shows the new action, other policy fields unchanged. "Do nothing" sends `"lifetime_actions": []`: confirm Key Vault clears the actions rather than ignoring the empty list. If it keeps them, Keyring says nothing changed instead of "Saved". Note the 400 text for a day count above 27 times the validity, and for auto on an imported certificate | `src/routes/certs/renewal.rs`, `src/azure/certs.rs` (`update_lifetime_actions`) | |
| Listing and downloading with the smallest roles | As Key Vault Reader only, list certificates and download a `.cer`. As Key Vault Certificate User only, download a `.pfx` | Both work, on a real RBAC vault | `src/routes/certs/download.rs`, `src/routes/error.rs` (`Need`) | |
| Backing secret URL | Download a `.pfx` | Works. Key Vault's `sid` is exactly `https://<vault>.vault.azure.net/secrets/<name>/<version>` | `src/routes/certs/download.rs` (`is_backing_secret`) | ok: `sid` is `https://<vault>.vault.azure.net/secrets/<name>/<version>` |

## Keys

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Default rotation policy | Create a key in Keyring, open its rotation policy | Key Vault returns its default (one Notify 30 days before expiry, no expiry). Keyring shows "no policy set". Record the exact JSON | `src/azure/keys.rs` (`is_key_vault_default`) | ok: one Notify `P30D` before expiry, `"attributes": null` |
| PUT without `attributes` | On a key whose policy has an expiry, save the policy form with expiry blank | Key Vault clears the expiry. Keyring leaves `attributes` out | `src/routes/keys/edit.rs`, `src/azure/keys.rs` (`set_rotation_policy`) | Key Vault clears the expiry. A PUT without `attributes` replaces the whole policy, so Keyring's blank expiry means no expiry |
| Rotation policy limits | Try an expiry of 27 days, a rotate trigger of 6 days, and a rotate 6 days before expiry | Keyring refuses each. Confirm Key Vault refuses each with 400 too (expiry at least 28 days, triggers at least 7 days) | `src/routes/keys/edit.rs` | ok: expiry under 28 days, a rotate trigger under 7 days and a rotate under 7 days before expiry are each refused with 400 `BadParameter`. Key Vault accepts a Notify trigger of 1 day; Keyring keeps its own minimum of 7 |
| Managed key | Create a certificate, then open its key on the keys page | Key Vault sends `managed: true`. Keyring refuses delete, rotate, rotation policy and disable with "This key belongs to a certificate". Note what Key Vault does if you try those in the portal | `src/routes/keys/mod.rs` (`unmanaged_key`) | ok: `managed: true` on the key and the backing secret. Key Vault itself refuses rotate, update, delete and set rotation policy with 403 `KeyManagedByKeyVault` |
| HSM key on a Standard vault | Create an RSA-HSM key on the Standard vault | 403 with inner code `HardwareKeysNotSupported`. Keyring says the vault needs the Premium tier | `src/routes/keys/edit.rs` | **Differs.** 403 `Forbidden`, inner `HardwareKeysNotSupported`, not 400. Fixed: Keyring matches that code |
| Enable and disable | Disable a key, then enable it | PATCH `attributes.enabled` on `/keys/{name}/{version}` works both ways | `src/azure/keys.rs` (`set_enabled`) | ok |
| Listing with the smallest role | As Key Vault Reader only, list keys and copy a public key | Both work | `src/routes/keys/mod.rs` | |

## Expiry and audit

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Throttling across many vaults | Open the expiry dashboard in a tenant with many vaults | Six vaults at a time draws few or no 429s from Key Vault or ARM. Note any | `src/routes/expiry.rs` (`CONCURRENCY`) | |
| A workspace in another tenant or deleted | Point a vault's diagnostic setting at two workspaces, one you can't read, and open the audit page | Events from the readable one show, with a note that one was left out. Note the status Log Analytics gave (403, 404 or other) | `src/routes/audit.rs` | |

## Deployment

These need an Azure subscription you can deploy to. `az deployment group what-if` shows what a deployment would do without making anything.

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Template guards | Run `what-if` with `configVaultPrivateEndpointSubnetId` set but no subnet for the app, and (Container Apps) `ingress = 'internal'` without `infrastructureSubnetId`, and `privateDnsVnetId` with external ingress | Each stops with the template's `fail()` message before anything changes | `infra/app-service/main.bicep`, `infra/container-apps/main.bicep` | ok: each stops with its `fail()` message (App Service and Container Apps) |
| Internal Container Apps ingress | Deploy with `ingress = 'internal'` and `privateDnsVnetId`, then open the app from a machine in the VNet | The default domain resolves to `staticIp` and Keyring loads. It isn't reachable from the internet | `infra/container-apps/main.bicep`, `infra/modules/container-apps-dns.bicep` | |
| App Service logs | Deploy with `logAnalyticsWorkspaceId`, reveal a secret, run the example query in [deploy.md](deploy.md#logs) using `AppServiceConsoleLogs` and `ResultDescription` | The action line shows up | `infra/app-service/main.bicep` | |
| Container Apps logs | Reveal a secret, run the example query in [deploy.md](deploy.md#logs) | The action line shows up in `ContainerAppConsoleLogs_CL`, column `Log_s` | `infra/container-apps/main.bicep` | |
| Alerts topic | Deploy `infra/alerts` once with no topic and once with `existingSystemTopicName` | The new topic is in the vault's region. With an existing topic, only the subscription is added | `infra/alerts/main.bicep`, `infra/modules/expiry-events.bicep` | New topic only: the topic takes the vault's location. The existing-topic case not run |
| Private vault | With a private endpoint and the DNS zone, open a vault with public access off | Opens normally. Without the DNS link, "Can't reach this vault" | [private-vaults.md](private-vaults.md) | |

## In the browser

| Check | Do this | Expected | Code | Result |
| --- | --- | --- | --- | --- |
| Clipboard clear, Chrome | Reveal and copy a secret, wait for the clear with the tab in front | The clipboard is empty, or holds what you copied since | `static/app.js` | |
| Clipboard clear in a background tab, Chrome, Firefox and Safari | Reveal and copy, switch to another tab or app before the clear, then come back | The clear happens on return, if the clipboard still holds the value. Safari and Firefox may refuse clipboard reads; note what each does | `static/app.js` | |
| Screen reader pass | With VoiceOver (Safari) or NVDA (Firefox or Chrome), sign in, find a secret, reveal and copy it, submit a form with an error, delete an item | Every control is named, errors are read out and focused, the copy countdown is announced at the start and near the end only | `templates/`, `static/app.js` | |
| Reflow | At 320 CSS pixels wide (or 400% zoom), open the secrets list, a secret, and a form | Nothing needs scrolling sideways except inside tables | `static/style.css` | |

## Record of runs

| Date (DD-MM-YYYY) | Who | Keyring commit | Notes |
| --- | --- | --- | --- |
| 11-11-2026 | Claude, for Justin | `607b9b7` | Key Vault REST rows only, as an app (client credentials) against two Standard access-policy vaults with 7-day retention, one with purge protection. Sign-in, on-behalf-of, RBAC role, browser and deployment rows other than the guards weren't run. Two differences found and fixed (clearing a date, HSM refusal) |
| 12-11-2026 | Claude, for Justin | this change | The six automated rows in `tests/real_vault.rs` (see [real-vault-automation.md](real-vault-automation.md)), as an app against a throwaway Standard access-policy vault with 7-day retention, deleted and purged afterwards. All six pass. Found and fixed: Key Vault answers 411 Length Required to a POST with no `Content-Length`, so recovering a deleted secret, key or certificate failed against a real vault; Keyring now sends `Content-Length: 0`. The mock's 409s now carry the inner code and message Key Vault sends. Recover then read: readable after about 1 second |

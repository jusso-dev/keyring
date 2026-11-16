# Rotation

Keyring doesn't rotate credentials. It shows what a rotator says about its last run, if the rotator writes the tags below.

## What Keyring does and doesn't do

- **Set a new value** in Keyring changes Key Vault only. The database, storage account or app the secret belongs to keeps its old credential until something else changes it.
- Keyring has no identity of its own for this. It acts as the signed-in person, through their on-behalf-of token, and holds no standing rights to change anything on a target system. That stays so: rotation needs an app-only identity that can write production credentials, and Keyring doesn't have or want one.
- Keyring reads three tags on a secret (below) and shows them as one line on the secret's page. The expiry dashboard lists secrets whose last rotation failed. Both come from tags Key Vault already returns on the calls Keyring makes; no extra calls.
- That line is **what the tags claim**. Anyone who can change a secret's tags can write them. Keyring doesn't check with the rotator or the target system.

Keys are different: Key Vault rotates keys itself, and Keyring's key pages set their rotation policy. This page is about secrets.

## First, remove the credential

The best credential to rotate is one you don't have. Before setting up rotation, check whether the app can stop using a stored secret:

- **Managed identities** for apps running in Azure, with Entra sign-in to the target: [Managed identities for Azure resources](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview).
- **Workload identity federation** for apps outside Azure (GitHub Actions, Kubernetes, other clouds): [Workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation).
- Entra-only sign-in on Azure SQL, and Shared Key access turned off on storage accounts, so there is no password or account key left to leak.

## Azure's rotation pattern

For a credential that has to stay, Microsoft's pattern is:

1. The secret has an expiry date.
2. Key Vault sends a `SecretNearExpiry` event to Event Grid 30 days before it expires.
3. Event Grid calls an Azure Function.
4. The Function, with its **own** narrowly scoped managed identity, makes a new credential on the target system and writes it to Key Vault as a new version with a new expiry.

The vault owner builds, deploys and runs this, outside this repository, under their own review. Keyring's identity and app registration get none of the rights the Function needs.

Microsoft's guides:

- [Rotation for resources with one set of credentials](https://learn.microsoft.com/azure/key-vault/secrets/tutorial-rotation) (for example a SQL login)
- [Rotation for resources with two sets of credentials](https://learn.microsoft.com/azure/key-vault/secrets/tutorial-rotation-dual) (for example storage account keys)
- [Key Vault as an Event Grid source](https://learn.microsoft.com/azure/event-grid/event-schema-key-vault) (the `SecretNearExpiry` event)
- [Autorotation in Key Vault](https://learn.microsoft.com/azure/key-vault/general/autorotation) (which item types Key Vault rotates itself)

Microsoft's samples read the tags `CredentialId`, `ProviderAddress` and `ValidityPeriodDays`. Keep them as they are; Keyring shows them as ordinary tags.

## Tag convention

A rotator that wants Keyring to show its status sets these tags on the secret (on the new version after a good run, or on the current version after a failed one):

| Tag | Example | Accepted format |
| --- | --- | --- |
| `rotation` | `storage-key-rotator` | The rotator's name. Any text |
| `rotation-last` | `2026-11-02` or `2026-11-02T03:00:00Z` | When the last attempt ran: a date `YYYY-MM-DD`, or an RFC 3339 date-time with `Z` or an offset such as `+10:00` (fractions of a second allowed) |
| `rotation-status` | `ok` or `failed` | The result of the last attempt. Exactly `ok` or `failed`, lower case |

Tag names are matched exactly, in lower case.

## What Keyring shows

On the secret's page, beside its tags, when any of the three tags is set:

> Rotation: Rotated by storage-key-rotator, last 2 Nov 2026, **OK** (what the secret's rotation tags say, not checked by Keyring)

- The date is shown in UTC as a date, like every other date in Keyring. A date-time with an offset is turned into UTC first, so it can land on the day before or after.
- The status is a badge with a glyph and a word: OK (ok style), Failed (error style), or Unknown (neutral).
- Anything outside the formats above shows as **unknown**, never hidden and never guessed: a missing tag, an empty name, a date that doesn't parse (such as `02-11-2026` or `2026-02-31`), or a status other than `ok` or `failed` (such as `OK` or `done`).
- The name has control characters and text-direction characters removed and is cut to 64 characters, with an ellipsis. All tag text is escaped.
- The three tags stay in the normal tag list as well.

On the expiry dashboard, a **Rotation failed** table lists secrets whose `rotation-status` is exactly `failed`, with the vault, the rotator's name and the last attempt. It follows the dashboard's vault, type and tag filters, and shows only when there is something in it.

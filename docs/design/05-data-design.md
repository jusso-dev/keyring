# Data design

Keyring has no database and writes nothing to disk. This chapter lists everything it does hold, where, and for how long; the tags it reads and writes in people's vaults; and the one record it creates, its audit event.

## What is held and where

| Data | Where | Lifetime | Notes |
|---|---|---|---|
| Session ID | Browser cookie (`__Host-` prefixed over HTTPS, http-only, `SameSite=Lax`) | Until sign-out, one hour idle or 12 hours | A random 256-bit value. The only thing the server knows the browser by |
| The person's access token for Keyring's API, refresh token, ID token claims (`oid`, `tid`, UPN, `acrs`, `auth_time`) | Server memory, in the session | The session | `AccessToken` and `Secret` wrappers print `[redacted]` and are zeroised when dropped |
| Exchanged OBO tokens (Key Vault, ARM, Log Analytics) | Server memory, per session, per resource | Until five minutes before expiry, or the session ends | Never shared between sessions |
| Each vault's item list (names and properties) | Server memory, per session | 60 seconds; dropped by a form post to that vault | The `Item` type has no field for a value. A partly read vault isn't kept |
| Permission hints per scope | Server memory, per session | 5 minutes; dropped after a PIM change | Only a hint |
| Pending certificate upload or secrets import | Server memory, per session | 10 minutes, or until used, cancelled or the session ends | Held as `Secret`, zeroised when dropped |
| Last vault used | Server memory, per session | The session | Only for navigation links and old addresses; handlers never act on it |
| Sign-in state (state, nonce, PKCE verifier, return path) | Sealed cookie | 10 minutes, checked on the server | AES-256-GCM, key from `SESSION_SECRET` |
| One-off messages | Sealed cookie | One minute, checked on the server | |
| Discovery document and signing keys | Server memory, shared | One hour | Public data |
| Managed identity tokens | Server memory, per audience | Until five minutes before expiry | Held as `Secret` |
| Audit sink queue | Server memory | Up to 10,000 events; sent every 5 seconds or at 500 | Each event is already on standard output |
| Email queue | Server memory | Up to 1,000 emails; each given up five minutes after its first try | |
| Email rate limit counts | Server memory | One-hour fixed window, at most 10,000 pairs | Counted by mailbox |
| Refusal counter for health notices | Server memory | 15 minutes per person or IP, at most 10,000 keys | Counts only |
| Event Grid dedupe | Server memory | 24 hours per vault, item, version and event type, at most 10,000 | Full means 503, never dropping an old entry |
| Pinned and recently opened items | Browser `localStorage`, key `keyring.pins` | Until sign-out or **Clear** | Kind, vault, item name, local path. Never a value, version, tag or token. At most 50 pinned and 10 recent |

A restart loses all of it. That signs everyone out and may send one repeat of an expiry email or a client secret notice, and that is the whole cost: there is nothing else to recover.

## What is never stored or logged

- Secret values, including every field of a typed secret, generated values and imported values.
- Private keys and PFX passwords.
- Tokens of any kind, cookies, the session ID itself, `IDENTITY_HEADER`, the client secret and `SESSION_SECRET`.
- Request and response bodies, headers and query strings (so search text and filters are never logged).
- Azure's error messages (only the status and error code are kept).
- The description note and owner or notify addresses (personal data). `KEYRING_NOTIFY_AUDIT_RECIPIENTS=true` is the one opt-in that puts email recipients on `notify.*` events.
- The reason a person typed, except in their own audit event's `reason` field.

`tests/no_secrets_in_logs.rs`, `tests/secrets_reveal_log.rs`, `tests/reason_log.rs` and the notify tests capture every log line at TRACE, in both text and JSON, through reveals, uploads, imports, generation, errors, descriptions, owners and email, and check that none of these appear.

## Tags Keyring reads and writes

Key Vault has no description or owner field. Keyring keeps these in ordinary tags. They show in the portal and CLI, anyone who can read an item's properties can read them, and each counts towards Key Vault's 15 tags per item. Every write reads the current tags, changes the one it owns and sends the whole set, because Key Vault replaces a version's tags as a whole.

| Tag | On | Written by Keyring | Rules |
|---|---|---|---|
| `description` | Secret, certificate, key | Yes, from the Description field, import column or bulk change | At most 256 UTF-16 code units. No control or invisible format characters; line breaks kept as `\n`. Never logged. Empty removes it (`src/description.rs`) |
| `owner` | Secret, certificate, key | Yes, from the Owner field | One plain `local@domain` address, held to `KEYRING_NOTIFY_ALLOWED_DOMAINS` when set. A value set elsewhere that Keyring wouldn't write is shown and kept byte for byte (`src/owner.rs`) |
| `notify` | Secret, certificate, key | Yes, from the Notify field | Up to 5 addresses separated by commas, within 256 characters |
| `keyring-owners` | Vault (ARM tag) | No, read from Resource Graph | Addresses separated by commas or semicolons, up to 20 shown. Vault health warns when missing |
| `rotation`, `rotation-last`, `rotation-status` | Secret | No | Untrusted text: cleaned, cut to 64 characters, escaped, shown as unknown when malformed (`src/rotation.rs`, `docs/rotation.md`) |

`description`, `owner` and `notify` never appear as tag rows and can't be added as ordinary tags; a row named one of them, even with spaces around it, is refused with a pointer to its field.

### Content types Keyring writes

Typed secrets use the content type `application/vnd.keyring.<type>+json;v=1` (`login`, `database`, `api-key`, `ssh-key`) and a compact JSON value with every field in a fixed order. Nothing is stored outside Key Vault. Reading is strict and bounded: over 25 KB isn't parsed, at most eight entries, and anything unexpected is shown as a plain value with a warning.

### Settings that act on values

- **Password policy** (`KEYRING_PASSWORD_POLICY`): rules for a value typed into a Password secret or a Login's password field, on create, Set a new value and import. The check runs in memory on the `Secret`; the refusal names the rule missed in fixed words, never the value or its length.
- **Owner rule** (`KEYRING_REQUIRE_OWNER`): a form that shows the Owner field refuses to save an item without an `owner` tag.

## Keyring's audit event

Every audited request writes one `AuditEvent` (`src/audit/mod.rs`), schema version 1, to standard output and, with the sink on, to `KeyringAudit_CL`. Fields with no value are left out. Appendix B lists every action and reason code.

| Field | Holds |
|---|---|
| `kind`, `schema_version` | `audit`, `1` |
| `time`, `event_id` | UTC with milliseconds; a random UUID |
| `action`, `outcome`, `reason_code` | What was done; `success`, `denied` (Azure 401 or 403), `refused` (Keyring's own check) or `failed`; Azure's error code or Keyring's reason, never Azure's message |
| `actor_oid`, `actor_tid`, `actor_upn` | From the verified ID token |
| `session_ref` | An HMAC of the session ID with a key derived from `SESSION_SECRET` |
| `client_ip`, `user_agent` | The socket peer, or `X-Forwarded-For` counted `KEYRING_TRUSTED_PROXY_HOPS` from the right; the user agent cut to 256 characters |
| `vault`, `item_kind`, `item_name`, `item_version` | What was acted on |
| `kv_request_id` | The last `x-ms-client-request-id` sent to Key Vault, to join with Key Vault's log |
| `reason`, `ticket` | When `KEYRING_REQUIRE_REASON` asked, or a PIM justification |
| `role`, `role_scope`, `role_duration` | On `role.activate` and `role.deactivate` (added to version 1) |
| `notify_type`, `notify_recipient_count`, `notify_recipients`, `notify_event_count` | On `notify.*` events (added to version 1) |
| `keyring_version`, `instance` | Keyring's version and a random ID for this run |

### The versioning rule

Adding an optional field, left out when not set, keeps the version, so a query on `schema_version == 1` still sees every row. Renaming or removing a field, or changing its meaning or type, is a new version with a CHANGELOG line. `tests/audit_events.rs` pins the version 1 names, lists the fields added since, and fails on a field in neither list; it also checks each added column is read with `column_ifexists` in the Sentinel parser.

### `KeyringAudit_CL` columns

`sink::COLUMNS` is the table's schema; a test checks `infra/modules/audit-sink.bicep` against it.

::: compact
| Column | Type | From | Column | Type | From |
|---|---|---|---|---|---|
| `TimeGenerated` | datetime | `time` | `ItemName` | string | `item_name` |
| `EventId` | string | `event_id` | `ItemVersion` | string | `item_version` |
| `SchemaVersion` | int | `schema_version` | `KvRequestId` | string | `kv_request_id` |
| `Action` | string | `action` | `Reason` | string | `reason` |
| `Outcome` | string | `outcome` | `Ticket` | string | `ticket` |
| `ReasonCode` | string | `reason_code` | `Role` | string | `role` |
| `ActorObjectId` | string | `actor_oid` | `RoleScope` | string | `role_scope` |
| `ActorTenantId` | string | `actor_tid` | `RoleDuration` | string | `role_duration` |
| `ActorUpn` | string | `actor_upn` | `NotifyType` | string | `notify_type` |
| `SessionRef` | string | `session_ref` | `NotifyRecipientCount` | int | `notify_recipient_count` |
| `ClientIp` | string | `client_ip` | `NotifyRecipients` | string | `notify_recipients` |
| `UserAgent` | string | `user_agent` | `NotifyEventCount` | int | `notify_event_count` |
| `Vault` | string | `vault` | `WriterIdentityClientId` | string | the sender's identity |
| `ItemKind` | string | `item_kind` | `KeyringInstance`, `KeyringVersion` | string | `instance`, `keyring_version` |
:::

The writer columns are whatever the sender put there. Treat the table as written by whoever holds Keyring's identity, and check a row that matters against Key Vault's own log by `KvRequestId` (threat T6).

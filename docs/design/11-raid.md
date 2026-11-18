# Assumptions, constraints, risks and decisions

## Assumptions

| ID | Assumption | If it is wrong |
|---|---|---|
| A1 | People already have the Azure roles they need, assigned by vault owners as for the portal | They see 403 pages naming the role to ask for, or the PIM offer |
| A2 | Admin consent is granted for the four delegated permissions, and for the two Graph permissions where sharing is on | Sign-in, the first vault page or only the audit pages say an admin must approve Keyring; without Graph consent the share picker says so and nothing is shared |
| A3 | Vaults send `AuditEvent` to a Log Analytics workspace people can read | Audit pages, reports and "Used by" say the log can't be read; vault health warns |
| A4 | One Keyring instance, or several with sticky sessions | Sessions are lost between copies |
| A5 | The deployment is in the Azure public cloud and one Entra tenant | Not supported (section 1.2) |
| A6 | Entra and Key Vault behave as Microsoft's REST reference says | Found differences are recorded on the checklist and the mocks changed to match |
| A7 | The list calls return the current version's `created` (age view) | The age view would need a versions call per secret; unconfirmed on a real vault |

## Constraints

| ID | Constraint | Source |
|---|---|---|
| K1 | No database and no stored state | Design principle "store nothing" |
| K2 | No app-only or managed identity access to people's data | Design principle "act as the user" |
| K3 | No npm or Node in the product; server-rendered HTML; strict CSP | Decisions D2 and D3 |
| K4 | One managed identity for Keyring's own calls; no client secret or second identity for them | `docs/architecture.md`, "Who makes each call" |
| K5 | Key Vault's own limits: 15 tags per item, 256 characters per tag value, 25 KB per secret value | Key Vault |
| K6 | No Microsoft Graph permission beyond sign-in, so no names for principals and no app registration credentials. **Reversed for sharing only** (D24): with `KEYRING_SHARING=true`, delegated `User.ReadBasic.All` and `GroupMember.Read.All` | Keeps consent to four delegated permissions unless sharing is wanted |
| K7 | New crates need a reason, `cargo deny` and `cargo audit` | `deny.toml`, dependency policy |

## Risks

::: compact
| ID | Risk | Likelihood | Impact | Response |
|---|---|---|---|---|
| R1 | A real tenant behaves differently from the mocks for sign-in, OBO, PIM, step-up, the sink, email or the webhook | Medium | Medium | Work through `docs/real-vault-checklist.md` on a test tenant before a pilot; fix the mocks and code for each difference |
| R2 | Someone adds an application permission to the app registration | Low | High | Documented as a security change (T3); review app registration changes |
| R3 | A restart signs everyone out | High during upgrades | Low | Upgrade out of hours; sessions across restarts considered after the pilot (section 11.6) |
| R4 | The ACS custom role's Write lets a stolen identity token change the one resource's settings | Low | Medium | Resource in Keyring's own group; Activity Log; Azure has no narrower role (T7) |
| R5 | Holders of the Event Grid subscriber role send real-looking expiry notices about vaults they control | Low | Low | Keep role holders and service principal owners short; remove the deployer's assignment after setup (T11) |
| R6 | A crate advisory with no fix | Medium | Varies | Accepted only with a reason and an issue (RUSTSEC-2023-0071 via `rsa`, #41; RUSTSEC-2026-0543 `chrono` unmaintained, #271) |
| R7 | A person relies on Keyring controls (step-up, reasons, password policy) as if Key Vault enforced them | Medium | Medium | Every page and document says they are Keyring controls; use Conditional Access on Key Vault for an everywhere control |
| R8 | ACS sending limits on an Azure-managed domain delay email | High on a managed domain | Low | Use a custom domain beyond a trial |
| R9 | Logs arrive late, so "Used by" or alerts miss recent use | Medium | Low | The panel never calls a change safe; rules look back past the ingestion delay |
| R10 | Sharing is turned on without step-up or the reason gate, and a stolen session shares secrets | Low | High | Turn step-up and `KEYRING_REQUIRE_REASON` on with sharing; Sentinel shares rule (T29) |
| R11 | Plain shares (no PIM licence) are never revoked and keep access past their date | Medium without P2 | Medium | Overdue on the secret's page and the access review; use PIM where it is licensed (T30) |
| R12 | `watched-reads` is turned on without `KEYRING_NOTIFY_ALLOWED_DOMAINS`, so tag writers choose who hears about reads | Medium | Low | Documented before the setting; the reader's IP address is left out without the allow-list (T26) |
| R13 | `KEYRING_EVENTGRID_SUBSCRIPTIONS` left unset on a deployment not made from the templates | Low | Low | A warning at every start; the templates set it (T11) |
:::

## Decisions

The design decisions D1 to D12 are in section 2.3. Decisions made while building, recorded here so they aren't reopened without cause:

| ID | Decision | Reason |
|---|---|---|
| D13 | Certificate "Do nothing" isn't offered once a lifetime action is set | A real vault keeps the old action when sent an empty list (13-11-2026) |
| D14 | The edit form refuses a removed date | A real vault ignores `"exp": null` |
| D15 | Recover sends `Content-Length: 0` | A real vault answers 411 without it |
| D16 | Pins in `localStorage`, not on the server | Keeps "store nothing" true |
| D17 | The webhook checks `topic` | The token proves only that Event Grid delivered the event |
| D18 | Email repeatability IDs are never reissued | ACS remembers a request five minutes; a new ID could send twice |
| D19 | The description is counted in UTF-16 code units | Key Vault is a .NET service; browsers count the same units |
| D20 | Request access emails the vault's owners and grants nothing | Keyring has no right to assign roles and must not gain one; the owners decide in Azure |
| D21 | Watched-read emails go to `notify`, and to `owner` only with `KEYRING_NOTIFY_OWNER_ON_READ` | An owner may not want an email on every read; `notify` is the explicit opt-in |
| D22 | A `keyring-reveal` value Keyring doesn't know counts as `none` | Fail closed: a typo set in the portal must not turn the limit off |
| D23 | An empty `KEYRING_EVENTGRID_SUBSCRIPTIONS` is the same as unset | Every setting treats an empty value as unset; the warning at start says any subscription is accepted |
| D24 | Sharing uses delegated Microsoft Graph for names, as the person | A share picked by object ID alone is too easy to get wrong. Reverses the object-IDs-only design (K6) for this one feature; the Access page and access review still make no Graph call |
| D25 | A PIM setting that refuses a share refuses it; only a missing PIM licence falls back to a plain assignment | A plain assignment has no end date and would step round the setting |

## Confirmed and not yet confirmed on a real tenant

::: unconfirmed
**Confirmed.** The Key Vault REST calls for secrets, certificates and keys, against real vaults on 11-11-2026 (by hand), 12-11-2026 and 13-11-2026 (`tests/real_vault.rs`), with five differences found and fixed. A browser run of Keyring against a real tenant on 17-11-2026.

**Built and tested against mocks only.** Sign-in and on-behalf-of in a production deployment; RBAC role behaviour; PIM activation and its ACRS challenge; Conditional Access step-up; the Bicep deployments; the Sentinel parser, rules and workbook; the audit sink (Logs Ingestion API, `Direct` rule, table, role); email through ACS (api-version 2025-09-01, repeatability, the two-action role, domains); the Event Grid webhook (token claims, `aud` form, `topic`, dead-lettering, the delivery header, the subscription allow-list).

**Added in version 1.1, all mocks only.** Request access and its emails; activity emails (watched reads, deletes and bulk changes, role use) and the vault owners read; reveal limits (including whether Key Vault copies a certificate's tags to its backing secret); the access review query; secret sharing: PIM `AdminAssign` with an end date at a secret's scope, the plain fallback and its exact error code, Revoke, Graph search with and without consent, guests, and the share emails.
:::

`docs/real-vault-checklist.md` holds a row for each, and its Record of runs is the place to record a result.

## Known limitations and roadmap

**Limitations.** Section 8.4 lists the known limits. In short: sessions are in memory; Keyring controls aren't Key Vault controls; object IDs, not names, outside sharing; plain shares have no end date in Azure; no rotation on target systems; public cloud, Key Vault only, one tenant.

**Built since version 1.0.** The five changes version 1.0 listed as in progress are built and described above, with secret sharing:

| Change | Issue | Where this document describes it |
|---|---|---|
| Request access from the 403 page when PIM isn't available | #258 | Sections 4.1, 6.3, 7.5; C24, T25; D20; appendices B and F |
| Emails on watched reads, deletes and bulk changes, and PIM role use | #259 | Sections 4.4, 6.3; C25, T26, T27; D21; appendix A |
| Reveal limits with a `keyring-reveal` tag | #261, part 2 | Sections 4.1, 5.3; C23, T28; D22; appendices B and F |
| The access review report per vault | #261, part 3 | Sections 4.1, 4.2, 6.1, 7.4; appendix F |
| The webhook subscription allow-list | #278 | Section 6.1 (I-26); C15, T11; D23; appendices A and B |
| Share a secret | #286 | Sections 4.1, 4.2, 6.1 (I-28 to I-30), 7.6; C26, C27, T29 to T34; D24, D25; appendices A, B and F |

**Later.**

- **Sessions across restarts**, after the pilot, once there is pilot data on how often restarts hurt.
- **Drop the RUSTSEC-2023-0071 exception** when `openidconnect` moves to `rsa` 0.10 (#41), and RUSTSEC-2026-0543 when it no longer needs `chrono` (#271).
- **Names for principals on the Access page** and **app registration credentials**. Sharing now has delegated Graph permissions for names; using them elsewhere would be a separate decision.
- **Reason and ticket beside Key Vault's row in "Used by"**, once the `kv_request_id` to `CorrelationId` join is confirmed on a real vault.
- **Close the mock gaps** found on real tenants (#170).

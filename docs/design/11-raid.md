# Assumptions, constraints, risks and decisions

## Assumptions

| ID | Assumption | If it is wrong |
|---|---|---|
| A1 | People already have the Azure roles they need, assigned by vault owners as for the portal | They see 403 pages naming the role to ask for, or the PIM offer |
| A2 | Admin consent is granted for the four delegated permissions | Sign-in, the first vault page or only the audit pages say an admin must approve Keyring |
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
| K6 | No Microsoft Graph permission, so no names for principals and no app registration credentials | Keeps consent to four delegated permissions |
| K7 | New crates need a reason, `cargo deny` and `cargo audit` | `deny.toml`, dependency policy |

## Risks

::: compact
| ID | Risk | Likelihood | Impact | Response |
|---|---|---|---|---|
| R1 | A real tenant behaves differently from the mocks for sign-in, OBO, PIM, step-up, the sink, email or the webhook | Medium | Medium | Work through `docs/real-vault-checklist.md` on a test tenant before a pilot; fix the mocks and code for each difference |
| R2 | Someone adds an application permission to the app registration | Low | High | Documented as a security change (T3); review app registration changes |
| R3 | A restart signs everyone out | High during upgrades | Low | Upgrade out of hours; sessions across restarts considered after the pilot (section 11.5) |
| R4 | The ACS custom role's Write lets a stolen identity token change the one resource's settings | Low | Medium | Resource in Keyring's own group; Activity Log; Azure has no narrower role (T7) |
| R5 | Holders of the Event Grid subscriber role send real-looking expiry notices about vaults they control | Low | Low | Keep role holders and service principal owners short; remove the deployer's assignment after setup (T11) |
| R6 | A crate advisory with no fix | Medium | Varies | Accepted only with a reason and an issue (RUSTSEC-2023-0071 via `rsa`, #41; RUSTSEC-2026-0543 `chrono` unmaintained, #271) |
| R7 | A person relies on Keyring controls (step-up, reasons, password policy) as if Key Vault enforced them | Medium | Medium | Every page and document says they are Keyring controls; use Conditional Access on Key Vault for an everywhere control |
| R8 | ACS sending limits on an Azure-managed domain delay email | High on a managed domain | Low | Use a custom domain beyond a trial |
| R9 | Logs arrive late, so "Used by" or alerts miss recent use | Medium | Low | The panel never calls a change safe; rules look back past the ingestion delay |
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

## Confirmed and not yet confirmed on a real tenant

::: unconfirmed
**Confirmed.** The Key Vault REST calls for secrets, certificates and keys, against real vaults on 11-11-2026 (by hand), 12-11-2026 and 13-11-2026 (`tests/real_vault.rs`), with five differences found and fixed. A browser run of Keyring against a real tenant on 17-11-2026.

**Built and tested against mocks only.** Sign-in and on-behalf-of in a production deployment; RBAC role behaviour; PIM activation and its ACRS challenge; Conditional Access step-up; the Bicep deployments; the Sentinel parser, rules and workbook; the audit sink (Logs Ingestion API, `Direct` rule, table, role); email through ACS (api-version 2025-09-01, repeatability, the two-action role, domains); the Event Grid webhook (token claims, `aud` form, `topic`, dead-lettering, the delivery header).
:::

`docs/real-vault-checklist.md` holds a row for each, and its Record of runs is the place to record a result.

## Known limitations and roadmap

**Limitations.** Section 8.4 lists the known limits. In short: sessions are in memory; Keyring controls aren't Key Vault controls; no Graph, so object IDs not names; no rotation on target systems; public cloud, Key Vault only, one tenant.

**In progress at the time of writing.** These five changes were being built while this document was written. None is described as built anywhere above. When each merges, the second pass of this document adds what is shown.

| Change | Issue | What the document gains |
|---|---|---|
| Request access from the 403 page when PIM isn't available, emailed to the vault's owners | #258 | Integration row for the email path; `access-requests` notice in chapter 6; a threat and control in chapter 8; the audit action in appendix B; routes in chapter 4 |
| Emails on watched reads, deletes and bulk changes, and PIM role use | #259 | `watched-reads`, `destructive` and `role-use` notices in chapter 6; any new settings in appendix A; threats for recipients from item tags |
| Reveal limits per item with a `keyring-reveal` tag | #261, part 2 | The tag in section 5.3; a control and threat in chapter 8; any reason code in appendix B |
| An access review report per vault | #261, part 3 | A page and CSV in chapter 4; its reads in chapter 6 |
| A subscription allow-list on the webhook | #278 | `KEYRING_EVENTGRID_SUBSCRIPTIONS` in appendix A; the check in C15 and T11; a reason code in appendix B |

**Later.**

- **Sessions across restarts**, after the pilot, once there is pilot data on how often restarts hurt.
- **Drop the RUSTSEC-2023-0071 exception** when `openidconnect` moves to `rsa` 0.10 (#41), and RUSTSEC-2026-0543 when it no longer needs `chrono` (#271).
- **Names for principals** and **app registration credentials**, only if a Graph permission is ever accepted.
- **Reason and ticket beside Key Vault's row in "Used by"**, once the `kv_request_id` to `CorrelationId` join is confirmed on a real vault.
- **Close the mock gaps** found on real tenants (#170).

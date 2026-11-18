# Introduction

## Purpose

This document records the design of Keyring: what it is for, how it is built, what it trusts, what it holds, every call it makes to other services, how it is secured, deployed and run, and what is still open. It is the formal record for three groups:

- reviewers of the design and its security, who need the architecture, the controls and the threat model in one place;
- the platform teams who deploy Keyring into an Azure subscription and connect it to an Entra ID tenant;
- the people who run it day to day.

`docs/architecture.md` in the repository stays the short engineering reference, and the tests in `tests/docs.rs` read it. Where the two differ, the code is the source of truth, then `docs/architecture.md`, and this document should be corrected.

::: unconfirmed
**Status.** Draft for review. Nobody has reviewed, approved or endorsed this design. The Key Vault REST calls and a browser run against a real tenant (17-11-2026) are confirmed. Sign-in and on-behalf-of in a deployed production instance, PIM, Conditional Access step-up, the deployments, the Sentinel content, the audit sink, email and the Event Grid webhook are built and tested against mock services only. So is everything added in version 1.1: request access, activity emails, reveal limits, the access review, the webhook subscription allow-list and secret sharing. Section 11.5 lists each open item.
:::

## Scope

### In scope

Keyring as it is on the `main` branch at commit `b76c19a` (18-11-2026), with secret sharing as built in pull request #289:

- the web application (`src/`, `templates/`, `static/`), built as one Rust binary in one container image;
- secrets, certificates and keys: list, read, create, change, delete, recover and, when turned on, purge;
- search, pins and recently opened items, the generator, the expiry dashboard, the age view and vault health;
- the audit pages (Key Vault's log, Keyring's own events, reports across vaults, "Used by"), Keyring's own audit events and the optional audit sink with its Sentinel content;
- access views, the access review report, permission hints, PIM activation, request access, step-up and reasons;
- sharing one secret with a person or security group, as a time-limited role assignment made as the person sharing, when `KEYRING_SHARING=true`;
- copy to another vault, bulk changes, import, descriptions, tag rows, owner and notify tags, reveal limits (`keyring-reveal`) and the optional password policy;
- email through Azure Communication Services: health notices, expiry notices pushed by Event Grid, access requests, activity emails (watched reads, deletes and bulk changes, PIM role use) and share notices;
- the Bicep templates in `infra/` for App Service and Container Apps, the optional alerts, Sentinel and private networking modules.

### Out of scope, by design

Keyring deliberately does not do these things. Each is a decision, not a gap waiting to be filled.

| Not done | Why |
|---|---|
| A database or any stored state | Keyring stores nothing. Sessions are in memory; pins live in the person's browser; notes, owners and policy live in Key Vault tags |
| App-only access to vaults | Every call that reads or changes a person's data uses that person's own token. Keyring's managed identity has no vault role |
| Key export | Keyring never calls export, backup, release, decrypt, unwrap or sign on keys (a test checks). Public keys only |
| Secrets export | There is no "export all values" file. A plain-text file of every value is what a secrets tool should make hard |
| Sovereign clouds | The Entra, ARM, Key Vault and Log Analytics hosts are fixed to the Azure public cloud |
| Managed HSM | Only Key Vault vaults (`*.vault.azure.net`) |
| Several tenants | One Keyring serves one Entra tenant |
| Rotating credentials on the target system | A new value set in Keyring changes Key Vault only. Azure's own pattern (Event Grid and a Function with its own identity) or removing the credential is the answer (`docs/rotation.md`) |
| App registration credentials | Showing client secrets and certificates on Entra app registrations needs a Microsoft Graph permission (`docs/app-credentials.md`) |
| Names for people and groups on the Access page | The Access page and the access review make no Microsoft Graph call, so they show object IDs and link to the portal. Sharing is the one exception: with `KEYRING_SHARING=true` it uses delegated Graph permissions to find people and groups and to name who a secret is shared with (decision D24) |
| Certificates signed outside Key Vault | No `Unknown` issuer, signing request download or merge. Issuers are managed in the portal |
| Hosting under a path | Keyring must be at the root of its host |

### Added in version 1.1

Version 1.0 listed five changes as in progress. All five are now on `main` and described as built: request access from the 403 page (#258), activity emails (#259), reveal limits (#261 part 2), the access review (#261 part 3) and the webhook subscription allow-list (#278). Version 1.1 also adds secret sharing (#286, pull request #289). None of these has run against a real tenant.

## Audience

| Reader | Read first | What they need from it |
|---|---|---|
| Solution or security architect | Chapters 2, 3, 6, 7 and 8 | The design principles, the trust boundaries, every outbound call and identity, the controls and the threat model |
| Identity administrator (Entra ID) | Chapter 7, sections 9.3 and 10.5 | The app registration, consent, the managed identity's federated credential, Conditional Access and PIM |
| Azure platform engineer | Chapters 9 and 10, appendix A | The Bicep paths, parameters, networking, settings, health endpoints and logs |
| Operator or support | Chapter 10, appendices A and B | Health, logs, alerts, audit actions and reason codes, upgrades and removal |
| Developer | Chapters 3, 4 and 5 | Modules, components, data and the rules the code keeps |

## Related documents

All paths are in the Keyring repository.

| Document | What it covers |
|---|---|
| `README.md` | What Keyring does, the app registration, roles people need, configuration |
| Documentation site, <https://jusso-dev.github.io/keyring/> | The guides and references below, published, with links to the PDF and Word editions of this document |
| `docs/architecture.md` | The engineering reference this document is built from, including the threat model summary |
| `docs/deploy.md` | Step-by-step deployment, logs, audit event fields, the audit sink, email, access requests, activity emails, step-up, reasons, password policy, owners, sharing, secret rotation |
| `docs/alerts.md` | Expiry alerts through Event Grid, expiry emails from Keyring, access alerts |
| `docs/sentinel.md` | The Sentinel parser, analytic rules, hunting queries and workbook for `KeyringAudit_CL` |
| `docs/private-vaults.md` | Reaching vaults that only accept private traffic |
| `docs/rotation.md` | What Keyring does and doesn't do about rotation, and the tag convention |
| `docs/app-credentials.md` | Why app registration credentials aren't shown, and Entra's own tools |
| `docs/real-vault-checklist.md` | What has and hasn't been confirmed against a real tenant and vault |
| `docs/troubleshooting.md` | Common problems and Entra error codes |
| `design.md` | The locked visual design system (colours and type used here too) |
| `SECURITY.md` | Reporting a vulnerability and verifying an image |
| `CHANGELOG.md` | Every change, by pull request |

## Conventions

- Dates are written DD-MM-YYYY. Times are UTC.
- Integration flows are numbered I-01, I-02 and so on (chapter 6), controls C1, C2 and so on (chapter 8), threats T1, T2 and so on (chapter 8). The numbers are stable: new items are added at the end.
- "The person" means whoever is signed in to Keyring. "Keyring's identity" means its one user-assigned managed identity.
- Examples use made-up names: `keyring.example.com`, `kv-payments-prod`, and the zero GUID `00000000-0000-0000-0000-000000000000`. Nothing here comes from a real tenant.

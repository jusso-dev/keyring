# Security design

Keyring's security rests on its first principle: it acts as the person, so it can never reach more than they can. This chapter lists the controls that protect what Keyring does hold (section 8.1), its trust boundaries (8.2), a STRIDE threat model (8.3) and its known limits (8.4).

## Security controls

::: {.compact .landscape}
Each control has a stable number, used in the overlay diagram (Figure 4) and the threat model (section 8.3). New controls are added at the end.

| ID | Control | Where | How |
|---|---|---|---|
| C1 | Act as the person | `src/azure/token.rs`, `src/azure/client.rs`; Key Vault, ARM, Log Analytics | Every data call carries the person's OBO token. No app-only path exists. Key Vault RBAC or access policies decide |
| C2 | Least-privilege identities | Entra ID, `infra/modules/` | Delegated-only app registration. One managed identity with only a federated credential, Monitoring Metrics Publisher on one rule and the two-action ACS role on one resource (section 7.3) |
| C3 | Strong sign-in | `src/auth/oidc.rs` | Authorisation code flow with PKCE (S256), state and nonce; ID token signature, issuer, audience, expiry and nonce checked; key rollover handled |
| C4 | Session protection | `src/auth/session.rs`, cookies | Random 256-bit ID, http-only, `SameSite=Lax`, `Secure` and `__Host-` over HTTPS; one hour idle, 12 hours absolute; tokens never leave the server; sealed cookies time-limited on the server |
| C5 | Forged request defence | `src/routes/origin.rs`, form tokens | Per-session form token checked in constant time and bound to the vault in the address, plus an origin check on every non-GET. The only exemption is exactly `/hooks/eventgrid` |
| C6 | Output and browser hardening | `src/routes/headers.rs`, templates, scripts | Askama escaping; CSP `default-src 'none'` with same-origin scripts, styles and fonts, no inline code or `eval`; `frame-ancestors 'none'`, `X-Frame-Options: DENY`; no `innerHTML`; `no-store` on every page, reveal, download and CSV |
| C7 | Input checked before use | Vault, item and version name checks; KQL builders | Names checked against Key Vault's own rules before any URL; `nextLink` and backing secret URLs only followed on the same host; audit filters only as escaped KQL `let` literals; CSV formula guarding |
| C8 | Secret handling | `src/secret.rs`, `src/azure/token.rs`, `src/telemetry.rs` | `Secret` and `AccessToken` print `[redacted]` and are zeroised; values, tokens, bodies, headers, query strings and Azure messages never logged (tested at TRACE); the panic hook logs only a location |
| C9 | Safe destructive actions | `src/routes/confirm.rs`, `src/routes/lifecycle.rs` | Typed name checked on the server; purge refused unless `KEYRING_ALLOW_PURGE=true`; no bulk delete or purge; managed items refused |
| C10 | Step-up | `src/routes/step_up.rs` | Optional authentication context or maximum sign-in age before a reveal, private key download, rollback, copy, purge or PIM activation |
| C11 | Reasons | `src/routes/reason.rs`, `src/reason.rs` | Optional reason and ticket, cleaned and checked before any audited handler, recorded on the event |
| C12 | Audit coverage | `src/audit/mod.rs`, `tests/audit_events.rs` | One event per audited request whatever the outcome; every POST route audited or exempt with a reason; a forged token on each audited route writes one `refused` event and nothing reaches Key Vault |
| C13 | Audit sink | `src/audit/sink.rs`, Logs Ingestion API | Events written to `KeyringAudit_CL` as Keyring's identity only; writer columns; health endpoint; `KEYRING_AUDIT_REQUIRED` refuses reveals while degraded |
| C14 | Email safety | `src/notify/` | Sent as Keyring's identity only; strict `to` addresses; domain allow-list; per-recipient rate limit; fixed content with no values, tokens, Azure messages or typed reasons; repeatability IDs; addresses never logged |
| C15 | Webhook authentication | `src/auth/eventgrid.rs`, `src/notify/expiry.rs` | Entra token checked first (RS256, tenant keys, issuer, audience, tenant, expiry, Event Grid's app ID, subscriber role, app-only); topic must be a Key Vault resource ID; size, count and rate limits; dedupe; 404 unless turned on |
| C16 | Value policies | `src/password_policy.rs`, `src/owner.rs` | Optional password policy on typed and imported passwords; optional owner rule. Keyring controls only |
| C17 | Transport security | `src/http.rs` | rustls with `ring`; HTTPS only except localhost; no redirects; fixed Azure public cloud hosts; connect and total timeouts; managed identity endpoint limited to the local host or link-local range |
| C18 | Resource limits | `src/serve.rs`, `src/routes/mod.rs` | 10 s header timeout; 64 KB form limit (larger only for value, upload and import forms); 90 s per request; 512 connections; connection age; bounded queues and maps everywhere |
| C19 | Supply chain | `Cargo.lock`, `deny.toml`, CI | Few crates, crates.io only, permissive licence allow-list, `cargo deny` and `cargo audit` on every change and weekly, pinned toolchain, actions pinned by SHA, images by digest, SBOMs, signed provenance on release |
| C20 | Runtime hardening | `Dockerfile`, `Cargo.toml` | `forbid(unsafe_code)`; distroless static image, non-root, read-only root filesystem, no capabilities, no shell; unwind on panic so one request's bug doesn't end other sessions |
| C21 | Browser-side data limits | `static/pins.js`, `static/app.js` | Pins hold names only, are rebuilt from checked names and cleared on sign-out; revealed values hidden after 30 s; clipboard cleared after copy |
| C22 | Store nothing | Whole design | No database or disk writes; per-session caches only, bounded and short-lived; secret values only in memory on the way to the browser |
:::

![Security controls overlay. Each C-number sits on the component that enforces it.](../diagrams/drawio/export/06-security-controls.png)

## Trust boundaries

| Boundary | Trusted with | Not trusted with |
|---|---|---|
| The browser | A random session ID in an http-only cookie; one revealed value at a time; pinned names | Tokens; anything it sends (every input is checked again on the server) |
| Keyring's server | The person's tokens in memory for the session; values in transit to the browser | Access of its own to any vault or workspace |
| Microsoft Entra ID, Key Vault, ARM, Log Analytics | Every authorisation decision, as the person | Out of scope if compromised |
| Keyring's managed identity | Acting as the app registration (federated credential), adding audit rows, sending email from one ACS resource | Any vault or workspace read path |
| Event Grid deliveries | Proving Event Grid delivered the event (the token) | The event's content beyond fixed fields, checked names and the topic |

## STRIDE threat model

Built from `docs/architecture.md`, "Threat model", and extended for notifications, the webhook and the managed identity. Each threat names its STRIDE category (S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of privilege), the controls that answer it and what is left. New threats are added at the end.

::: {.compact .landscape}
| ID | STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | E | Keyring used to reach vaults a person can't | C1, C2: every data call carries the person's OBO token; no app-only token with vault access | None beyond the person's own access |
| T2 | S, E | Stolen session cookie | C4, C10: random ID, http-only, `__Host-`, timeouts, server-side sign-out; optional step-up with a maximum age | A cookie from a session that already met step-up works until it ends or ages out. Set `KEYRING_STEP_UP_MAX_AGE` as well as a context |
| T3 | E | The managed identity used to act as the app with nobody signed in | C2: delegated-only registration, OBO needs a person's token | Holds only while the registration has no application permissions. Treat adding one as a security change |
| T4 | S | Forged or replayed sign-in | C3: PKCE, state, nonce, ID token checks, sealed state cookie | None known |
| T5 | T | Cross-site request forgery | C5: form token bound to the vault plus origin check, tested on every mutating route | The webhook is exempt by design and has C15 instead |
| T6 | T, R | Made-up rows in `KeyringAudit_CL` with a stolen identity token | C13: Monitoring Metrics Publisher on one rule only; can't read, change or delete rows | Made-up rows can carry any writer or actor. Check a row that matters against Key Vault's own log by `KvRequestId` |
| T7 | S, I | A stolen identity token used to send email | C2, C14: two-action role on one resource in Keyring's own resource group; no keys | A stolen token could send mail from Keyring's domain outside Keyring's own allow-list and rate limit, and change that one resource's settings. ACS limits, ACS logs and the Activity Log are what remain |
| T8 | I | Email used to leak values | C14: fixed text, checked names, never a value, token, private key, Azure message or reason (tested at TRACE over logs and every body sent) | None known |
| T9 | D, S | Email used to mail-bomb or phish | C14: strict `to` addresses, allow-list, per-recipient rate limit; health emails to admins only, outside text in labelled fields, burst emails capped at 10 an hour | Within the limits, an admin can get repeated notices |
| T10 | S | The webhook used without a session | C15: token checked first, app-only, subscriber role, 1 MB, 50 events, separate bounded counter for bad tokens | Whoever can change the subscription can trigger expiry notices to the admins or allowed addresses, within the limits |
| T11 | S, T | Made-up expiry events through Event Grid | C15: Event Grid stamps `topic`; custom topics are refused; recipients held to admins or the allow-list; dedupe | Holders of the subscriber role or owners of Keyring's service principal can subscribe any real vault they control and send real-looking notices about its items, and can use up the 120 a minute. Keep that list short. Whether a custom input schema can map into `topic` is unconfirmed |
| T12 | I | Secret values or tokens in logs | C8: wrappers, redaction, no bodies, headers or query strings; tested at TRACE in text and JSON | Copies inside `openidconnect` and `reqwest` aren't zeroised |
| T13 | I | Values cached by browsers or proxies, or left on screen or clipboard | C6, C21: `no-store`; hidden until asked; wiped after 30 s; clipboard cleared, retried on focus | A clipboard clear can fail if the browser refuses it |
| T14 | T, I | Cross-site scripting | C6: escaping, strict CSP, no inline code, no `innerHTML` | None known |
| T15 | T | Query injection in the audit views | C7: strict patterns, then escaped `let` literals; fixed KQL; fixed time ranges | None known |
| T16 | T | CSV injection in exports | C7: formula guarding on every text field | None known |
| T17 | T, E | Path tricks in names or links | C7: names checked against Key Vault's rules; `nextLink` and backing secret URLs only on the same host; return paths local only | None known |
| T18 | T | Accidental or malicious deletes | C9: typed name; purge off by default; no bulk delete | A person with the role can still delete through the CLI or portal |
| T19 | I | Private key leaks | C9, C1: no key export calls (tested); JWK type has no private fields; certificate private key download only for exportable policies, after a typed name | Certificate User at vault scope can read every secret; assign it per certificate |
| T20 | R | Actions with no trace | C12: one event per audited request, including refusals and Azure's 401 and 403; coverage tested | Read-only pages write no event (the request line covers them). Events are on standard output; the sink is optional |
| T21 | D | Large, slow or many requests | C18: header timeout, body limits, request limit, connection cap and age; webhook counters; bounded maps | The connection cap is shared by every client; a front-end proxy normally covers the rest |
| T22 | T | Tampered pinned list or shared-browser exposure | C21: entries rebuilt from checked names and local paths; cleared on sign-out; **Clear** button | Names stay until sign-out or Clear if a browser is closed without signing out |
| T23 | T, E | Supply chain or container tampering | C19, C20 | Trust in crates.io crates and base images that pass the checks |
| T24 | I | Description or owner text exposing sensitive data | C8, C16: never logged or put in an event; control and invisible characters refused; the form says not to put secrets in it | Tags are readable by anyone with read access to the item's properties |
:::

**Request access, watched reads and reveal limits** are in progress at the time of writing (section 11.5). When they merge, each adds threats here (for example, request access used to phish vault owners) and controls in section 8.1.

## Known limits

- **Sessions are in memory.** A restart signs everyone out, and several copies need sticky sessions. Anyone who can read the server's memory can read active tokens.
- **The session secret** only protects short-lived cookies. Rotating it means a restart.
- **Keyring controls are Keyring's own.** Step-up, reasons, the password policy and the owner rule don't stop anyone using the Azure CLI, the portal or another app. A Conditional Access policy on Key Vault itself is what applies everywhere.
- **Keyring doesn't rotate credentials on the target system.** The rotation line is a display of tags anyone with tag rights can write.
- **Keyring trusts Azure's answers.** A compromised Entra tenant or Key Vault is out of scope.
- **Access shows object IDs, not names**, and app registration credentials aren't shown, because Keyring has no Graph permission.
- **The connection cap is shared** by every client; idle connections and slow bodies are limited only by the request limit and connection age.
- **Pinned names outlive a closed tab** until the next sign-out or Clear.
- **Zeroising covers Keyring's own copies** of tokens, not those inside `openidconnect` and `reqwest`.
- **A panic** gives that one request a 500 page; sessions survive it.
- **Not yet run against a real tenant:** sign-in in production, PIM, step-up, the deployments, Sentinel, the audit sink, email and the webhook (section 11.4).

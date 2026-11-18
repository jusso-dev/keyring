# Component design

The crate is one binary. `src/main.rs` loads the configuration (failing fast with a list of what is missing or wrong), starts logging, binds and serves. `src/lib.rs` holds `AppState` and the router, so tests drive the whole app without a socket. Static files and templates are compiled in.

## Web server and routes (`src/routes/`)

One file per area. Every POST route is either wrapped in `audited(Action, handler)` or on an exempt list with a reason, and a test (`tests/audit_events.rs`) reads the router to check.

| Module | What it serves |
|---|---|
| `vaults.rs`, `home.rs`, `shell.rs`, `vault_ctx.rs` | The vault list and picker, the home page, and what every layout needs: who is signed in, their form token, the vault in the address |
| `secrets/` | Secrets list, detail, versions, reveal, create and edit (`form.rs` holds the shared form checks), delete, copy to another vault, import (`import.rs`, `import_file.rs`) |
| `certs/` | Certificate list, detail, create, upload with preview, renewal, downloads, delete |
| `keys/` | Key list, detail, create, rotate, rotation policy, delete. Public parts only |
| `details.rs` | Edit details (description and tag rows) for certificates and keys |
| `lifecycle.rs`, `lifecycle/handlers.rs`, `confirm.rs` | Delete, recover and purge for all three kinds, and typed confirmation |
| `bulk.rs`, `batch.rs` | Bulk changes, and the four-at-a-time runner shared with import |
| `tag_rows.rs` | Tag rows and their suggestions, the tag filter |
| `search.rs`, `every_vault.rs` | Search across vaults, and reading every vault's lists (shared with expiry and age) |
| `expiry.rs`, `age.rs`, `vault_health.rs` | The expiry dashboard, age view and vault health, each with CSV |
| `audit.rs`, `audit_keyring.rs`, `audit_across.rs`, `used_by.rs` | Key Vault's log for a vault, Keyring activity, reports across vaults, the "Used by" panel |
| `access.rs`, `hints.rs`, `pim.rs` | Access page and sections, permission hints, PIM activation and My access |
| `access_review.rs` | The access review, `/v/{vault}/access/review` and `/v/{vault}/access/review.csv`: every item with its owner, notify, description, value age, who used it in 90 days, who has access and rotation status. Reads only, as the person; writes no audit event |
| `access_request.rs` | Request access, `GET` and `POST /v/{vault}/my-access/request` (`access.request`), when email and `access-requests` are on; "not found" otherwise. Offered on a `ForbiddenByRbac` 403 page with no PIM offer, and on My access |
| `reveal_limit.rs` | The "Not shown in Keyring" refusal, the reads that find an item's `keyring-reveal` limit, and the step-up and reason check before a limit is loosened |
| `share.rs` | With `KEYRING_SHARING=true` only ("not found" otherwise): `GET` and `POST /v/{vault}/secrets/{name}/share` (`share.grant`), `GET` and `POST /v/{vault}/secrets/{name}/share/revoke` (`share.revoke`), the picker's JSON at `/v/{vault}/share/people?q=` (30 searches a minute per session, `no-store`) and My shares at `/v/{vault}/my-access/shares` |
| `step_up.rs`, `reason.rs`, `audit_gate.rs` | The three gates that run before Azure is called on sensitive actions, sharing and revoking a share included |
| `origin.rs`, `headers.rs`, `rejection.rs`, `error.rs` | The origin check, security headers, extractor errors, plain-English error pages |
| `auth.rs` | Sign-in, callback, keep-alive, sign-out, signed out |
| `hooks.rs` | `POST /hooks/eventgrid` |
| `health.rs` | `/healthz`, `/healthz/audit`, `/healthz/notify`, no sign-in |
| `assets.rs` | Static files with content-hash versions, cached a year when current |
| `generator.rs` | Passwords, GUIDs and API keys, shown once, never stored |
| `moved.rs` | Redirects from old addresses without a vault (308) |
| `flash.rs`, `forms.rs`, `paging.rs` | One-off messages, shared form pieces, paging |

## Azure clients (`src/azure/`)

| Module | Calls (all as the person) |
|---|---|
| `token.rs` | The `TokenBroker`: refresh and OBO exchange per resource (Key Vault, Management, Log Analytics, Graph), cached per session, one in flight at a time |
| `client.rs` | The REST client: attaches the token, a fresh `x-ms-client-request-id`, retries once on 401, maps errors to status and code |
| `secrets.rs`, `certs.rs`, `keys.rs`, `paging.rs` | Key Vault REST API 7.5. `nextLink` followed only on the same vault |
| `vaults.rs` | Resource Graph vault and subscription queries, and one vault's tags (`vault_tags`) for activity emails |
| `audit.rs`, `audit_across.rs`, `audit_keyring.rs`, `used_by.rs` | Diagnostic settings through ARM, then Log Analytics queries. Filters reach KQL only as escaped `let` literals |
| `authz.rs` | Role assignments, eligible assignments, role definitions, permissions, the vault resource (access model and policies) |
| `pim.rs` | PIM eligibility, active and requested instances, policy rules, `SelfActivate` and `SelfDeactivate` |
| `access_review.rs` | One Log Analytics query per workspace for every item in a vault over 90 days, at most 20 callers per item and 2000 rows per workspace |
| `share.rs` | A share's role assignment at a secret's scope: PIM `AdminAssign` and `AdminRemove`, or a plain `roleAssignments` PUT and DELETE; listing the assignments and PIM requests that are Keyring's shares |
| `graph.rs` | Microsoft Graph, delegated, for sharing only: search users and security groups by name, read one by ID or exact address, read names for a list of IDs. Never group members |
| `fanout.rs` | Reading every vault the person can see: six at a time, 20 seconds each, a minute in all, first 100 by name |

## Sign-in and sessions (`src/auth/`)

| Module | Job |
|---|---|
| `oidc.rs` | OIDC with the `openidconnect` crate: discovery and signing keys cached for an hour, refetched once on an unknown key, last good copy kept on failure |
| `session.rs` | The in-memory session store: one hour idle, 12 hours absolute, swept every minute; per-session token, list and hint caches |
| `cookies.rs`, `crypto.rs` | Cookie handling, AES-256-GCM sealing with keys derived from `SESSION_SECRET` (HKDF-SHA256), the cookie name bound in |
| `return_to.rs` | Local return paths only |
| `entra.rs` | One place that maps Entra error codes to "sign in again", "an admin must consent", Conditional Access blocks or a setting to fix |
| `step_up.rs` | The step-up policy and the claims request built from settings |
| `assertion.rs` | `ManagedIdentityTokens`, the one managed identity token source, cached per audience; the client assertion for the federated credential |
| `eventgrid.rs` | The Event Grid bearer token check, using the same cached key set as sign-in |

## Audit, email and the rest

| Module | Job |
|---|---|
| `src/audit/mod.rs` | `AuditEvent` schema version 1, `Action` and `Refusal` lists, the per-request layer, `ItemEvents` for imports and bulk changes, the observer hook |
| `src/audit/sink.rs` | The audit sink: bounded queue, batching, gzip, retries, `/healthz/audit` state, `COLUMNS` |
| `src/notify/mod.rs`, `sender.rs`, `rate.rs` | `Notification`, `Address`, the queue and sender, the per-recipient rate limit |
| `src/notify/health.rs`, `expiry.rs` | Health notices (timer and refusal counter) and expiry notices from Event Grid, with the subscription allow-list |
| `src/notify/access.rs` | The access request email, the requester's own copy, when a reason or ticket may be quoted, and the per-person request limit |
| `src/notify/activity.rs` | Activity emails: a second audit observer for watched reads, deletes, purges, bulk changes and role use; the 4 an hour per item limit; the vault owners read |
| `src/notify/share.rs` | The share email to the recipient and the receipt to the sharer |
| `src/reason.rs` | Cleaning a reason and checking a ticket pattern |
| `src/password_policy.rs`, `src/common_passwords.txt` | The password policy and the 1,000 most common passwords |
| `src/description.rs`, `src/owner.rs`, `src/rotation.rs`, `src/reveal_limit.rs` | Rules for the `description`, `owner`, `notify`, `keyring-owners`, `rotation*` and `keyring-reveal` tags |
| `src/secret_types.rs` | Typed secrets: strict, bounded JSON reading and writing |
| `src/secret.rs` | `Secret`: prints `[redacted]`, zeroised on drop |
| `src/http.rs` | The one outbound HTTP client |
| `src/telemetry.rs` | Text or JSON log lines, the request log, the panic hook |
| `src/serve.rs` | Connection cap, header timeout, connection age |
| `src/x509.rs`, `src/pkcs12.rs` | Reading certificate details and checking a PFX before upload |
| `src/expiry.rs`, `src/age.rs`, `src/health.rs`, `src/dates.rs` | Expiry bands, age bands, vault health checks, date handling |
| `src/generator.rs` | Values from the operating system's secure random source |
| `src/config.rs` | Every setting (appendix A) |

## Browser scripts

Pages work without JavaScript. The scripts are optional extras, served from Keyring's own origin under `script-src 'self'`, with no inline code, no `eval` and no `innerHTML` (tested). Tests cap their size.

| Script | Lines (cap) | What it does | Limits |
|---|---|---|---|
| `static/app.js` | 449 (450) | Copy and clipboard clearing, hiding a revealed value after 30 seconds, the filter-as-you-type, the idle notice and keep-alive | Browsers only allow a clipboard clear while the tab has focus; a failed clear is tried again on return |
| `static/pins.js` | 198 (200) | Pinned and recently opened items in `localStorage` (`keyring.pins`) | Every stored entry is rebuilt from checked names and must be a local `/v/...` path or is dropped. Cleared on sign-out |
| `static/tags.js` | 130 (150) | Adds and removes tag rows, swaps a row's suggestion list | Builds rows with `createElement` and `textContent` only. Stops at 40 rows |
| `static/share.js` | 137 (under 160) | The share picker: asks Keyring's own `/v/{vault}/share/people` and lists the people and groups it returns | Calls only that same-origin address; writes results with `textContent` only; no storage. Sharing works without it by typing an exact address or object ID |

## Templates

Askama templates in `templates/`, compiled into the binary and escaped by default. Shared partials (`_ui.html`, `_access.html`, `_used_by.html`, `_pager.html`, `_field_error.html`) keep fields, tables and confirmation pages the same everywhere. The layout follows `design.md`: a top bar, a section navigation and one work area, with list, detail, form, decision and ledger page types. `templates/notify/` holds the email templates, each as plain text and HTML: the general notice, health, expiry, access request, activity and share notices.

## Search and pins

- **Search** (`/search`) matches a name, a tag as `name=value`, the description, or a content type, case-insensitive, across every vault the person can see. It makes list calls only, never a value read. Text is capped at 100 characters and results at 500. It reads through the per-session list cache.
- **Pins** live only in the browser. The server neither reads nor writes them.

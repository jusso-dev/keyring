# Appendices

## Appendix A: Settings

Every environment variable Keyring reads, from `src/config.rs`. A test in `tests/docs.rs` fails if a `KEYRING_*` setting the code reads is missing from this table. Every setting is checked at start: a value Keyring can't use stops it starting with a message naming the setting. Settings marked *Test only* make Keyring log a warning at start when set; leave them unset in real deployments.

::: compact
| Setting | Default | Meaning |
|---|---|---|
| `ENTRA_TENANT_ID` | Required | Directory (tenant) ID, a GUID. Lower-cased to match Entra's issuer |
| `ENTRA_CLIENT_ID` | Required | Application (client) ID, a GUID |
| `ENTRA_CLIENT_SECRET` | Required unless the managed identity is set | The client secret. Not with `KEYRING_FEDERATED_IDENTITY_CLIENT_ID`. An unresolved Key Vault reference is refused |
| `ENTRA_API_SCOPE` | `api://<client ID>/access_as_user` | Keyring's own API scope, requested at sign-in |
| `APP_BASE_URL` | Required | Public origin, `https://` except `http://localhost`. Scheme, host and port only. The only source of Keyring's own origin |
| `SESSION_SECRET` | Required | At least 32 random characters. Key for sealed cookies and `session_ref` |
| `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` | Set by the platform | The managed identity's local token service. Must be on `localhost`, `127.0.0.1` or `169.254.0.0/16` |
| `KEYRING_MANAGED_IDENTITY_CLIENT_ID` | None | Keyring's one user-assigned managed identity, for the federated credential (without `ENTRA_CLIENT_SECRET`), the audit sink and email |
| `KEYRING_FEDERATED_IDENTITY_CLIENT_ID` | None | Deprecated alias for the above, read for one release with a warning |
| `KEYRING_LISTEN` | `0.0.0.0:3000` | Address to listen on |
| `KEYRING_LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug` or `trace`. `off` and filter strings refused. Audit events are written at every level |
| `KEYRING_LOG_FORMAT` | `text` | `text` or `json` |
| `KEYRING_TRUSTED_PROXY_HOPS` | `0` | Proxies in front that add to `X-Forwarded-For`, 0 to 8. `1` on App Service and Container Apps (the templates set it) |
| `KEYRING_ALLOW_PURGE` | Off | `true` allows permanent deletes |
| `KEYRING_STALE_AFTER_DAYS` | `365` | Days before "Not changed in over ..." shows, 1 to 3650 |
| `KEYRING_STEP_UP_AUTH_CONTEXT` | Off | Conditional Access authentication context, `c1` to `c99`, before sensitive actions |
| `KEYRING_STEP_UP_MAX_AGE` | Off | Minutes since sign-in, 1 to 720, for those actions |
| `KEYRING_REQUIRE_REASON` | `off` | `off`, `reveal` or `all` |
| `KEYRING_REASON_TICKET_PATTERN` | None | Anchored regular expression a ticket must match. Needs `KEYRING_REQUIRE_REASON` |
| `KEYRING_PASSWORD_POLICY` | None | Rules such as `min=14,upper,lower,digit,symbol,max-repeat=3,common` |
| `KEYRING_REQUIRE_OWNER` | Off | `true` refuses saving an item without an `owner` tag on forms that show the field |
| `KEYRING_SHARING` | Off | `true` adds Share to a secret's page: a Key Vault Secrets User assignment on that secret, made as the sharer. Off, every sharing route is "not found". Needs the delegated Graph permissions `User.ReadBasic.All` and `GroupMember.Read.All` |
| `KEYRING_SHARE_MAX_DAYS` | `30` | The longest a share can last, 1 to 365 days |
| `KEYRING_AUDIT_INGESTION_ENDPOINT` | None | Audit sink: `https://<rule>.<region>.ingest.monitor.azure.com`. Needs the managed identity and `KEYRING_AUDIT_DCR_ID` |
| `KEYRING_AUDIT_DCR_ID` | None | The rule's immutable ID, `dcr-` and 32 hex digits |
| `KEYRING_AUDIT_STREAM` | `Custom-KeyringAudit_CL` | The rule's stream |
| `KEYRING_AUDIT_REQUIRED` | Off | `true` refuses reveals and private key downloads while the sink is degraded |
| `KEYRING_AUDIT_WORKSPACE_ID` | None | Workspace ARM ID holding `KeyringAudit_CL`, for the Keyring activity view (read as the person) |
| `KEYRING_NOTIFY_ACS_ENDPOINT` | None (email off) | `https://<resource>[.<geography>].communication.azure.com`. Needs the managed identity and `KEYRING_NOTIFY_SENDER`. Every other `KEYRING_NOTIFY_*` setting is refused without it |
| `KEYRING_NOTIFY_SENDER` | None | `DoNotReply@<verified domain>`, one plain address |
| `KEYRING_NOTIFY_TYPES` | None | Comma list of `expiry`, `access-requests`, `watched-reads`, `destructive`, `role-use`, `health` and `shares` (section 6.3) |
| `KEYRING_NOTIFY_ADMINS` | None | Up to 20 addresses for health and fallback notices |
| `KEYRING_NOTIFY_ALLOWED_DOMAINS` | Any domain | Every recipient, admins included, must be in one, exactly |
| `KEYRING_NOTIFY_RATE_PER_HOUR` | `20` | Emails an hour to one recipient for one type, 1 to 1000 |
| `KEYRING_NOTIFY_AUDIT_RECIPIENTS` | Off | `true` puts recipients' addresses on `notify.*` events |
| `KEYRING_NOTIFY_OWNER_ON_READ` | Off | With `watched-reads`: `true` sends watched-read emails to the item's `owner` as well as its `notify` addresses |
| `KEYRING_NOTIFY_BURST_THRESHOLD` | `20` | With `health`: refused or denied events from one person or IP in 15 minutes that count as a burst, 1 to 1000 |
| `KEYRING_CLIENT_SECRET_EXPIRES` | None | With `ENTRA_CLIENT_SECRET` only: its expiry, `YYYY-MM-DD`, for health emails |
| `KEYRING_EVENTGRID_AUDIENCE` | `api://<client ID>` | With `expiry`: the `aud` the webhook's token must have |
| `KEYRING_EVENTGRID_SUBSCRIPTIONS` | Any subscription, with a warning at start | With `expiry` only: subscription IDs (GUIDs) separated by commas, at most 50, any case, each kept once, whose Key Vaults may send expiry events. An event from another subscription refuses the delivery with `subscription_not_allowed`. An empty value is the same as unset. An entry that isn't a GUID, an empty entry or more than 50 stops Keyring starting. The templates set it from `eventGridSubscriptions` |
| `ENTRA_AUTHORITY_HOST` | `https://login.microsoftonline.com` | *Test only*: a mock identity provider |
| `KEYRING_TEST_MANAGEMENT_URL` | `https://management.azure.com` | *Test only*: a mock ARM |
| `KEYRING_TEST_KEYVAULT_URL` | None | *Test only*: a mock Key Vault |
| `KEYRING_TEST_LOGANALYTICS_URL` | `https://api.loganalytics.io` | *Test only*: a mock Log Analytics |
| `KEYRING_TEST_AUDIT_INGESTION_URL` | None | *Test only*: a mock ingestion endpoint |
| `KEYRING_TEST_NOTIFY_ACS_URL` | None | *Test only*: a mock ACS endpoint |
| `KEYRING_TEST_GRAPH_URL` | `https://graph.microsoft.com` | *Test only*: a mock Microsoft Graph |
:::

The HTTP client also reads `SSL_CERT_FILE`, `SSL_CERT_DIR`, `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY` (and lower-case forms) from the environment, as reqwest does.

## Appendix B: Audit actions and reason codes

From `Action::ALL` and `Refusal::ALL` in `src/audit/mod.rs`. `tests/docs.rs` already checks that `docs/deploy.md` lists each one.

::: compact
| Area | Actions |
|---|---|
| Secrets | `secret.reveal`, `secret.create`, `secret.set`, `secret.update`, `secret.enabled.set`, `secret.rollback`, `secret.delete`, `secret.recover`, `secret.purge`, `secret.import` (one per request and one per secret), `secret.bulk_update` (one per request and one per item), `secret.copy.read` (source), `secret.copy.write` (target), `secret.multi_env_set` (one per request, plus one `secret.create` or `secret.set` per vault written) |
| Certificates | `certificate.download_private_key`, `certificate.upload`, `certificate.create`, `certificate.pending.cancel`, `certificate.renewal.set`, `certificate.enabled.set`, `certificate.update`, `certificate.delete`, `certificate.recover`, `certificate.purge`, `certificate.bulk_update` |
| Keys | `key.create`, `key.rotate`, `key.rotation_policy.set`, `key.enabled.set`, `key.update`, `key.delete`, `key.recover`, `key.purge`, `key.bulk_update` |
| PIM and access | `role.activate`, `role.deactivate`, `access.request` (a person asked the vault's owners for a role; one per request whatever the outcome) |
| Sharing | `share.grant` (a refusal is `share.grant` with outcome `refused`), `share.revoke` |
| Sessions | `session.sign_in`, `session.sign_in_failed`, `session.sign_out`, `session.expired` |
| Requests | `request.refused` (refused before Keyring knew what it was for) |
| Email | `notify.sent`, `notify.failed`, `notify.webhook` |
:::

Outcomes: `success`, `denied` (Azure said 401 or 403), `refused` (Keyring's own check), `failed` (anything else).

::: compact
| Keyring's refusal codes | Meaning |
|---|---|
| `csrf` | Form token missing, forged or for another vault |
| `cross_site` | The request didn't come from Keyring's own pages |
| `typed_name_mismatch` | The typed name didn't match |
| `purge_disabled` | `KEYRING_ALLOW_PURGE` is off |
| `managed_item` | The item belongs to a certificate |
| `tag_limit` | A change would pass Key Vault's 15 tags |
| `no_session` | A form post with no live session |
| `invalid_request` | A bad name, field or form, or one too large |
| `stale_sign_in` | The sign-in reply didn't match one Keyring started |
| `id_token_rejected` | Entra's ID token failed Keyring's checks |
| `audit_unavailable` | `KEYRING_AUDIT_REQUIRED` is on and the sink is degraded |
| `step_up_required` | A stronger or fresher sign-in is needed |
| `step_up_not_met` | The step-up sign-in came back without it |
| `reason_required` | A reason or ticket was needed and not given or not valid |
| `password_policy` | A typed or imported password missed the policy |
| `owner_required` | An item would be saved without an owner |
| `reveal_limited` | The item's `keyring-reveal` tag refused a reveal, copy, copy to another vault or private key download, or a bulk change named the tag |
| `rate_limited` | On `access.request`: the same person asked for the same role on the same vault within the hour, or has 10 live requests; nothing sent |
| `share_to_self` | On `share.grant`: the recipient is the sharer |
| `share_date` | On `share.grant`: the end date is in the past or beyond `KEYRING_SHARE_MAX_DAYS` |
| `share_principal` | On `share.grant`: Graph didn't return the recipient as a user or security group in the tenant |
| `share_not_allowed` | On `share.grant`: the secret has a reveal limit, or the vault uses access policies |
:::

Other `reason_code` values: Azure's error code (such as `ForbiddenByRbac`); `timeout`, `server_error`, `cancelled`, `network`, `unreadable`, `sign_in_again`, `consent_needed`, `entra_unreachable`, or Entra's OAuth error code; `partly_written`, `none_written`, `partly_changed`, `none_changed` and `no_change` on imports and bulk changes; `PendingApproval` on a PIM request waiting for approval. On `access.request`: `queue_full`, `recipient_rate_limited` or `no_recipients` with outcome `failed`. On `share.grant` and `share.revoke`: `pim_refused` with outcome `failed` when a PIM setting refused the request. On `notify.sent` and `notify.failed`: `status_unknown`, `delivery_failed`, `delivery_canceled`, `rejected`, `gave_up`, `gave_up_maybe_sent`, `queue_full`, `shutdown`. On `notify.webhook`: `queued`, `repeat`, `no_recipients`, `validation`, `queue_full`, `recipient_rate_limited`, `rate_limited`, `not_json`, `too_large`, `not_events`, `too_many_events`, `bad_validation`, `bad_event`, `bad_topic`, `subscription_not_allowed` (the vault's subscription isn't in `KEYRING_EVENTGRID_SUBSCRIPTIONS`), `bad_recipients`, and the token codes `token_missing`, `token_malformed`, `token_algorithm`, `token_signature`, `token_issuer`, `token_audience`, `token_tenant`, `token_expired`, `token_caller`, `token_role`, `token_not_app_only`.

## Appendix C: Glossary

| Term | Meaning |
|---|---|
| ACS | Azure Communication Services, used to send email |
| `acrs` | The authentication context class references claim in an Entra token, used for step-up |
| ARM | Azure Resource Manager, the control plane API |
| ASIM | Advanced Security Information Model, Sentinel's normalised schemas |
| Data collection rule (DCR) | Azure Monitor's definition of a stream into a Log Analytics table |
| Federated credential | An Entra trust that lets a managed identity's token stand in for an app's client secret |
| KQL | Kusto Query Language, used by Log Analytics and Resource Graph |
| Managed identity | An Azure-managed service principal with no secret to handle |
| Microsoft Graph | Microsoft's API for directory data such as users and groups. Keyring calls it only for sharing, as the person |
| OBO | The OAuth 2.0 on-behalf-of flow: swapping a person's token for one for a downstream API, still as that person |
| OIDC | OpenID Connect, the sign-in protocol |
| PIM | Entra Privileged Identity Management, which turns eligible roles on for a time |
| PKCE | Proof Key for Code Exchange, which binds an authorisation code to the sign-in that asked for it |
| RBAC | Azure role-based access control |
| Reveal limit | The `keyring-reveal` tag: `copy-only` or `none`, checked by Keyring before it shows or copies a value |
| Share | A Key Vault Secrets User role assignment on one secret, made through Keyring as the person sharing, with an end date where PIM is licensed |
| Step-up | Asking for a stronger or more recent sign-in before a sensitive action |
| STRIDE | Spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege |
| Typed secret | A secret Keyring stores as JSON with its own content type (Login, Database, API key, SSH key) |

## Appendix D: Third-party crates and licences

Direct dependencies, from `Cargo.toml` and `Cargo.lock`. `deny.toml` allows only permissive licences (MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, BSL-1.0, ISC, Unicode-3.0, Unlicense, Zlib, CDLA-Permissive-2.0), crates from crates.io only, and bans `openssl`, `openssl-sys`, `native-tls`, `aws-lc-rs` and `aws-lc-sys`.

::: compact
| Crate | Version | Licence | Use |
|---|---|---|---|
| `askama` | 0.16.1 | MIT OR Apache-2.0 | Templates compiled into the binary |
| `axum` | 0.8.9 | MIT | Web framework |
| `base64` | 0.23.1 | MIT OR Apache-2.0 | Encoding |
| `flate2` | 1.1.11 | MIT OR Apache-2.0 | Gzip for the audit sink (pure Rust backend) |
| `hyper`, `hyper-util` | 1.12.0, 0.1.21 | MIT | HTTP server |
| `openidconnect` | 4.1.0 | MIT | OIDC sign-in |
| `regex` | 1.13.1 | MIT OR Apache-2.0 | Ticket patterns and character classes (linear time) |
| `reqwest` | 0.13.5 | MIT OR Apache-2.0 | Outbound HTTP |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | Crypto for rustls, AES-GCM, HKDF, HMAC, random |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | MIT OR Apache-2.0 | JSON |
| `tokio` | 1.54.1 | MIT | Async runtime |
| `tower`, `tower-http` | 0.5.3, 0.7.1 | MIT | Middleware, panic catching |
| `tracing`, `tracing-subscriber` | 0.1.44, 0.3.23 | MIT | Logging |
| `x509-cert` | 0.3.0 | Apache-2.0 OR MIT | Certificate parsing |
| `zeroize` | 1.9.1 | Apache-2.0 OR MIT | Clearing secrets from memory |
| `http-body-util`, `rsa`, `url` | dev only | MIT OR Apache-2.0, MIT | Tests |
:::

`Cargo.lock` holds 300 packages including build and test dependencies, every one under the allow-list. Accepted advisories: RUSTSEC-2023-0071 (`rsa` via `openidconnect`; Keyring does no RSA private-key operation; #41) and RUSTSEC-2026-0543 (`chrono` unmaintained notice; #271). CI produces a CycloneDX SBOM for the crates and one for the image.

## Appendix E: Azure resource names

From the templates. `<name>` is the `name` parameter; examples use `keyring`.

| Resource | Name | Template |
|---|---|---|
| User-assigned managed identity | `<name>-id` | `config-vault.bicep` |
| Config vault | `configVaultName` parameter (globally unique) | `config-vault.bicep` |
| Config vault secrets | `entra-client-secret`, `session-secret` | Set by hand after deployment |
| App Service plan, web app | `<name>-plan`, `<name>` | `app-service/main.bicep` |
| Log Analytics workspace, Container Apps environment, app | `<name>-logs`, `<name>-env`, `<name>` | `container-apps/main.bicep` |
| Private endpoints | `<name>-pe`, `<name>-inbound-pe`, `<vault>-pe` | `private-endpoint.bicep` |
| Audit table, stream | `KeyringAudit_CL`, `Custom-KeyringAudit_CL` | `audit-sink.bicep` |
| Data collection rule | `<name>-audit` | `audit-sink.bicep` |
| Email Communication Service, Communication Services | `<name>-email`, `<name>-acs` | `notify.bicep` |
| Custom role | Keyring email sender (`<name>`) | `notify.bicep` |
| Event Grid system topic, subscription | `<vault>-events` (or an existing topic), `expiry-to-keyring` or `expiry-to-action-group` | `expiry-events.bicep` |
| Sentinel parsers | `vimAuditEventKeyring`, `ASimAuditEventKeyring` | `sentinel/main.bicep` |

## Appendix F: Screens

| Screen | Address | Notes |
|---|---|---|
| Sign in, signed out | `/auth/sign-in`, `/auth/signed-out` | No session needed |
| Home | `/` | Pinned and recently opened |
| Vaults | `/vaults` | Every vault the person can see, with environment badges |
| Environments | `/environments`, `/environments.csv` | Cross-environment secret parity matrix, drift notes, missing-secret actions and CSV export (never reads values) |
| Set across environments | `/environments/set` | Create or update one secret across up to 8 environment vaults with distinct per-environment values and duplicate-value guard |
| Secrets list, detail, versions | `/v/{vault}/secrets`, `/v/{vault}/secrets/{name}` | Reveal (or Copy only, under a reveal limit), copy, edit, reveal limit, set value, roll back, disable, delete, copy to another vault, Share |
| Create or import secrets | `/v/{vault}/secrets/-/new`, import from the list | Typed secrets; preview before import |
| Certificates list and detail | `/v/{vault}/certificates`, `/v/{vault}/certificates/{name}` | Create, upload with preview, renewal, downloads, Edit details |
| Keys list and detail | `/v/{vault}/keys`, `/v/{vault}/keys/{name}` | Create, rotate, rotation policy, Edit details |
| Deleted items | Under each list | Recover, purge when allowed |
| Bulk change review and results | `/v/{vault}/{kind}/-/bulk` | No bulk delete |
| Access | `/v/{vault}/access` | And an Access section on every item |
| Access review | `/v/{vault}/access/review`, `/v/{vault}/access/review.csv` | From the Access page. Every item with owner, notify, value age, who used it in 90 days, who has access and rotation; gaps marked "Not known" |
| My access, Activate | `/v/{vault}/my-access` | PIM, and Request for roles the person neither holds nor is eligible for |
| Request access | `/v/{vault}/my-access/request` | With `access-requests` on. Role, scope, reason and optional ticket; the same answer page whatever happened |
| Not shown in Keyring | Any reveal, copy or private key download | The fixed 403 page for a reveal limit |
| Share a secret, revoke a share | `/v/{vault}/secrets/{name}/share`, `/v/{vault}/secrets/{name}/share/revoke` | With `KEYRING_SHARING=true`. The picker, the end date and the reason; Revoke after a typed name, for Keyring's own shares only. A Shared with section on the secret's page |
| My shares | `/v/{vault}/my-access/shares` | With `KEYRING_SHARING=true`. Secrets shared with the person and shares they made |
| Audit | `/v/{vault}/audit`, `/v/{vault}/audit/keyring` | Key Vault's log, Keyring activity |
| Audit across vaults | `/audit` | Five fixed reports |
| Expiry, age | `/expiry`, `/expiry/age` | With CSV |
| Vault health | `/vault-health` | With CSV |
| Search | `/search` | Across vaults |
| Generator | `/generator` | Values shown once |
| Error pages | Any | Plain English, the role to ask for, PIM offer where eligible |

Screenshots of most screens are in `docs/images/screenshots/` and the README.

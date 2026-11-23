# Changelog

All notable changes to Keyring are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are tagged `vX.Y.Z`, and each tag's container image is built by `.github/workflows/release.yml`. The tag must point at a commit on `main` whose CI passed, match the version in `Cargo.toml`, and have a matching `## [X.Y.Z]` heading in this file. To see which commit an image was built from, inspect its `org.opencontainers.image.revision` label.

## [Unreleased]

### Security
- Sign-in no longer uses the `openidconnect` crate. Discovery, the authorise URL, the code exchange and the ID token checks are Keyring's own code on `reqwest` and `ring` (`src/auth/oidc.rs`, `src/auth/jwt.rs`): RS256 only with a `kid` and no `crit`, the issuer matched exactly, the client ID in `aud` (and `azp` when there are several), `exp`, `nbf` and `iat` with five minutes' skew, and the nonce compared in constant time. Event Grid webhook tokens are checked against the same keys with `ring`. This takes `rsa` 0.9 and `chrono` out of the build, so the RUSTSEC-2023-0071 (#41) and RUSTSEC-2026-0543 (#271) exceptions are gone from `deny.toml` and `.cargo/audit.toml`. `Cargo.lock` drops from 300 packages to 185.
- `url` 2.5.8 to 2.5.9 for RUSTSEC-2026-0592 (stack overflow in `Url::origin()` on nested `blob:` URLs). Keyring never calls `origin()`, but the advisory fails `cargo audit`.

### Fixed
- The deleted-key page failed on a real vault: "Get Deleted Key" sends the key's `kid` inside `key`, not at the top as the list does, so Keyring couldn't read it. Both shapes are now read (#170).
- Secret values in non-ASCII text were refused below Key Vault's real limit. Key Vault allows 25,600 characters counted in UTF-16 code units, not 25 KB of UTF-8, and the create, edit, import, multi-environment and typed-secret checks now count the same way (#170).

### Added
- **Defender alerts** page (`/defender`, `/defender.csv`): Microsoft Defender for Key Vault's plan on each subscription, and its alerts on Key Vaults from the last 90 days, read from Resource Graph's `securityresources` table as the signed-in person. Alert text is cleaned and escaped, links are kept only when they point at the Azure portal, and an alert read that fails says so rather than showing none. Home gets a Defender alerts tile and the most urgent open alerts; the executive report gets a "Defender for Key Vault on" control, risk points per open alert, remediation actions and a Defender row in its CSV.
- Three vault health checks: **Expiring soon** (an enabled item expired or expiring within `KEYRING_EXPIRY_WARN_DAYS`, default 30), **Not cycled** (no new value in more than `KEYRING_STALE_AFTER_DAYS`) and **Defender for Key Vault** (plan off, or open alerts on the vault). Each vault's three lists are now read once for every check that needs them.
- `KEYRING_EXPIRY_WARN_DAYS` (1 to 365, default 30), and `expiryWarnDays` in both Bicep templates. Home's expiry tile and the executive report's expiring count and action follow it.
- Twelve more real-vault checklist rows in `tests/real_vault.rs` (21 in all): typed content types, value and description limits, line breaks, tag round trips, tags replaced as a whole, certificate and key Edit details, certificate tags on backing items, `created` on list calls, `managed` backing items and rotation tags. All 21 run on 22-11-2026 against a throwaway vault, and the mock Key Vault now matches every answer (#170).
- Microsoft Sentinel Content Hub V3 solution package under `Solutions/Keyring/` (ASIM parsers, 8 analytic rule YAMLs, 6 hunting query YAMLs, workbook, `mainTemplate.json` and `createUiDefinition.json`), one-click Deploy to Azure ARM template (`infra/sentinel/azuredeploy.json`), and packaging/validation scripts in `tools/sentinel/` (#301).

### Changed
- Removed `chrono` from test dev-dependencies in favour of `keyring::dates` and standard library time helpers (#271).
- Silenced false-positive `secure-secrets-in-params` Bicep linter warning on the non-secret `passwordPolicy` parameter in `infra/app-service/main.bicep` and `infra/container-apps/main.bicep`.
- Updated `.env.example`, `SECURITY.md`, `README.md`, `docs/sentinel.md` and `docs/real-vault-checklist.md` to reflect `v1.0.0`, real-tenant test runs through 19-11-2026, and all production environment variables.
- Bumped `taiki-e/install-action` from `2.90.3` to `2.90.6` in CI (#290).

## [1.0.0] - 2026-11-21

Initial v1.0.0 release of Keyring, a self-hosted, zero-storage secrets console for Azure Key Vault built in Rust (Axum and Askama) that signs people in with Entra ID and makes every Azure call on their behalf.

### Added

#### Authentication and vault discovery
- Entra ID OpenID Connect sign-in with on-behalf-of (OBO) token exchange for Key Vault, Azure Resource Manager, Log Analytics and (when sharing is enabled) Microsoft Graph, acting strictly as the signed-in user with no stored credentials.
- Support for proving app identity via either a client secret (`ENTRA_CLIENT_SECRET`) or a user-assigned managed identity federated credential (`KEYRING_MANAGED_IDENTITY_CLIENT_ID`).
- Automatic MFA claims challenge handling when OBO returns AADSTS50076, 50078, 50079 or 50158, preventing sign-in loops (#295).
- Multi-subscription vault discovery via Azure Resource Graph, with vault-scoped URLs (`/v/{vault}/...`) for shareable links and multi-tab use (#188).

#### Secrets, certificates and keys
- Full secret lifecycle: list, reveal (hidden after 30 seconds with clipboard clearing), create, edit, set new value, view versions, roll back, enable/disable, set expiry and tags, delete, recover and opt-in purge.
- Multi-field typed secrets (`application/vnd.keyring.<type>+json;v=1`): Password, Login, Database (with SQL Server and PostgreSQL connection string builders), API key and SSH private key (#246).
- Certificate management: list, upload `.pfx` or `.pem`, download `.cer` or `.pfx` (when policy allows), create self-signed or vault-issuer certificates, cancel pending requests, edit details and configure near-expiry renewal or contact notifications.
- Key management: list, create, rotate, enable/disable, edit details and configure rotation policies; raw private key material is never exported.
- Password, GUID and API key generator.
- Cross-vault search by name, tag, description, owner or content type without reading secret values (#227).
- Reserved well-known tags (`description`, `owner`, `notify`, `keyring-reveal`, `rotation*` and vault `keyring-owners`), tag rows with vault-sourced `<datalist>` suggestions, **Owned by me** filtering (#253, #254, #255, #267, #277) and browser-local pinned and recently opened items (#240).
- Bulk updates (tags, description, owner, notify list, enabled state and expiry) across up to 100 selected items with review and per-item results (#244).
- Secret import from `.env` or CSV files (up to 500 rows / 1 MB) with name-only preview and zeroised session storage (#234), and cross-vault secret copy without displaying the value (#247).

#### Multi-environment collaboration, dashboard and executive reporting
- Multi-environment comparison and value collaboration across `dev`, `test`, `staging` and `prod` vaults without reading values, with parity CSV export and duplicate-value protection (#298).
- Enterprise console UI with single-line data tables, pill filter bars, organisation-wide Home dashboard (KPI cards, pure-SVG charts and vault risk watchlist), custom branding and Retina assets (#293, #296, #297, #298, #299).
- White-label executive report builder (`/reports/executive`) with HTML/PDF, CSV and JSON exports (#298).

#### Access governance and Keyring controls
- Optional Conditional Access step-up (`KEYRING_STEP_UP_AUTH_CONTEXT`) and sign-in freshness (`KEYRING_STEP_UP_MAX_AGE`) before sensitive actions (#235).
- Optional reason and ticket reference gate (`KEYRING_REQUIRE_REASON`, `KEYRING_REASON_TICKET_PATTERN`) for reveals or all changes (#242).
- Optional server-side password policy (`KEYRING_PASSWORD_POLICY`) including a built-in common-password check (#275), and optional mandatory owner policy (`KEYRING_REQUIRE_OWNER`) (#277).
- Per-item reveal limits via the `keyring-reveal` tag (`copy-only` or `none`), enforced server-side across all read, copy, download, import and bulk paths (#285).
- Privileged Identity Management (PIM) self-activation directly from 403 refusal pages and a **My access** view showing active, eligible, upcoming and pending roles (#245, #249).
- Email-based **Request access** workflow to vault owners when PIM is unavailable (#282).
- Opt-in per-secret sharing (`KEYRING_SHARING`, `KEYRING_SHARE_MAX_DAYS`) creating time-bound PIM or Azure RBAC Key Vault Secrets User assignments as the sharer, with Microsoft Graph person/group lookup and revocation (#289).
- Role-based permission hints on action buttons read from ARM permissions (#238).

#### Audit, compliance, lifecycle and Microsoft Sentinel
- Per-vault and cross-vault Key Vault diagnostic log views (`AZKVAuditLogs` and `AzureDiagnostics`) with accurate HTTP outcome classification and CSV export (#229, #265).
- 30-day **Used by** impact panel on item pages and change forms showing callers from Key Vault logs with explicit coverage caveats (#236, #264).
- Structured Keyring audit events (schema v1) for every action, refusal, denial and failure (#232), with optional Log Analytics Logs Ingestion API sink (`KeyringAudit_CL`), fail-closed reveal gating (`KEYRING_AUDIT_REQUIRED`) (#237) and a **Keyring activity** tab (#243, #297).
- Microsoft Sentinel content (`infra/sentinel`): ASIM Audit Event parser (`vimAuditEventKeyring`), parameterised analytic rules (disabled by default), hunting queries and workbook (#243, #289).
- Per-vault **Access** view and quarterly **Access review** page and CSV combining owners, descriptions, expiry, value age, 90-day usage, effective access and rotation status (#233, #279).
- Cross-vault **Expiry dashboard**, **Age view** (`/expiry/age`, `KEYRING_STALE_AFTER_DAYS`), rotation status display from tags (#230, #239) and **Vault health** compliance checks (#228).

#### Notifications and alerts
- Managed-identity email delivery through Azure Communication Services (`KEYRING_NOTIFY_*`) with repeatability headers, rate limiting and `/healthz/notify` (#266).
- Event Grid expiry webhook (`POST /hooks/eventgrid`) with Entra token verification, deduplication and subscription allow-list (`KEYRING_EVENTGRID_SUBSCRIPTIONS`) (#274, #280).
- Activity emails for watched-item reads, destructive/bulk actions and PIM role use (#281), access request and share emails (#282, #289), and admin health notices for audit sink degradation, refusal bursts and client secret expiry (#273).
- Azure Monitor access alert templates (`infra/alerts`) for watched reads, purges and repeated refusals (#226).

### Security
- Static musl Rust binary packaged in a distroless non-root container image (`65532:65532`, no shell, read-only root filesystem, all Linux capabilities dropped).
- `#![forbid(unsafe_code)]`, strict Content-Security-Policy, CSRF form tokens bound to the active vault, Origin validation, bounded server connections and timeouts, and in-memory session expiry sweeping.
- Supply-chain enforcement via `cargo-deny` (including explicit bans on `aws-lc-rs` and `aws-lc-sys`), `cargo-audit`, pinned CI tools and base image digests, CycloneDX SBOMs for both crates and base image, and GitHub build provenance attestations.

### Deployment
- Bicep templates for Azure Container Apps (`infra/container-apps`, supporting external and internal VNet ingress with private DNS) and Azure App Service (`infra/app-service`), plus reusable modules for Keyring's config vault, private endpoints, audit sink, ACS notifications and expiry events (`infra/modules`, `infra/alerts`, `infra/sentinel`).
- Health endpoints `/healthz`, `/healthz/audit` and `/healthz/notify`, and OCI image labels (`org.opencontainers.image.version`, `org.opencontainers.image.revision`).

### Documentation
- Docusaurus documentation site deployed to GitHub Pages (`website/`, kept separate from the Rust product and container image) (#288).
- Comprehensive README with capability matrix, machine-access guidance and full environment variable reference (#283).
- Walkthrough guides (`docs/guides/`), administrator SOPs, developer guide, formal solution design document, security architecture and controls, deployment guide, enterprise comparison and migration guide (including PDF and Word DOCX packs), architecture and Sentinel diagrams, and a real-tenant verification checklist (#284, #287, #298).

[Unreleased]: https://github.com/jusso-dev/keyring/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jusso-dev/keyring/releases/tag/v1.0.0

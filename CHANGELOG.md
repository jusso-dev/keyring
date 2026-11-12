# Changelog

Notable changes to Keyring. Keyring has no releases yet, so everything is under Unreleased. Each entry names the pull request it came from. To see which commit an image was built from, read its `org.opencontainers.image.revision` label.

Releases are tagged `vX.Y.Z`, and each tag's image is built by `.github/workflows/release.yml`. The tag must match the version in `Cargo.toml`, and this file must have a `## X.Y.Z` heading for it.

## Unreleased

- **Managed identity credential**: Keyring can prove itself to Entra with the app's managed identity (`KEYRING_FEDERATED_IDENTITY_CLIENT_ID`) instead of a client secret, so there is no secret to rotate. `ENTRA_CLIENT_SECRET` is now optional, and the Bicep templates have `useFederatedCredential`. The app registration must stay delegated-only (see the threat model).

### Review fixes, November 2026

A code review on 10-11-2026 filed issues #73 to #173 (index #174). These are the fixes so far, one line per area. Each issue says what was wrong.

- **Sign-in and sessions** (#181): the callback checks `state` before it trusts an `error=` reply, sealed cookies are time-limited on the server, sign-in metadata is fetched once and kept as a fallback, Entra errors are sorted in one place, the `.env.example` placeholder is refused as `SESSION_SECRET`, and expired sessions are swept every minute. #73, #74, #76, #77, #78, #80, #81, #82, #83, #84.
- **Tokens** (#181): concurrent requests share one refresh and one on-behalf-of exchange per resource, and share a failure too. #75.
- **Server** (#181): a request log line per request, a warning at start for any test-only override, at most 512 connections each closed after 5 minutes, unwinding panics that give one 500 page instead of ending every session, and the HTTP client built before binding. #79, #85, #86, #87, #88.
- **Forms** (#179, #181): every changing form is bound to the vault it was opened for, and the form token is checked before Azure is called. #89, #108.
- **Secrets** (#179): multi-line values are kept as typed, rollback keeps the enabled state and expiry, edits go to the version that was shown, tags round-trip, start and expiry times keep their minutes, the delete warning gives the vault's real retention period, and purge isn't offered on purge-protected vaults. #90, #91, #92, #93, #100, #101, #104, #105, #106, #107, #111, #113.
- **Reveal and copy** (#177): Keyring tries to clear the clipboard and retries when you come back to the tab, the auto-hide holds in background tabs, hidden buttons stay hidden, pages reflow at 320 pixels, and the idle sign-out gives a warning. #94, #95, #134, #135, #136, #140, #141.
- **Expiry, audit and errors** (#178): the expiry dashboard has time limits per vault and overall and lists what it couldn't read, the audit view says which workspaces it left out, a 409 for a soft-deleted name says so, and static files are versioned and cached for a year. #96, #97, #98, #102, #103, #109, #110, #112.
- **Certificates** (#180): the issuer is a select of Self and the vault's own issuers, pending requests can be cancelled, self-signed creates show "Being created", uploads show the leaf certificate and say when a name exists, PEM keys must be PKCS #8 and match, BER PFX files can be uploaded, and certificates can be enabled and disabled. #114, #116, #117, #118, #119, #120, #123, #125, #127, #128, #130, #131, #132.
- **Keys** (#180): the rotation policy form keeps what it can't show and Key Vault's own durations, checks Key Vault's limits, and reads the default policy as none. Managed keys are refused on the server, and keys can be enabled and disabled. #115, #121, #122, #126, #129.
- **Azure's message** (#180): a 400 on a write shows Key Vault's own reason under the form, cut to 500 characters and never logged. #124.
- **Deployment, CI and docs** (#176): internal Container Apps ingress with private DNS, App Service logs to a workspace, the alerts topic in the vault's region, image labels, a CI check that docs only name `src/` files that exist, and many doc corrections. #151, #153, #154, #155, #157, #158, #159, #160, #161, #163, #164, #165, #166, #167, #168.
- **Docs and tests** (#182): the architecture, deploy and troubleshooting pages describe the fixes above, the README says which certificate issuers Keyring supports, `docs/real-vault-checklist.md` lists what the first real-tenant run must confirm, and a test checks the numbers in the docs against the code. #119, #124, #169, #170, #171.
- **Shared code** (#183): one form token check, field errors and name check for every form; delete, recover and purge written once for secrets, certificates and keys; fixed pages moved under `/-/` (old addresses redirect); the deleted lists are paged; dead code and stale comments removed. #99, #133, #172, #173.
- **Templates and accessibility** (#184): shared partials for fields, tables and confirm pages, row actions kept inside table cells, wide tables reachable by keyboard, focus moved to the error summary or message, and disable asks first. #137, #138, #139, #142, #143, #144, #145, #146, #147, #148, #149, #150.
- **Deleted pages** (#185): secrets use the shared deleted list and deleted page too, which keep a secret's content type and now give every kind the vault's real retention period. #150, #172.
- **Visibility** (#186): `unreachable_pub` is on, so items only the crate uses are `pub(crate)` or `pub(super)` and the compiler reports them when they fall out of use. That found and removed a few more unused items: two never-read Azure fields, an unused key name helper, and two checks used only by their own tests. #173.
- **First real-vault run** (this change): Key Vault keeps a version's start and expiry dates when sent `null`, so the secret edit form now refuses a removed date and says to set a new value instead of reporting a change that didn't happen. An HSM key on a Standard vault is refused with 403 `HardwareKeysNotSupported`, not 400, so Keyring now matches that code. The mocks follow both, and `docs/real-vault-checklist.md` records the results. #129, #170.

### Security

- `deny.toml` also bans `aws-lc-rs` and `aws-lc-sys`, so a dependency change can't quietly swap rustls's ring provider for aws-lc.
- CI installs its tools only from pinned, checksummed binaries (no fallback download), pins the Bicep CLI, and pins the Dockerfile build frontend by digest.

### Deployment

- Container Apps with `ingress = 'internal'` is reachable from the VNet. The template outputs `defaultDomain` and `staticIp` and can create the private DNS zone (`privateDnsVnetId`).
- Both templates take `apiScope` and `logLevel`.
- App Service can send Keyring's output to Log Analytics (`logAnalyticsWorkspaceId`), and otherwise keeps a 7 day local log.
- The alerts template puts the system topic in the vault's region and can use a topic the vault already has (`existingSystemTopicName`).
- Images carry `org.opencontainers.image.version` and `org.opencontainers.image.revision` labels.

### Documentation

- App registration: the Log Analytics API permission and the sign-out redirect URI.
- Role table: the smallest role first, and which roles can read secret values.
- Rotating the client secret and `SESSION_SECRET`, logs on each platform, proxies and private CAs, and more troubleshooting rows.

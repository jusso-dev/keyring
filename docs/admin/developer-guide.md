# Keyring developer guide

This guide explains how the Keyring repository is laid out, how to build and test it locally, how Keyring's automated security and documentation checks work, how to add a new route, setting or audit action, how to run the local end-to-end demo and screenshot suite, and how to build the PDF and Word documentation pack.

Architecture and threat details are in [docs/architecture.md](../architecture.md) and [docs/Keyring-Design-Document.pdf](../Keyring-Design-Document.pdf). Deployment is in [docs/deploy.md](../deploy.md) and day-to-day operations are in [administrator SOPs](admin-sops.md).

## Document control

| Item | Value |
|---|---|
| Version | 1.0 |
| Date | 21-11-2026 |
| Owner | Keyring maintainer |
| Audience | Developers changing Keyring Rust code, templates, Bicep templates or documentation |
| Source | `docs/admin/developer-guide.md` in `jusso-dev/keyring`; rebuilt with `python3 tools/docs/build-admin-docs.py` |

## Contents

1. [Repository layout](#1-repository-layout)
2. [Toolchain and local checks](#2-toolchain-and-local-checks)
3. [Architecture and invariants](#3-architecture-and-invariants)
4. [Adding a route, audit action or setting](#4-adding-a-route-audit-action-or-setting)
5. [Running the local end-to-end demo and Playwright screenshots](#5-running-the-local-end-to-end-demo-and-playwright-screenshots)
6. [Bicep templates and container build](#6-bicep-templates-and-container-build)
7. [Continuous integration and release provenance](#7-continuous-integration-and-release-provenance)
8. [Building the PDF and Word documentation suite](#8-building-the-pdf-and-word-documentation-suite)

---

## 1. Repository layout

| Path | Contents |
|---|---|
| `src/lib.rs`, `src/main.rs`, `src/serve.rs` | Application wiring, `AppState`, graceful HTTP/1 server with connection cap, header read timeout and connection age limits |
| `src/config.rs` | Startup configuration parsed from environment variables; fails closed on invalid values or unresolved Key Vault references |
| `src/auth/` | Entra ID OIDC sign-in with PKCE, state and nonce (`oidc.rs`), in-memory sessions (`session.rs`), AES-256-GCM sealed cookies (`crypto.rs`, `cookies.rs`), federated managed identity token client (`assertion.rs`), Conditional Access step-up (`step_up.rs`), and Event Grid JWT verification (`eventgrid.rs`) |
| `src/azure/` | Plain REST clients over `reqwest` + `rustls` using the signed-in person's OBO token: `token.rs`, `client.rs`, `vaults.rs`, `secrets.rs`, `certs.rs`, `keys.rs`, `audit.rs`, `audit_across.rs`, `access.rs`, `pim.rs`, `share.rs`, `graph.rs`, `fanout.rs` |
| `src/audit/` | Structured `AuditEvent` schema v1 (`mod.rs`) and async Logs Ingestion API batch sink (`sink.rs`) |
| `src/notify/` | Azure Communication Services email sender (`sender.rs`), expiry webhook handler (`expiry.rs`), health notices (`health.rs`), access requests (`access.rs`), activity emails (`activity.rs`) and share emails (`share.rs`) |
| `src/environments.rs` | Pure multi-environment grouping, promotion ordering, parity matrix, CSV export and in-memory duplicate-value detection |
| `src/routes/` | Axum handlers and middleware: `secrets/`, `certs/`, `keys/`, `environments.rs`, `vaults.rs`, `expiry.rs`, `age.rs`, `vault_health.rs`, `search.rs`, `audit.rs`, `access.rs`, `access_review.rs`, `pim.rs`, `share.rs`, `reason.rs`, `step_up.rs`, `origin.rs`, `headers.rs`, `health.rs` |
| `src/secret.rs`, `src/secret_types.rs`, `src/password_policy.rs`, `src/reveal_limit.rs`, `src/owner.rs`, `src/description.rs` | Zeroising `Secret` wrapper, structured secret JSON codec, password complexity checker, reveal limit rules and well-known tag helpers |
| `templates/` | Askama HTML templates compiled directly into the Rust binary (auto-escaped) |
| `static/` | Hand-written CSS (`style.css`) following `design.md` tokens, plus small browser scripts (`app.js`, `behaviors.js`, `pins.js`, `tags.js`, `share.js`); no npm or bundler in the product |
| `tests/` | End-to-end integration tests running against full mock Azure servers in `tests/support/`, plus `tests/screenshots.rs` (local demo server) and `tests/js/*.test.mjs` (Node script tests) |
| `infra/` | Bicep templates for App Service, Container Apps, private networking, Event Grid expiry alerts, Azure Monitor access alerts and Microsoft Sentinel content |
| `docs/` | Markdown sources, draw.io diagrams, walkthrough guides, admin SOPs, design chapters, security pack, enterprise comparison guide, and generated PDF and Word editions |
| `tools/docs/` | Shared Pandoc + WeasyPrint + Word document builders (`build-doc.sh`, `build-admin-docs.py`, `build-guides.py`) |
| `website/` | Docusaurus documentation site published to GitHub Pages (never included in the Rust binary or Docker image) |

---

## 2. Toolchain and local checks

Install Rust via [rustup](https://rustup.rs). `rust-toolchain.toml` pins the exact Rust channel (`1.99` / `1.100`) and edition `2024`.

Run every check CI runs before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
node --test tests/js/*.test.mjs
cargo deny --locked check
cargo audit --deny warnings
```

The entire test suite runs offline against mock Entra ID, Resource Graph, ARM, Key Vault, Log Analytics, Logs Ingestion, Microsoft Graph, ACS and Event Grid servers in `tests/support/`. No Azure subscription is needed.

To run one integration test file quickly while iterating:

```sh
cargo test --test environments
cargo test --test audit_events
cargo test --test accessibility
cargo test --test no_secrets_in_logs
cargo test --test docs
```

---

## 3. Architecture and invariants

Keyring enforces its core rules in automated tests so regressions fail CI immediately:

| Invariant | Enforced by |
|---|---|
| Zero `unsafe` Rust code | `#![forbid(unsafe_code)]` in `Cargo.toml` `[lints.rust]` |
| Every POST route writes an audit event (or has a documented exemption) | `tests/audit_events.rs` parses `src/routes/mod.rs` and posts forged CSRF tokens to every audited route, asserting one `refused` event and zero Key Vault calls |
| Secret values, tokens, private keys, query strings and Azure error messages never appear in logs | `tests/no_secrets_in_logs.rs`, `tests/secrets_reveal_log.rs`, `tests/reason_log.rs` capture every log line at `TRACE` in text and JSON |
| No key export, decrypt, sign or unwrap calls exist | `tests/keys.rs` checks every route and client call |
| WCAG AA accessibility on rendered HTML | `tests/accessibility.rs` verifies one `h1` per page, labels for every control, valid `aria-describedby` / `aria-labelledby`, named table captions, `autocapitalize="off"` on identifiers, and focused error summaries |
| One-line table rows and plain audit labels | `tests/one_line_rows.rs` checks cell classes against long real-tenant UPNs and descriptions |
| Documentation matches code | `tests/docs.rs` checks that every `KEYRING_*` setting is in `README.md` and `docs/design/12-appendices.md`, every `Action` and `Refusal` is in `docs/deploy.md`, every bold UI label in `docs/guides/` appears in `templates/`, all relative links exist, and `README.md` has no hype words or em dashes |
| Docs point at real `src/` files | CI step in `.github/workflows/ci.yml` verifies every backticked source path under `src/` in docs exists on disk |
| Dependencies stay small and permissively licensed | `deny.toml` allows only crates.io permissive licences and bans `openssl`, `native-tls` and `aws-lc-rs` |

---

## 4. Adding a route, audit action or setting

### 4.1 Adding a POST route and audit action

1. Add the variant to `Action` in `src/audit/mod.rs`, add it to `Action::ALL`, and give it a dotted `as_str()` name and plain-English `label()`.
2. Wire the route in `src/routes/mod.rs` with `audited(Action::..., handler)`.
3. If the route is not nested under `/v/{vault}` or carries secret values, update `holds_secret_material` and `Target::from_route` in `src/routes/reason.rs` so the reason gate places the request and never echoes secret material.
4. Document the dotted action name in `docs/deploy.md` (under **Audit event fields**) and `docs/design/12-appendices.md` (Appendix B).
5. Run `cargo test --test audit_events --test docs --test one_line_rows`.

### 4.2 Adding a `KEYRING_*` setting

1. Parse and validate the variable in `src/config.rs` (`Config::from_lookup`). Reject invalid or empty-where-required values at startup rather than silently disabling a control.
2. Add it to `.env.example`, `README.md` (Configuration tables), `docs/design/12-appendices.md` (Appendix A), `docs/deploy.md`, and the Bicep templates in `infra/app-service/main.bicep` and `infra/container-apps/main.bicep` if deployers should configure it.
3. Run `cargo test --test docs`.

---

## 5. Running the local end-to-end demo and Playwright screenshots

`tests/screenshots.rs` launches the real Keyring binary server on `http://127.0.0.1:3999` backed by realistic mock Azure vaults (`kv-payments-dev`, `kv-payments-test`, `kv-payments-prod`, `kv-platform-dev`, `kv-identity-test`), Audit logs, Keyring activity rows, PIM roles and a pre-authenticated session cookie.

Start the local server in one terminal:

```sh
cargo test --test screenshots -- --ignored --nocapture
```

It prints:

```text
Keyring demo at http://127.0.0.1:3999
KEYRING_DEMO_COOKIE=keyring_session=<id>
```

Open `http://127.0.0.1:3999`, set the printed cookie (or use `curl -b "$KEYRING_DEMO_COOKIE"`), or capture fresh screenshots with Playwright:

```sh
KEYRING_DEMO_COOKIE=keyring_session=<id> scripts/screenshots.sh
KEYRING_SHOTS=guides KEYRING_DEMO_COOKIE=keyring_session=<id> scripts/screenshots.sh
```

The Playwright script writes desktop and mobile screenshots into `docs/images/screenshots/` and walkthrough screenshots into `docs/images/guides/`.

---

## 6. Bicep templates and container build

Validate every Bicep template and parameter file locally with the Azure CLI:

```sh
cd infra
for f in app-service/main.bicep container-apps/main.bicep alerts/main.bicep alerts/access.bicep sentinel/main.bicep modules/*.bicep; do
  az bicep build --file "$f" --stdout > /dev/null
done
```

Build and run the hardened distroless container locally:

```sh
docker build -t keyring:local .
docker run --rm -p 3000:3000 --env-file .env \
  --read-only --cap-drop ALL --security-opt no-new-privileges keyring:local
```

Verify `/healthz` returns `ok` with `Cache-Control: no-store`.

---

## 7. Continuous integration and release provenance

- `.github/workflows/ci.yml` runs five jobs on every push and pull request: `rust` (doc path check, `fmt`, `clippy`, `test`, Node JS tests, release build), `supply-chain` (`cargo deny`, `cargo audit`, CycloneDX crate SBOM), `bicep` (all templates and feature combinations), and `docker` (toolchain match check, distroless image build and hardening check).
- `.github/workflows/docs.yml` builds and publishes the Docusaurus site in `website/` to GitHub Pages.
- `.github/workflows/release.yml` builds signed multi-arch / `linux/amd64` container images on `vX.Y.Z` tags, generates SBOMs and attaches GitHub build provenance attestations (`gh attestation verify`).

---

## 8. Building the PDF and Word documentation suite

All formal PDF and editable Word DOCX documents in `docs/` are built from Markdown using Pandoc 3, Python 3 and WeasyPrint (`brew install pandoc weasyprint`), styled with the locked `design.md` colour tokens and system fonts:

```sh
# 1. Solution Design Document (docs/Keyring-Design-Document.pdf & .docx)
docs/design/build.sh

# 2. Security Architecture & Controls (docs/Keyring-Security.pdf & .docx)
tools/docs/build-doc.sh docs/security Keyring-Security

# 3. Enterprise Comparison & Migration Guide (docs/Keyring-Enterprise-Comparison.pdf & .docx)
tools/docs/build-doc.sh docs/comparison Keyring-Enterprise-Comparison

# 4. Deployment Guide, Administrator SOPs and Developer Guide
python3 tools/docs/build-admin-docs.py

# 5. User Walkthrough Guides (combined + individual per-walkthrough packs)
python3 tools/docs/build-guides.py
```

Every builder sets `SOURCE_DATE_EPOCH` and deterministic zip timestamps so unchanged inputs produce reproducible artefacts. Commit the Markdown sources and rebuilt PDF/DOCX deliverables together.

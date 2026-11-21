# Executive summary

Many organisations running on Microsoft Azure pay twice for secrets management. They already store application secrets, TLS certificates and cryptographic keys in Azure Key Vault, and already govern staff identities in Microsoft Entra ID with Conditional Access, Privileged Identity Management (PIM) and Microsoft Sentinel. Alongside that, they continue to licence, host, patch and back up a separate secrets product such as Delinea (Thycotic) Secret Server, CyberArk, HashiCorp Vault or a SaaS password vault, primarily because the Azure portal is awkward for day-to-day human workflows, cross-environment collaboration and non-specialist teams.

Keyring removes that gap without introducing a second vault, a second database or a second identity store. It is a single, stateless Rust web console (~8 MB container image, no Node.js or npm, no database) that acts strictly as the signed-in person using the OAuth 2.0 on-behalf-of (OBO) flow. Every read and write goes straight to Azure Key Vault under that person's own Entra RBAC roles.

## What moving to Keyring + Azure Key Vault delivers

| Outcome | What changes when you consolidate onto Keyring + Azure Key Vault |
|---|---|
| Single source of truth | Applications (via managed identities, Key Vault references and CSI drivers) and people (via Keyring) work against the exact same Key Vaults, eliminating copy-paste drift between Secret Server and Azure |
| Zero new database or standing vault roles | Keyring stores nothing and its managed identity holds zero vault roles. Compromising the identity or container at rest yields zero vault access; runtime compromise is strictly limited to active in-memory user OBO sessions until idle or absolute expiry |
| Native Entra ID governance | Sign-in, MFA, Conditional Access step-up, PIM just-in-time activation and approval workflows, and leaver offboarding all live in Entra ID with no directory sync lag |
| Multi-environment collaboration | Teams compare `dev`, `test`, `staging` and `prod` vaults side by side without revealing values, spot missing or drifting secrets, export release-readiness CSVs, and set separate values per environment with built-in duplicate-value protection |
| Lower total cost of ownership | Eliminates per-user / per-secret commercial vault licences, dedicated SQL Server / IIS / cluster infrastructure, backup jobs and database HA maintenance |
| Audit and SIEM ready | Combines Key Vault's native `AuditEvent` logs with Keyring's structured `KeyringAudit_CL` table (capturing reasons, tickets and refusals), backed by Microsoft Sentinel ASIM parsers, analytics rules and workbooks |

## Where commercial PAM tools still fit

Keyring is intentionally focused on Azure Key Vault and human secret operations. Keep or pair a specialist Privileged Access Management (PAM) tool if you require:

- **Interactive session proxying and video recording** (RDP/SSH jump hosts, keystroke logging for domain admins or third-party vendors).
- **Automated target-system password rotation (RPC)** against on-premises Active Directory accounts, Windows local admins, Linux root accounts or network switches (Keyring displays rotation status tags written by Azure Functions or external jobs, but does not log into target servers).
- **Network discovery** of unmanaged local accounts and service accounts across on-premises servers.
- **Browser autofill extensions** for consumer-style SaaS website logins.
- **Multi-cloud dynamic secrets** (AWS STS, GCP IAM, Postgres dynamic roles outside Azure).

For most Azure-first enterprises, however, 70% to 90% of day-to-day entries in Secret Server are application API keys, database credentials, TLS certificates, service tokens, partner logins and shared operational credentials that belong in Azure Key Vault anyway. Moving those workloads onto Key Vault + Keyring shrinks commercial PAM licences dramatically or allows full retirement where Entra ID + Azure Bastion cover interactive access.

# Architectural comparison

Standalone secrets tools (Delinea Secret Server, CyberArk, HashiCorp Vault, Infisical, Doppler) all share one structural property: they are **a second secret store** with their own encryption hierarchy, storage backend, replication topology, user/group sync and admin break-glass accounts.

Keyring takes the opposite architecture: **a stateless, zero-privilege control plane directly over Azure Key Vault**.

| Architectural dimension | Keyring + Azure Key Vault | Standalone PAM / Secrets Vault (Secret Server, CyberArk, HashiCorp Vault) | SaaS Secrets Managers (Doppler, Infisical Cloud, 1Password) |
|---|---|---|---|
| Where secrets live | Azure Key Vault (HSM-backed Standard or Premium, customer's own Azure region and subscription) | Dedicated vault database (SQL Server, PostgreSQL, Raft/Consul, or vendor SaaS) | Vendor-hosted multi-tenant cloud (or self-hosted DB + Redis + app stack) |
| Does the console have vault access? | **No.** Managed identity has zero roles on any vault; every call uses the signed-in person's OBO token | **Yes.** The application tier holds master encryption keys / database credentials | **Yes.** Backend service or client-side master key decrypts vaults |
| Database to back up, patch and HA-cluster | **None.** Restarting the container loses only in-memory sessions | **Yes.** SQL Server Always On, Vault Raft/Consul cluster, or PostgreSQL HA | Managed by vendor (SaaS) or Postgres + Redis (self-hosted) |
| Application runtime secret delivery | Native Azure Managed Identities, Key Vault references, AKS CSI driver, GitHub OIDC (zero static bootstrap keys) | SDK, agent, or API token that must itself be distributed and rotated | CLI wrapper, sync agent or service token synced into Azure/K8s |
| Identity and RBAC authority | Entra ID + Azure RBAC + Entra PIM directly (one source of truth) | Synced AD/Entra groups mapped to internal folder permissions and policies | Synced SCIM/SSO groups mapped to product-specific projects and roles |
| Data residency and sovereignty | Stays entirely inside the organisation's Azure tenant and chosen region (e.g. Australia East) | Customer-hosted (self-hosted) or vendor cloud region | Vendor cloud region (often US/EU unless enterprise tier) |
| Build and supply-chain surface | Single static Rust binary (~8 MB distroless image, `forbid(unsafe_code)`, CycloneDX SBOM, cosign provenance, no Node/npm in runtime) | Large .NET / Java / Go / Node stacks with OS, web server, DB and plugin dependencies | Large Node/TypeScript or proprietary SaaS stacks |

# Side-by-side capability matrix

The table below compares Keyring (with Azure Key Vault, Entra ID, Entra PIM and Microsoft Sentinel) against six tools enterprises most commonly use or evaluate.

::: {.compact .landscape}
| Capability | Keyring + Azure Key Vault | Delinea Secret Server | CyberArk PAM / Conjur | HashiCorp Vault (OSS / HCP) | 1Password Business / Bitwarden SM | Infisical / Doppler | Azure Portal / CLI |
|---|---|---|---|---|---|---|---|
| **Core storage & encryption** | Azure Key Vault (FIPS 140-2/3 HSM option), soft delete, purge protection | SQL Server / Delinea Cloud DB | Hardened vault appliance / Privilege Cloud | Raft / Consul / HCP Vault | Vendor cloud (E2EE) | Vendor cloud or self-hosted Postgres | Azure Key Vault |
| **Zero-database stateless UI** | Yes (8 MB container, stores nothing) | No (SQL Server + IIS / SaaS) | No (Vault + PVWA + CPM + PSM) | No (storage backend + seal keys) | No (cloud DB) | No (Postgres + Redis / SaaS) | N/A (Microsoft portal) |
| **Delegated user identity (no app vault access)** | Yes (Entra OBO on every call) | No (app mediates all reads) | No (app mediates all reads) | Token/OIDC auth to Vault policies | No | No | Yes (user ARM/KV token) |
| **Secrets, certificates and keys** | Full lifecycle (secrets, X.509 certs, RSA/EC/HSM keys, versions, rollback) | Secrets & files; limited native Azure cert/key lifecycle | Secrets, certs (via add-ons), SSH keys | KV secrets, PKI engine, Transit | Logins, notes, SSH keys; no Azure Key Vault certs/keys | KV secrets & env vars; limited cert/HSM key mgmt | Full, spread across fragmented blades |
| **Structured secret types** | Password, Login, Database, API key, SSH key (stored as clean JSON in Key Vault) | Custom secret templates | Account platforms | Arbitrary JSON KV maps | Rich item templates | Key-value pairs | Plain strings only |
| **Multi-environment comparison matrix** | Yes (`/environments`: auto-grouped `dev`/`test`/`prod`, parity, drift, CSV) | Folders only (no native cross-folder drift matrix) | Safes only (no native env parity matrix) | Paths/namespaces only | Vaults only | Yes (core strength: env matrix) | No |
| **Multi-env value entry + prod duplicate guard** | Yes (`/environments/set` warns when identical values span prod and non-prod) | No | No | No | No | Partial (env overrides, no Azure KV native guard) | No |
| **Copy / promote without showing value** | Yes (`/copy`: value never rendered in browser) | Requires read or script | Requires dual control or script | CLI/API copy | Manual copy/paste | Sync/promote across envs | CLI script only |
| **Just-in-time elevation & approval** | Native Entra PIM activation & deactivation directly from 403 pages; email fallback without P2 | Built-in checkout & approval workflows | Built-in dual control & ticketing workflows | Enterprise namespaces / external workflow | No native JIT RBAC | Access requests (paid tier) | Separate PIM blade in Entra |
| **Conditional Access step-up** | Yes (`acrs` auth context or max sign-in age before reveal/download/rollback/copy/purge/share) | MFA policies / external IdP | MFA / CyberArk Identity | OIDC / MFA (Enterprise) | SSO + master password | SSO + MFA | CA policy on Key Vault resource |
| **Reason & ticket reference gate** | Yes (`KEYRING_REQUIRE_REASON` + regex `KEYRING_REASON_TICKET_PATTERN`) | Yes (Require Comment + ITSM integration) | Yes (Reason + ServiceNow/Jira integration) | Audit metadata (custom) | No | Partial (change requests) | No |
| **Per-item reveal limits (`copy-only` / `none`)** | Yes (`keyring-reveal` tag; loosening gated by step-up & reason) | Yes (Hide Launcher Password / View vs Use) | Yes (Connect without viewing password) | Policy-based read deny | Conceal / view permissions | Role-based | No |
| **Password policy enforcement** | Yes (`KEYRING_PASSWORD_POLICY` + built-in common-password check + generator) | Yes (Password Requirements) | Yes (Master Policy) | Password policies (Vault policies) | Watchtower / generator | No | No |
| **Item ownership & access review report** | Yes (`owner`/`notify`/`keyring-owners` tags, mandatory owner rule, quarterly Access Review CSV) | Folder/secret owners & reports | Safe owners & compliance reports | External / custom | Vault permissions report | Project audit logs | No unified per-item access review |
| **Time-limited single-secret sharing** | Yes (opt-in `KEYRING_SHARING`: real Azure RBAC / PIM assignment, no one-time links) | Temporary secret sharing | Temporary safe access | Short-lived tokens / cubbyhole | Public / org share links | Secret share links | Manual RBAC assignment |
| **Who used it (30-day blast radius)** | Yes (queries Key Vault diagnostic logs before you change a value) | Audit report (Secret Server reads only; misses direct Azure app reads) | Audit report (vault reads only) | Audit device logs | Usage events | Audit logs | Manual KQL query in Log Analytics |
| **Expiry & credential age dashboards** | Yes (cross-vault Expiry + Age view + Event Grid + ACS email) | Built-in expiration reports & alerts | Built-in compliance dashboard | Custom / lease expiry | Watchtower expiry | Rotation reminders | No cross-vault dashboard |
| **SIEM integration** | Native Logs Ingestion (`KeyringAudit_CL`) + Microsoft Sentinel ASIM parser, analytics rules & workbook | Syslog / CEF / Sentinel connector | Syslog / CEF / PTA / Sentinel connector | Audit device -> log shipper -> SIEM | Events API -> Sentinel | Webhook / SIEM export (Enterprise) | AzureDiagnostics / AZKVAuditLogs |
| **Target-system auto-rotation (AD, Windows, Linux, switches)** | **No** (displays tags from Azure Functions/Event Grid rotation jobs) | **Yes** (Remote Password Changing / Heartbeat) | **Yes** (Central Policy Manager) | **Yes** (Database, AD, Cloud secrets engines) | No | Limited (selected cloud DBs/APIs) | Via Event Grid + Azure Functions |
| **Interactive RDP/SSH session recording** | **No** (use Azure Bastion / Entra) | **Yes** (Web/Protocol Launcher + recording) | **Yes** (Privileged Session Manager) | **No** (separate Boundary product) | No | No | No (use Azure Bastion) |
| **Browser form autofill extension** | **No** | Yes (Web Password Filler) | Partial | No | **Yes** (core strength) | No | No |
| **Software licence cost** | **Free (MIT open source)**; pay only Azure Key Vault + small App Service / Container Apps | High commercial per-user / per-secret subscription | Very high enterprise PAM licence | OSS free (BSL 1.1); Enterprise / HCP high | Per-user SaaS subscription | Free tier; Enterprise per-seat | Included with Azure |
:::

# Deep dive: Moving off Delinea Secret Server

Delinea Secret Server (formerly Thycotic Secret Server) is the single most common legacy tool Azure teams look to retire or downsize. Many organisations bought Secret Server years ago for on-premises Active Directory accounts, and over time teams began storing Azure connection strings, API keys, certificates and SaaS credentials inside it as well.

## Concept-by-concept mapping

| Delinea Secret Server concept | Keyring + Azure Key Vault equivalent | Notes for architects and admins |
|---|---|---|
| **Folder** (e.g. `Payments / Production`) | **Azure Key Vault** (e.g. `kv-payments-prod`) tagged `app=payments`, `env=prod` | One vault per workload and environment gives hard Azure RBAC, network firewall and purge-protection isolation instead of logical folder rows in one SQL database |
| **Folder permissions** (List / View / Edit / Owner) | **Azure RBAC roles** (`Reader`, `Key Vault Reader`, `Key Vault Secrets User`, `Key Vault Secrets Officer`, `Key Vault Administrator`) assigned to Entra security groups | Enforced by Azure across Keyring, the Azure portal, CLI, SDKs and pipelines |
| **Secret Template** (Web Password, SQL Server, SSH Key, API Key) | **Keyring secret types** (Password, Login, Database, API key, SSH private key) | Stored as clean, documented JSON (`application/vnd.keyring.<type>+json;v=1`) inside an ordinary Key Vault secret so other tools still read it cleanly |
| **Require Comment** / **Ticket Number** | `KEYRING_REQUIRE_REASON=reveal` or `all` + `KEYRING_REASON_TICKET_PATTERN` | Regex-checked ticket reference (e.g. `(INC\|CHG)[0-9]{7}`) recorded on `KeyringAudit_CL`; never calls external ITSM systems |
| **Require Approval** / **Check Out** | **Entra ID PIM** eligible roles with approval, justification, MFA and time-bounded activation | Activated directly from Keyring's "You don't have access" page; no duplicate approval engine. Where Entra ID P2 is not licensed, Keyring emails vault owners (`keyring-owners`) via ACS |
| **Hide Launcher Password** (use without seeing) | `keyring-reveal=copy-only` or `keyring-reveal=none` | `copy-only` copies to clipboard without showing on screen; `none` blocks reveal/copy in Keyring so only managed identities or break-glass CLI use the secret |
| **Password Requirements** | `KEYRING_PASSWORD_POLICY` (e.g. `min=14,upper,lower,digit,symbol,max-repeat=3,common`) | Enforced in memory on create, Set a new value, import and multi-environment writes, with built-in common-password list |
| **Secret Expiration & Alerts** | Key Vault `exp` attribute + **Expiry dashboard** + **Age view** + Event Grid -> Keyring -> ACS email | Also tracks credential age even when no expiry date was set (`KEYRING_STALE_AFTER_DAYS`) |
| **Secret Audit & Event Pipeline** | Key Vault `AuditEvent` + Keyring `KeyringAudit_CL` + **Microsoft Sentinel content** + ACS activity emails | `KvRequestId` correlates every Keyring UI action (including reason and ticket) to Key Vault's own `CorrelationId` row |
| **Secret Dependencies** ("what breaks if I rotate this?") | **Used by in the last 30 days** panel on every secret, certificate and key | Reads real Key Vault diagnostic logs showing every app, managed identity and person that read the item, rather than a manually maintained dependency list that goes stale |
| **Unlimited Administrator** | **Eliminated.** No Keyring super-admin exists | Every user acts strictly with their own Azure RBAC. Vault administrators are governed through Entra PIM with approval and Sentinel alerts |
| **Discovery & Remote Password Changing (RPC)** | **Not in Keyring.** Replace static secrets with Azure Managed Identities / OIDC wherever possible; use Azure Event Grid + Functions (`docs/rotation.md`) for Azure PaaS credentials; retain minimal PAM only if legacy on-premises RPC is mandatory | Most cloud teams discover that 80%+ of Secret Server entries never used RPC anyway |
| **Session Recording (RDP/SSH)** | **Not in Keyring.** Use Azure Bastion (with session recording) or Entra ID SSH login for Azure VMs, or retain a scoped PAM tool strictly for legacy jump hosts | Separating human cloud secrets from jump-host recording shrinks PAM seat counts dramatically |

## Why Azure teams hit friction with Secret Server

1. **Duplicate storage and drift.** Apps in Azure App Service, AKS and Azure Functions read from Azure Key Vault, while engineers store and copy values in Secret Server. When someone rotates a secret in one place and forgets the other, outages follow.
2. **Database and infrastructure overhead.** Self-hosted Secret Server requires Windows servers, IIS, SQL Server (often Always On for HA), Distributed Engines for private networks, TLS certificates, regular upgrades, and database backups. Even Secret Server Cloud requires Distributed Engines inside your VNet and ongoing connector maintenance.
3. **Licensing expansion.** Commercial PAM licences scale by active users, seats or secret counts. Giving every developer, QA engineer and auditor read-only visibility into secret metadata or expiry status becomes prohibitively expensive, leading teams to share spreadsheets or `.env` files instead.
4. **Blind spots on application usage.** Secret Server only logs people clicking "View" in Secret Server. It has no visibility into which Azure Managed Identities, pipelines or services are actually reading the credential in Key Vault. Keyring's **Used by in the last 30 days** and **Access review** show both human and machine consumers from Key Vault's own log.

# Comparing with other enterprise tools

## CyberArk PAM and Conjur

- **Where CyberArk excels:** Tier-0 privileged access (Active Directory domain controllers, mainframe/network devices, full RDP/SSH session isolation and video recording, threat analytics on privileged sessions) and multi-cloud enterprise PAM programmes.
- **Where Keyring wins for Azure workloads:** CyberArk carries high licence costs, complex multi-component architecture (Digital Vault, PVWA, CPM, PSM, Conjur followers), and steep administration overhead. For Azure application teams managing Key Vault secrets, certificates and keys, Keyring deploys in under an hour with zero database, zero agents and zero per-seat cost, while still integrating natively with Entra PIM and Microsoft Sentinel.
- **Recommended pattern:** Keep CyberArk strictly for Tier-0 interactive PAM and legacy infrastructure if already mandated; move all Azure application secrets, certificates and keys onto Azure Key Vault + Keyring so platform and engineering teams never need CyberArk seats.

## HashiCorp Vault (OSS, Enterprise and HCP)

- **Where HashiCorp Vault excels:** Multi-cloud dynamic secrets (short-lived AWS IAM, GCP, Postgres, RabbitMQ and PKI credentials), Transit encryption-as-a-service across AWS/GCP/on-premises, and teams deeply invested in Terraform across multiple clouds.
- **Where Keyring wins for Azure-first enterprises:** Running self-hosted HashiCorp Vault in production requires cluster management, unseal/auto-unseal key lifecycle, Raft snapshots, DR replication, upgrade coordination and BSL 1.1 licence review (or paying for HCP Vault Dedicated). If your workloads run on Azure, Azure Key Vault already gives you Microsoft-managed HA, geo-redundancy, HSM backing, Managed Identity integration and native App Service/AKS secret mounting. Keyring gives humans the clean console, multi-environment matrix, RBAC/PIM workflow and Sentinel audit layer over Key Vault without running a Vault cluster.

## Doppler and Infisical

- **Where Doppler and Infisical excel:** Developer-friendly multi-environment `.env` workflows, SDKs and sync bridges for startups and multi-cloud SaaS teams.
- **Where Keyring wins for regulated enterprises:** Doppler and Infisical store your secrets in their own database (vendor SaaS or a self-hosted Node/Postgres/Redis stack) and sync copies out to Azure Key Vault using a high-privilege service principal. That creates a **god-mode sync credential** with write access to every production vault and introduces a second secret database to accredit. Keyring never stores secrets, never syncs copies, holds zero vault permissions, ships as an 8 MB static Rust binary with no Node.js runtime, and now provides native multi-environment comparison (`/environments`) and per-environment value entry (`/environments/set`) directly against Azure Key Vault.

## 1Password Business and Bitwarden Secrets Manager

- **Where 1Password and Bitwarden excel:** Personal and team browser password autofill for SaaS web logins (marketing tools, vendor portals, social media accounts), passkeys and mobile apps.
- **Where Keyring wins for infrastructure and engineering:** Consumer-origin password managers lack native Azure Key Vault storage, X.509 certificate auto-renewal policies, HSM cryptographic key rotation, Entra PIM activation, Azure RBAC enforcement and Sentinel KQL correlation. Many enterprises keep 1Password/Bitwarden strictly for human SaaS website logins (browser autofill) while standardising all application, database, API, certificate and infrastructure credentials in Azure Key Vault + Keyring.

## Azure Portal and Azure CLI

- **Where the Azure portal and CLI fall short for teams:** The Azure portal exposes raw secret values immediately with one click on "Show Secret Value" (no 30-second auto-hide, no clipboard clearing, no reason/ticket gate, no per-item reveal limit, no password policy), offers no cross-vault search, no cross-vault expiry or credential-age dashboard, no multi-environment side-by-side matrix, no value-blind copy across vaults, no quarterly per-item access review, and no structured Secret Types.
- **Important security boundary:** Because Keyring's extra UI controls (step-up, reason gate, password policy, owner rule, reveal limits) live in Keyring, organisations that want hard enforcement across **every** path should pair Keyring with **Entra Conditional Access policies on Azure Key Vault** and **Entra PIM eligible assignments** for officer roles.

# Multi-environment collaboration and secret hygiene

One of the main reasons engineering teams cling to standalone tools like Doppler, Infisical or shared Secret Server folders is collaborating across `dev`, `test`, `staging` and `prod` environments. Keyring supports this natively without breaking its stateless, zero-privilege architecture:

1. **Zero-configuration environment grouping.** Keyring automatically groups vaults that share an Azure ARM tag (`keyring-group`, `app`, `service`, `workload`, `system`) or a common naming prefix (`kv-payments-dev`, `kv-payments-test`, `kv-payments-prod`), ordering columns left-to-right in promotion order (`dev` -> `test`/`sit`/`qa` -> `uat`/`staging`/`preprod` -> `prod` -> `dr`). Teams with custom naming can pick any 2 to 8 visible vaults on demand.
2. **Side-by-side parity and drift detection without reading values.** The **Environments** page (`/environments`) reads only names and properties via Keyring's bounded fan-out cache. It immediately surfaces:
   - **Missing in an environment:** secrets present in `dev`/`test` that haven't been created in `prod` yet, with 1-click **Create** (pre-filling the secret name to enter prod's own value) and **Copy from ...** (promoting the value without displaying it).
   - **Needs attention:** secrets expired, expiring within 30 days, disabled or stale in any environment.
   - **Metadata differs:** secrets whose content type, owner, reveal limit or enabled state drifted between environments.
   - **Not read:** if a developer lacks access to `prod`, that column clearly shows **Not read** rather than falsely claiming secrets are missing.
3. **Setting distinct values across environments with production reuse protection.** On **Set across environments** (`/environments/set`), a team member enters separate values for each environment in one audited form with shared description, owner, notify list, expiry, reveal limit and tags:
   - **Duplicate-value safety guard:** Keyring compares submitted values in memory (never logging or quoting them) and refuses when the exact same secret value is entered for more than one environment (highlighting production reuse in particular) unless explicitly confirmed.
   - **RBAC-aware handoff:** If a developer holds `Key Vault Secrets Officer` in `dev` and `test` but only `Reader` in `prod`, `dev` and `test` succeed and the results page cleanly reports `prod` as **Refused** with a direct link to **My access** (PIM activation or owner access request) so an operator or release manager finishes `prod`.
   - **Fail-closed reveal-limit preservation:** Before writing any target vault, Keyring verifies existing secret metadata (failing closed if metadata cannot be read) and carries forward any stricter `keyring-reveal` limit (`copy-only` or `none`). Note that Azure Key Vault's `SetSecret` API does not provide server-side version preconditions against a concurrent admin tightening the tag mid-flight.
4. **Release-readiness CSV exports.** `/environments.csv` exports a formula-guarded parity report (marking any unreadable vaults as `NOT READ`) for Change Advisory Board (CAB) sign-off and quarterly audits.

# Total cost of ownership (TCO) and operational footprint

Indicative annual comparison for a 150-engineer Azure organisation managing 2,000 secrets across 30 vaults (`dev`, `test`, `prod` across 10 workloads). Replace figures with your organisation's negotiated Azure Enterprise Agreement and vendor quotes.

| Cost and effort category | Keyring + Azure Key Vault | Commercial PAM / Secret Server (150 users) | Self-hosted HashiCorp Vault Enterprise |
|---|---|---|---|
| **Software licence** | **$0** (MIT licence) | Significant annual per-user / tier subscription | High enterprise node + namespace subscription (OSS free under BSL 1.1) |
| **Compute hosting** | ~$15–$80 / month (1–2 small Azure Container Apps replicas or App Service `P0v3` / `B1`) | 2+ Windows/IIS app servers + Distributed Engines + SQL Server Enterprise/Standard HA (or SaaS tier) | 3–5 HA Vault nodes + KMS auto-unseal + monitoring |
| **Secret storage (Azure Key Vault)** | Standard Key Vault operations (~$0.03 per 10,000 operations; HSM keys ~$1–$5/key/month) | Included in PAM DB (plus you still pay Azure Key Vault for cloud runtime secrets!) | Storage + snapshots (plus Azure Key Vault if syncing) |
| **Database backup, DR and patching** | **Zero** (stateless container; Azure Key Vault geo-redundancy & soft delete built in) | Full SQL Server backup/DR, OS patching, IIS & application upgrades | Raft snapshot automation, DR secondary cluster, seal key ceremonies |
| **Audit & SIEM ingestion** | Low volume `KeyringAudit_CL` rows into existing Log Analytics / Sentinel workspace | Custom syslog forwarders / connectors + ingestion | Audit log shipping + parser maintenance |
| **Identity administration** | Zero separate users/groups; uses existing Entra groups & PIM | AD/Entra sync jobs, internal roles, break-glass local admin rotation | Auth method config, entity/group aliases, root token procedures |
| **Blast radius of app compromise** | **Zero standing vault access** (no stored secrets or vault roles; runtime compromise limited strictly to active in-memory user OBO sessions) | High (app tier has access to vault database and master encryption keys) | High (compromised Vault node with unseal access exposes stored secrets) |

# Compliance and regulatory alignment

For Australian government agencies and regulated enterprises (financial services, critical infrastructure, healthcare), Keyring + Azure Key Vault aligns directly with common assurance frameworks:

| Framework control area | How Keyring + Azure Key Vault addresses it |
|---|---|
| **ASD ISM: Cryptographic storage & key management** | Secrets, keys and certificates stay in Azure Key Vault (Australian regions `australiaeast` / `australiasoutheast`, FIPS 140-2 Level 2 / FIPS 140-3 Level 3 HSM option for Premium keys, non-exportable keys enforced in Keyring) |
| **ASD ISM: Least privilege & JIT administration** | No standing service principal with vault access; every call runs as the signed-in person; Entra PIM activates eligible roles just in time with approval and automatic expiry |
| **ASD ISM: Event logging & central SIEM** | Every action (and every refusal) emits a schema-versioned audit event (`KeyringAudit_CL`) joined via `KvRequestId` to Key Vault's `AuditEvent`, with Microsoft Sentinel ASIM parser, analytics rules and fail-closed `KEYRING_AUDIT_REQUIRED` option |
| **ASD Essential Eight: MFA & Restrict Admin Privileges** | Entra ID MFA and Conditional Access step-up (`KEYRING_STEP_UP_AUTH_CONTEXT`) before reveals, private key downloads, rollbacks, copies, purges and shares; zero local accounts |
| **ASD Essential Eight: Patch Applications & Supply Chain** | Minimal Rust binary (~8 MB distroless image, no shell, no package manager, no Node/npm), weekly `cargo audit` and `cargo deny` CI gates, CycloneDX SBOMs and signed GitHub build provenance |
| **SOC 2 (CC6 / CC7) & ISO 27001 (A.8 / A.9 / A.12)** | Quarterly **Access review** CSV (owner, last changed, 90-day usage, effective RBAC access, rotation status), mandatory `owner` tag policy, password complexity policy, reveal limits, and full change reasons with ticket references |

::: unconfirmed
**Assurance note.** Nothing in this document implies formal IRAP, SOC 2 or ISO 27001 certification of Keyring. Platform accreditation of Azure Key Vault, Entra ID and Microsoft Sentinel comes from Microsoft's own assessments; Keyring's own controls are documented with source and test mappings in `docs/Keyring-Security.pdf`, and deployment verification on a real tenant is tracked in `docs/real-vault-checklist.md`.
:::

# Five-phase migration playbook (Secret Server to Keyring)

A low-risk migration does **not** lift-and-shift every static password into Azure Key Vault. Use the migration to eliminate unnecessary static credentials first, then move the remaining human-managed and application secrets cleanly.

## Phase 1: Inventory and classify (Weeks 1–2)

1. Export the **metadata only** (never secret values) from Secret Server: folder path, secret name, template type, owner, last accessed date, RPC enabled flag, and linked launcher/session recording flag.
2. Classify every entry into four buckets:
   - **Bucket A: Eliminate:** Azure service principal secrets, storage account keys, SQL passwords for Azure PaaS services that can be replaced with **Azure Managed Identities** or **GitHub/Azure DevOps OIDC federation**.
   - **Bucket B: Migrate to Azure Key Vault + Keyring:** Application API keys, third-party integration credentials, database logins, SSH keys, TLS certificates, partner tokens and operational credentials.
   - **Bucket C: Move to SaaS password manager (optional):** Pure human browser logins for external SaaS portals where autofill is needed.
   - **Bucket D: Retain in scoped PAM:** Tier-0 AD/network device credentials that strictly require automated on-premises RPC or interactive RDP/SSH session recording.
3. Archive or retire secrets not accessed in over 12 months after owner sign-off.

## Phase 2: Design vault topology, tags and RBAC (Week 3)

1. Establish a standard per-workload, per-environment Key Vault layout (for example `kv-<workload>-dev`, `kv-<workload>-test`, `kv-<workload>-prod`) in the matching Azure subscriptions.
2. Turn on **Azure RBAC**, **soft delete** and **purge protection** (at minimum on `prod` vaults), and route `AuditEvent` logs to your central Log Analytics / Sentinel workspace (see Administrator SOP 1).
3. Tag every vault consistently with Azure ARM tags:
   - `keyring-owners=<team-email>,<lead-email>`
   - `app=<workload>` (or `keyring-group=<workload>`)
   - `env=<dev|test|staging|prod>` (or `keyring-env=<...>`)
4. Map Entra ID security groups per vault (never individual users): `kv-<workload>-<env>-readers`, `kv-<workload>-<env>-users`, `kv-<workload>-<env>-officers`. Make production `Secrets Officer` and `Secrets User` **PIM eligible** with approval.

## Phase 3: Deploy and harden Keyring (Week 4)

1. Deploy Keyring using the Bicep templates in `infra/app-service/` or `infra/container-apps/` with:
   - **Federated managed identity** (`useFederatedCredential = true`, zero client secrets to rotate).
   - **Private networking** (`docs/private-vaults.md`) if any target vaults disable public access.
   - **Audit sink** (`auditWorkspaceId`) + `auditRequired = true` + Microsoft Sentinel content (`infra/sentinel/`).
   - **Enterprise controls:** `KEYRING_STEP_UP_AUTH_CONTEXT`, `KEYRING_REQUIRE_REASON=all`, `KEYRING_REASON_TICKET_PATTERN`, `KEYRING_PASSWORD_POLICY`, `KEYRING_REQUIRE_OWNER=true`.
   - **Notifications:** Azure Communication Services email (`notifyDomain`, `notifyAllowedDomains`, `notifyTypes = 'expiry,access-requests,watched-reads,destructive,role-use,health'`) + Event Grid expiry delivery (`KEYRING_EVENTGRID_SUBSCRIPTIONS`).
2. Complete every applicable check in `docs/real-vault-checklist.md` against a pilot subscription and record the results.

## Phase 4: Migrate secrets and validate parity (Weeks 5–8)

1. For each workload, migrate non-production (`dev`, `test`) first, then `prod`:
   - **Small or sensitive sets (recommended):** Rotate credentials as you move them by entering fresh, distinct values per environment directly in Keyring's **Set across environments** (`/environments/set`), setting `owner`, `notify`, `description`, `expires` and `keyring-reveal` (`copy-only` or `none` for high-sensitivity items).
   - **Larger existing sets:** Prepare a short-lived CSV (`name,value,content_type,expires,description,owner,notify,...`) in an encrypted working directory, import per vault using Keyring's **Import secrets** preview flow (which validates password policy and mandatory owners before writing), then securely wipe the CSV immediately.
2. Open **Environments** (`/environments`) for the workload and confirm:
   - Zero unintended **Missing in an environment** gaps.
   - Zero unintended **Metadata differs** drift (owners, reveal limits, content types match).
   - Download `/environments.csv` and archive it as migration evidence.
3. Open **Vault health** (`/vault-health`) and confirm every migrated vault passes RBAC, soft delete, purge protection, audit logs, network access and owners.
4. Update applications and pipelines to read directly from Key Vault using Managed Identities, Key Vault references or CSI drivers (removing any Secret Server API calls).

## Phase 5: Parallel run, audit sign-off and decommission (Weeks 9–12)

1. Mark migrated Secret Server folders **Read-only** for 2–4 weeks while monitoring Secret Server audit logs to catch any forgotten consumer.
2. In Keyring, open **Used by in the last 30 days** and **Access review** (`/v/{vault}/access/review`) on each production vault to confirm live application reads and clean ownership.
3. Verify Sentinel alerts (`KeyringAudit_CL` + `AZKVAuditLogs`) fire as expected on test reveals, refusals and role activations.
4. Export final Secret Server compliance audit logs to long-term immutable storage, then either reduce Secret Server licences to the small Tier-0 PAM subset (Bucket D) or decommission Secret Server infrastructure completely.

# Decision guide

Use this quick decision table to confirm the right target state for your organisation:

| Organisation profile | Recommended target state |
|---|---|
| **Azure-first engineering & platform teams** (App Service, AKS, Functions, Azure SQL, DevOps/GitHub Actions) | **Full consolidation onto Azure Key Vault + Keyring + Entra PIM + Sentinel.** Retire Secret Server / Doppler / Infisical for all cloud workloads |
| **Hybrid enterprise with legacy on-premises AD, Windows/Linux servers and network gear** | **Split by workload:** move all Azure & cloud application secrets, certificates and keys to Azure Key Vault + Keyring (eliminating 70–90% of PAM seats); retain a small, tightly scoped PAM instance solely for Tier-0 interactive session recording and legacy RPC |
| **Teams needing browser autofill for marketing / business SaaS websites** | Keep a lightweight SaaS password manager (e.g. 1Password/Bitwarden) for browser autofill only; prohibit storing production infrastructure, database or API credentials in it and route those to Azure Key Vault + Keyring |
| **Multi-cloud dynamic secrets heavy (AWS + GCP + on-prem Postgres dynamic leases)** | Evaluate HashiCorp Vault (or cloud-native managers per cloud). Keyring is intentionally built for Azure Key Vault and one Entra tenant |

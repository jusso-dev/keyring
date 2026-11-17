# Solution overview

## What Keyring is

Keyring is a small web app that sits in front of Azure Key Vault. It lets people who don't use the Azure portal find a vault, look up a secret, add a certificate or rotate a key, in plain English.

It is a thin layer. Every call to Key Vault is made as the person who is signed in, so Key Vault's own Entra RBAC (or access policies on older vaults) decides what they can see and change. If they can't do it in the portal, they can't do it in Keyring. Keyring adds what the portal doesn't give a non-specialist: plain wording, typed confirmation before a delete, an expiry dashboard across every vault, who used an item before it is changed, an audit trail of its own, and optional controls such as step-up sign-in and a reason before a value is shown.

Keyring is written in Rust (Axum and Askama) and ships as one container image of about 8 MB. There is no Node.js or npm anywhere in the product.

## Design principles

These four principles come first. Every later decision in this document follows from one of them.

| Principle | What it means in practice |
|---|---|
| **Act as the user** | Every Azure call that reads or changes a person's data uses a token Keyring got through the on-behalf-of (OBO) flow from that person's sign-in. Keyring has no identity of its own with data-plane or control-plane access to anyone's vaults, subscriptions or workspaces. Its one managed identity only proves Keyring is the app, writes audit rows and sends email; it never reads them |
| **Store nothing** | No database. Secret values pass through memory on the way to the browser and are never logged, cached or written to disk. The only lists Keyring keeps are each vault's item names and properties for a minute and the person's permissions for five minutes, in the session's memory. Pins are kept by the person's own browser |
| **Let Key Vault decide** | Authorisation is Key Vault RBAC or access policies. Keyring shows what Azure allows and explains clearly when it doesn't. Disabled buttons are only a hint; Key Vault still answers every request |
| **Safe by default** | Purge is off. Deletes need the name typed. Values are hidden until revealed, cleared from the screen after 30 seconds, and Keyring tries to clear the clipboard after a copy. Every optional control is off until a setting turns it on, and a bad setting stops Keyring starting |

## Key design decisions

| # | Decision | Reason |
|---|---|---|
| D1 | **Rust**, with `unsafe` code forbidden in the crate | A small, auditable dependency tree (24 direct crates, 300 in the lock file including build and test), memory safety, one static binary. Supply chain checked by `cargo deny` and `cargo audit` on every change |
| D2 | **No npm in the product** | A typical Node web app pulls in hundreds of packages, many with install scripts. That is a lot of trust to extend for a tool that handles secrets. No bundler, no CDN scripts, no Tailwind |
| D3 | **Server-rendered HTML** (Askama templates compiled into the binary) | Pages work without JavaScript. Three small hand-written same-origin scripts (`app.js`, `pins.js`, `tags.js`) add copy, clipboard clearing, pins and tag rows. A strict CSP with no inline code is possible because nothing needs it |
| D4 | **On-behalf-of tokens** for every data call | The person's own roles decide every action, so Keyring can't be used to reach anything they couldn't already reach. It is also why Keyring uses OIDC, not SAML: a SAML assertion can't be exchanged for a downstream token |
| D5 | **A managed identity only for Keyring's own calls** | One user-assigned identity, three uses: the federated credential (in place of a client secret), writing audit rows, sending email. Never a client secret or a second identity for these, and no role on any vault or workspace read path |
| D6 | **Tags as the data store** for notes, owners and policy | Key Vault has no description or owner field. Keeping the note, the owner and the rotation markers in ordinary tags (`description`, `owner`, `notify`, `rotation*`) keeps "store nothing" true: they show in the portal and CLI, move with the item, and need no database |
| D7 | **Plain REST, not the `azure_*` crates** | The official Rust SDK crates were still in beta, change often and bring their own identity and HTTP layers that would need working around to plug in OBO tokens. The few stable, versioned REST endpoints Keyring uses are less code to trust |
| D8 | **One outbound HTTP client** on rustls with the `ring` provider | No OpenSSL and no aws-lc (`deny.toml` bans both). HTTPS only except to localhost, no redirects, fixed timeouts |
| D9 | **Sessions in memory** | Nothing to persist, back up or leak from disk. The cost is that a restart signs everyone out and several copies need sticky sessions (section 11.3) |
| D10 | **Azure-native alerting** | Keyring runs no background job with stored credentials. Expiry alerts come from Key Vault's Event Grid events; access alerts are Azure Monitor log search rules; Sentinel rules run in Sentinel |
| D11 | **Optional controls are Keyring controls** | Step-up, reasons, the password policy, the owner rule and reveal gates apply inside Keyring only. The Azure CLI and portal aren't limited by them, and the document says so wherever they appear |
| D12 | **Public cloud only, one tenant** | The hosts are fixed in the code. Supporting sovereign clouds, Managed HSM or several tenants would widen what has to be trusted and tested |

## What a person can do

| Area | What Keyring offers |
|---|---|
| Vaults | Every vault the person can see across subscriptions (Resource Graph), filtered on the server, with each vault's audit log status and owners |
| Secrets | List, versions, reveal and copy with clipboard clearing, create (Password, Login, Database, API key, SSH key types), set a new value, edit details, enable or disable, roll back, delete, recover, purge when allowed, copy to another vault, import from `.env` or CSV, bulk changes |
| Certificates | List, details from the DER, create self-signed or with the vault's issuers, upload PEM or PFX with a preview, renewal settings, cancel pending requests, public downloads, private key download for exportable policies, edit details, delete, recover, purge when allowed |
| Keys | List, public key as JWK and PEM, create, rotate now, rotation policy, enable or disable, edit details, delete, recover, purge when allowed |
| Across vaults | Search, expiry dashboard, age view, vault health, audit reports, each with CSV export |
| Audit | Key Vault's log for a vault, Keyring's own events for a vault, "Used by in the last 30 days" on every item and change form |
| Access | Who can reach a vault or an item (RBAC, eligible PIM assignments, access policies), permission hints on buttons, PIM activation from a 403 page, My access |
| Tags | Description, owner and notify fields, tag rows with suggestions, Owned by me |
| Generator | Passwords, GUIDs and API keys from the operating system's secure random source |
| Email | Health notices to admins, expiry notices pushed by Event Grid |

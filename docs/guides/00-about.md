# About these walkthroughs

These walkthroughs show people how to use each page of Keyring, step by step. Each one names the role you need, what to have ready, the steps with what you should see, what Keyring checks and the messages you may meet, what goes in the audit log, and what to do when something goes wrong.

People who run Keyring have their own guide, the [administrator SOPs](../admin/admin-sops.md).

## How to read them

- Button, field, link and heading names are in bold, exactly as Keyring shows them.
- Messages Keyring shows are in "quotes".
- Names in examples (`kv-payments-prod`, `db-connection-string`, `alex.taylor@demo.example`) are made up. So are the people in the screenshots, which come from Keyring's demo over mock Azure services.
- Steps that have only been checked against Keyring's mock Azure services say "Not yet confirmed on a real tenant" and point to the matching rows in the real-tenant checklist.
- Some parts of Keyring are only there when whoever runs it turns them on, such as access requests, activity emails and sharing. The walkthrough says how to tell.

## Who does what

Keyring has no roles of its own. You use it with your own Azure roles, the same ones that decide what you can do in the Azure portal. The table shows the usual roles and which walkthroughs each person needs.

| Role | Azure roles it means | Typical people | Walkthroughs |
| --- | --- | --- | --- |
| Reader | Reader on the vault (or its resource group or subscription), plus Key Vault Reader for names and dates | Anyone who needs to know what exists and when it expires | 01, 03, 08, 09, 10 |
| Secrets officer | Key Vault Secrets Officer on the vault. Key Vault Secrets User reads values but can't change them | Application teams who look after their own secrets | 01 to 03, 06, 07, 08, 10, 13 |
| Certificates officer | Key Vault Certificates Officer. Key Vault Certificate User to download a private key | Platform and web teams who look after TLS certificates | 01, 03, 04, 07, 08 |
| Crypto officer | Key Vault Crypto Officer | Teams whose apps sign, encrypt or wrap with keys | 01, 03, 05, 07, 08 |
| Vault administrator | Key Vault Administrator, or the three officer roles together. To share a secret, also Owner, User Access Administrator or Key Vault Data Access Administrator | The people who own a vault | All of 01 to 13, and 16 |
| Auditor | Reader on the vaults, and Log Analytics Reader on the workspaces they send their logs to | Security, risk and audit staff | 11, 14, 15 |

The README's role table lists the role for every action, one row at a time. Ask whoever looks after your vaults for a role; Keyring can't grant one.

## How Keyring enforces the rules

Key Vault decides. Every read and change goes to Azure as you, with your own token. If Azure says no, Keyring shows "You don't have access" with the role to ask for. Keyring has no access of its own to any vault, and it stores no secrets, values or lists. Restarting it forgets everything except what is in Azure.

Disabled buttons are hints. Keyring reads your permissions on the vault from Azure and keeps them for five minutes. A button your roles don't allow stays on the page but is disabled, with "Needs" and the role beside it. It is only a hint: if Keyring can't read your permissions, or the vault uses access policies, every button stays enabled and Key Vault still decides when you use it.

Keyring adds a few checks of its own. These depend on how your Keyring is set up, and the walkthroughs say where each applies:

- typing an item's name before a delete or a permanent delete
- a reason, and maybe a ticket, before a value is shown or anything is changed (`KEYRING_REQUIRE_REASON`)
- confirming it's you with a fresh or stronger sign-in before a value is shown, a private key is downloaded, a secret is rolled back or copied, or anything is purged (step-up)
- a password policy for passwords you type (`KEYRING_PASSWORD_POLICY`)
- an owner on every item (`KEYRING_REQUIRE_OWNER`)
- no permanent deletes unless they are turned on (`KEYRING_ALLOW_PURGE`)
- reveal limits on a sensitive secret or certificate (its `keyring-reveal` tag)

These are Keyring's rules, not Key Vault's. Someone with the same Azure role can still use the Azure CLI or the portal without them. They are there for the Keyring path and for the audit log.

## Two audit logs

Two different logs come up in these walkthroughs:

- Key Vault's audit log is what Key Vault writes for every call it receives, from Keyring or anything else, when the vault sends its logs to a Log Analytics workspace. The **Audit** page and **Who used it** read it as you.
- Keyring's own audit events are what Keyring writes for each thing you do through it, including what it refused before asking Key Vault. They go to Keyring's own log and, when set up, to a table in Log Analytics that the **Keyring activity** view reads.

Each walkthrough names the Keyring audit actions its steps write, such as `secret.reveal`. Pages that only read names and properties (lists, search, expiry, vault health, the audit pages) write no audit event.

## The walkthroughs

| Number | Walkthrough |
| --- | --- |
| 01 | Getting started |
| 02 | Secrets |
| 03 | Tags, notes and owners |
| 04 | Certificates |
| 05 | Keys |
| 06 | Copy a secret to another vault |
| 07 | Bulk changes and secrets import |
| 08 | Expiry dashboard, age view and expiry emails |
| 09 | Vault health |
| 10 | Access |
| 11 | Audit |
| 12 | Notifications people receive |
| 13 | Password policy and reveal limits |
| 14 | Access review report |
| 15 | For auditors |
| 16 | Share a secret |
| 17 | Collaborate across environments |

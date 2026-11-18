# Access review report

This walkthrough is for people who review who can reach a vault, for example in a quarterly access review. It shows the **Access review** page and its CSV, and how to use them with the vault's owners.

## Who this is for

| To do this | Azure role | Where |
| --- | --- | --- |
| Open the access review, and see role assignments and access policies | Reader | Each vault in the review |
| See the items in it | Key Vault Reader, or the matching User role | Each vault in the review |
| See who used each item | Log Analytics Reader | The workspace each vault logs to |

The report reads as you. With fewer roles it still opens, and says what it couldn't read.

## Before you start

- List the vaults in the review.
- Have each vault's owners from its `keyring-owners` tag (shown on **Vaults**), or ask whoever owns the vault.

## Steps

1. Open the first vault and select **Access**, then **Access review**. Its address is `/v/<vault>/access/review`.

   The page lists every secret, certificate and key in the vault. Secrets and keys that belong to a certificate are listed as the certificate. "Only names, properties, role assignments and the audit log are read, never values."

2. Read the notices at the top first. Anything Keyring couldn't read (no diagnostic setting on the vault, a workspace you can't read, role assignments you can't read, no events yet, a partial or slow answer) is said once there, and every cell it affects says "Not known". "Not known" isn't the same as none.

3. Read **Used by in the last 90 days**: the people, apps and managed identities that read a secret's value, read a certificate's private key or used a key, from Key Vault's audit log, up to 20 for each item. "None found" means none in the logs Keyring read for this period, not that nothing uses it.

4. Read **Who has access to the whole vault**. Everything listed there reaches every item, including roles given on the resource group or subscription, with **Eligible** for PIM assignments.

5. Work down **Items**. Each row has **Name**, **Type**, **Expires**, **Owner**, **Description**, **Value changed**, **Used by (90 days)**, **Access on this item** and **Rotation**. "As the vault" means nobody has a role on that item alone. Disabled items are marked **Disabled**.

6. Select **Download CSV** to keep a copy with the review record. The file is named `keyring-access-review-<vault>-<date>.csv`, and has the vault, the notify list, days since the value changed, and a complete **Who has access** column for each row. Anything Keyring couldn't read is a `NOT READ` row at the end.

7. Ask the vault's owners to confirm each assignment and each item, and have whoever looks after Azure roles remove what isn't needed. Keyring doesn't change role assignments.

8. For anyone whose access you question, run **Activity by one person** on the vault's **Audit** page to see what they actually did.

9. Repeat for each vault.

Not yet confirmed on a real tenant: the 90-day query on a busy vault, certificates and keys in "Used by", item-scoped roles, and the CSV in a spreadsheet. See the "Access review:" rows in the "Access" section of [real-vault-checklist.md](../real-vault-checklist.md).

## What Keyring checks

| Check | What you see |
| --- | --- |
| You can't read role assignments | A notice with "What to ask for:" and the role, and "Not known" in the access cells, not an empty table |
| The vault sends no audit logs, or you can't read the workspace | A notice, with "What to ask for:" where a role would help. Every "Used by" cell says "Not known" |
| Some items couldn't be listed | "Some of this vault's secrets, certificates or keys couldn't be listed". Those aren't in the report |
| An item has more than 20 callers | "More not listed. Open the item to see its callers." |
| The vault uses access policies | Each policy by object ID, with what it allows, and those that read secret values marked |

## What is recorded

Nothing. The **Access review** page and its CSV, like **Access** and the audit reports, write no audit event of Keyring's own. Key Vault and Log Analytics may log the reads made as you.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| Every "Used by" cell says "Not known" | Read the notice at the top. Usually the vault doesn't send its logs to Log Analytics, or you need Log Analytics Reader on the workspace |
| Object IDs, not names | Keyring doesn't look up names. Each ID links to the Azure portal |
| Group members aren't listed | Open the group in the Azure portal to see them |
| The page is slow on a busy vault | "Used by" is one Log Analytics query per workspace for 90 days. Wait, or use the CSV |

## Related walkthroughs

- [10 Access](10-access.md)
- [11 Audit](11-audit.md)
- [15 For auditors](15-auditors.md)

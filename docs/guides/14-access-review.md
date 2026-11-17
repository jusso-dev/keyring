# Access review report

This walkthrough is for people who review who can reach a vault, for example in a quarterly access review. The access review report itself is still to come. Until it is on main, this walkthrough shows how to do a review with the pages Keyring has today.

## Who this is for

| To do this | Azure role | Where |
| --- | --- | --- |
| See role assignments and access policies | Reader | Each vault in the review |
| See who used each item | Log Analytics Reader | The workspace each vault logs to |

## Before you start

- List the vaults in the review.
- Have each vault's owners from its `keyring-owners` tag (shown on **Vaults**), or ask whoever owns the vault.

## Steps with the pages on main today

1. Open the first vault and select **Access**.

2. Select **Download CSV** for every role assignment that reaches the vault, with where each comes from and whether it is **Eligible** (PIM) or **Can grant itself access**.

3. For each item with its own roles, open it and read its **Access** section, which adds roles given on that one item.

4. On the vault's **Audit** page, run **Refused requests** across vaults and **Activity by one person** for anyone whose access you question, to see what they actually did.

5. Ask the vault's owners to confirm each assignment, and have whoever looks after Azure roles remove what isn't needed. Keyring doesn't change role assignments.

6. Repeat for each vault, and keep the CSVs with the review record.

## Coming with #261: the access review report

A later change (#261, part 3) is to add an access review report to Keyring. This section will say where to find it, what it lists and how to export it, once that change is on main.

## What Keyring checks

| Check | What you see |
| --- | --- |
| You can't read role assignments | A message with "What to ask for:" and the role, not an empty table |
| The vault uses access policies | Each policy by object ID, with what it allows, and those that read secret values marked |

## What is recorded

Nothing. The **Access** page, its CSV and the audit reports write no audit event.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| Object IDs, not names | Keyring doesn't look up names. Each ID links to the Azure portal |
| Group members aren't listed | Open the group in the Azure portal to see them |

## Related walkthroughs

- [10 Access](10-access.md)
- [11 Audit](11-audit.md)
- [15 For auditors](15-auditors.md)

# Share a secret

This walkthrough shows how to give a colleague or a security group read access to one secret until a date you pick, how to see who it is shared with, how to revoke a share, and how to read **My shares**. Sharing is off unless whoever runs Keyring turns it on.

A share is a real Azure role assignment: Keyring gives the person or group the Key Vault Secrets User role on that one secret, as you, with your own access. They can then read its value in Keyring, the portal or the Azure CLI. Nothing else in the vault is shared, and Keyring keeps no list of shares: every page reads them from Azure.

## Who this is for

| To do this | Azure role | Where |
| --- | --- | --- |
| Share a secret, and revoke a share | Owner, User Access Administrator, or Key Vault Data Access Administrator (which can be limited to assigning Key Vault Secrets User) | The secret or its vault |
| See the secret and who it is shared with | Key Vault Secrets User or Officer, and Reader to read the role assignments | The vault |
| Read a secret shared with you | Nothing more: the share gives you Key Vault Secrets User on that secret | The secret |

Key Vault Secrets Officer alone can't share: Azure decides who can create a role assignment, not Keyring.

## Before you start

- Check your Keyring has sharing on: the secret's page has a **Share** button.
- Know who to share with: their name, email address or object ID, or a security group's name.
- Pick the last day they need it. Keyring allows up to a set number of days (30 unless whoever runs Keyring set `KEYRING_SHARE_MAX_DAYS` otherwise).
- Know whether your tenant has Privileged Identity Management (PIM, with Entra ID P2). It decides whether the access ends by itself.

## When the access ends

| Your tenant | What Keyring makes | At the end date |
| --- | --- | --- |
| Has PIM | A PIM assignment with that end date | Azure removes the access at the end of that day. **Shared with** says "(Azure removes it)" |
| Has no PIM licence | A plain role assignment, described as made by Keyring with its end date | Azure does NOT remove it. **Shared with** says "(Azure won't remove it)", and shows **Overdue** after the date until someone selects **Revoke** |
| Has PIM, but a PIM setting refuses the request (multifactor sign-in, a shorter time, a ticket) | Nothing. The share is refused and the page names the setting | Not applicable. Keyring doesn't fall back to a plain role assignment, since that would have no end date and step round the setting |

Without PIM, a share lasts until someone revokes it. Put a reminder in your calendar for the end date, and check **Shared with** or the access review (walkthrough 14) for **Overdue**.

## Steps

### Share a secret

1. Open the secret and select **Share**.

   The page says Keyring gives the person or group "the Key Vault Secrets User role on this one secret, as you, until the date you pick".

2. In **Share with**, type part of a name and pick the person or security group from the list. Or type their exact email address or object ID.

   The list comes from your directory through Microsoft Graph, as you, so it shows only who you could find yourself. If the list says groups can't be searched, people are still listed; ask whoever runs Keyring about the `GroupMember.Read.All` permission.

3. Pick **Until**: the last day they can read it, up to the most days your Keyring allows. It starts at 7 days from today.

4. Give a reason, and a ticket if asked. Your Keyring may ask for one, as it does before a value is shown. Don't type secrets or personal details.

5. Select **Share**.

   If your Keyring asks you to confirm it's you, you see **Confirm it's you**, sign in again, and come back to the form.

   You are back on the secret's page with one of:

   - "Shared" the secret "with" them "until" the date. "Azure removes this access at the end of that day."
   - "Asked to share" the secret: "PIM needs someone to approve it first." Nobody has access until it is approved.
   - "Shared" with them, and "PIM isn't licensed in this tenant, so Keyring made a plain role assignment. Azure won't remove this access on the end date. Keyring will show it as overdue."

   When your Keyring sends share emails, the person gets one naming the secret, the vault, the end date and you, with a link to the secret's page, and you get a receipt. A group gets none, and nobody is emailed while PIM waits for approval.

Not yet confirmed on a real tenant: every sharing step. See the "Sharing a secret" section of [real-vault-checklist.md](../real-vault-checklist.md).

### See who a secret is shared with

6. Open the secret and read **Shared with**, under **Used by**.

   It lists everyone with a role on this secret on its own, with **Who**, **Role** and **Shared**. Shares made in Keyring say who shared them and until when, with **Overdue** once a plain share's date has passed. Roles given some other way say "Not through Keyring". Access to the whole vault is listed under **Access**, not here.

### Revoke a share

7. Under **Shared with**, select **Revoke** beside the share. Only shares Keyring made on this one secret have **Revoke**.

8. On **Revoke this share?**, type the secret's name, give a reason if asked, and select **Revoke**.

   Keyring says "Revoked the share of" the secret. "Azure can take a few minutes to apply it."

### Read My shares

9. Select **My access**, then **My shares**.

   **Shared with me** lists secrets in this vault shared with you, who shared each and until when. **Shared by me** lists the ones you shared through Keyring, with **Overdue** where a plain share's date has passed. To revoke one, open the secret and use **Revoke** under **Shared with**.

## What Keyring checks

Keyring refuses these before anything changes in Azure:

| Check | What you see |
| --- | --- |
| The secret has a `keyring-reveal` tag on any version (walkthrough 13) | "This secret has a reveal limit". Keyring won't give anyone else access to read it |
| The vault uses access policies | No **Share** button. A share tried anyway says "This vault can't share one secret": access policies can only give access to every secret in the vault |
| The secret belongs to a certificate | "This secret belongs to a certificate", with a link to open the certificate |
| You picked yourself | "That's you. You can't share a secret with yourself. Nothing was shared." |
| The end date is in the past | "The end date is in the past. Pick today or a later date." |
| The end date is too far away | "A share can last at most" the most days your Keyring allows. "Pick an earlier end date." |
| Nobody matches what you typed | "Keyring couldn't find a person or security group with that in your directory. Check it and try again." Only people and security groups in your tenant can be picked |
| Too many searches | "Too many searches. Wait a minute and try again." |

Azure then decides:

| Azure says | What you see |
| --- | --- |
| You can't create role assignments here | "Not shared", naming the roles that can: Owner, User Access Administrator, or Key Vault Data Access Administrator |
| They already have the role on this secret | "Already shared" |
| A PIM setting refuses it | "Not shared", naming the setting, such as "PIM wants you to have signed in with multifactor authentication". Nothing else is tried |
| PIM refuses the request | "PIM refused the request", and nothing was shared |

## What is recorded

`share.grant` when you share, with the secret, who it was shared with (object ID and type) and whether it went through PIM or as a plain assignment, and your reason. A refusal is `share.grant` with `outcome` `refused` and a `reason_code`: `share_to_self`, `share_date`, `share_principal` or `share_not_allowed`. A PIM refusal is `pim_refused`. `share.revoke` when you revoke one. Your security team may be alerted to a share with a guest account, or to many shares by one person in a short time.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| No **Share** button | Sharing is off in your Keyring, or the vault uses access policies |
| "Not shared" with the roles named | Ask whoever looks after the vault for one of them, or ask them to share it |
| The person still can't read it | Azure can take a few minutes. If PIM said it needs approval, it isn't on until someone approves it |
| The picker finds nobody | Type their exact email address or object ID. If the picker says Keyring can't search the directory, ask whoever runs Keyring about the Graph permissions |
| A share is **Overdue** | Your tenant has no PIM, so Azure didn't remove it. Select **Revoke** |

## Related walkthroughs

- [02 Secrets](02-secrets.md)
- [10 Access](10-access.md)
- [13 Password policy and reveal limits](13-password-policy-and-reveal-limits.md)
- [14 Access review report](14-access-review.md)

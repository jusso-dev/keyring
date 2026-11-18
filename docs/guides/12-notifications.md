# Notifications people receive

This walkthrough explains the emails Keyring sends, who gets each one, and what an email never contains. Keyring sends email only when whoever runs it has turned email on and chosen which kinds to send.

## Who this is for

Anyone who might receive Keyring's emails: vault owners, item owners, people on a notify list, people who ask for access, and the Keyring admins.

| To do this | You need |
| --- | --- |
| Receive an email | Nothing in Azure. Whoever runs Keyring decides who gets each kind |

## Before you start

Nothing. Emails come from a `DoNotReply` address in your organisation's domain (or an Azure-managed one), with a subject starting `[Keyring]`, so mail rules can sort them.

## What an email never contains

Every Keyring email holds a heading, a few lines, the item and vault where there is one, who and when, and a link to the item in Keyring. Each ends "Keyring never puts a secret value in an email."

An email never holds a secret value, a token, a private key, Azure's error message, a description or a tag value. The reason a person typed appears only in an access request, and only when it can't become a link; every other email only says a reason was given. Opening the link signs you in to Keyring as usual, and you see only what your own roles allow.

## The emails

### Expiry

Subject: `[Keyring] Expiry:`, the kind, the name and the vault.

Sent when Key Vault says a secret, certificate or key is about to expire or has expired, and whoever runs Keyring has pointed that vault's events at Keyring. It says when the item expires, its version, and has **Open it in Keyring** and **Expiry dashboard** links.

Who gets it: the addresses whoever runs Keyring set for that vault's event subscription (only when Keyring limits email to allowed domains), otherwise the Keyring admins. Not the item's **Owner** or **Notify** tags: reading them needs vault access, which Keyring's own identity doesn't have.

Repeats: one email per item, version and event in 24 hours.

### Health (to the admins only)

Subject: `[Keyring] Health`.

Sent to the Keyring admins only, when Keyring itself is in trouble:

| Email | When |
| --- | --- |
| **Keyring's audit sink is failing** | Keyring's own audit table hasn't accepted records for over five minutes |
| **Keyring's audit sink has recovered** | It is sending again |
| **Many refused requests in a short time** | One person or address was refused more than a set number of times in 15 minutes. Names them and the count, with a link to their activity |
| **Keyring's client secret expires soon** | 30, 14, 7 and 1 days before Keyring's own client secret expires |
| **Keyring's client secret has expired** | Once the date has passed. Nobody can sign in until it is replaced |

### Access requests

Subject: `[Keyring] Access request`.

Sent when someone selects **Send request** on the **Request access** page (walkthrough 10). Heading: "Someone asked for access to a vault".

Who gets it: the addresses in the vault's `keyring-owners` tag, read as the person asking. When the tag names nobody, or can't be read in time, the Keyring admins. The person asking gets their own separate copy, headed "Your access request was sent", with no links, so it never shows who the owners or admins are.

What it holds: **Asked by** (their sign-in name), **Role**, **Vault**, **Scope** (one item, or "The whole vault"), **Reason**, **Ticket** if given, and **When**, with a link to open the vault's Access control in the Azure portal and one to see who has access in Keyring.

The reason and ticket are quoted only when they hold nothing a mail client could turn into a link: no `@`, no full stop with a letter or digit straight after it (so `example.com`, and even `v1.2`, are held back), no colon followed by anything but a space, and no two slashes in a row. Otherwise the field says it was "Given, but not shown here because it holds something a mail client could turn into a link", and points to the `access.request` event in Keyring's audit log.

What to do: Keyring grants nothing and keeps no request. If the request is right, grant the role in the vault's Access control (IAM) page in the Azure portal, at the scope asked for or the smallest scope that will do. If it isn't, there is nothing to do.

Repeats: one request per person, vault and role an hour, and at most 10 live requests for one person.

### Watched item reads

Subject: `[Keyring] Watched item read:`, the kind, the name and the vault.

Sent when someone reveals a secret's value, downloads a certificate's private key, copies a secret to another vault, or rolls a secret back, and the item lists addresses to tell. Heading: "A watched item was read".

Who gets it: the addresses in the item's **Notify** field (its `notify` tag), from the current version. With `KEYRING_NOTIFY_OWNER_ON_READ=true`, its **Owner** too. An item with neither sends nothing.

What it holds: **Who**, **What**, **When**, **Vault** and **Item**, and a link to the item's activity in Keyring. **From address** (where the reader came from) is shown only when whoever runs Keyring has limited email to allowed domains. If a reason was given, **Reason** says it was given and is on the event in Keyring's audit log.

Repeats: at most 4 emails an hour about one item. The fourth says "This is the last email about reads of this item for up to an hour." Later reads in that hour are in Keyring's audit log only.

### Deletes, permanent deletes and bulk changes

Subject: `[Keyring] Delete or bulk change`, and for a single item, the kind, the name and the vault.

Sent when a secret, certificate or key is deleted or permanently deleted, or a bulk change goes through. Heading: "An item was deleted", or "Several items were changed at once" for a bulk change, which lists up to 50 changed names and counts the rest. One bulk change is one email, even if only some items changed.

Who gets it: the vault's owners from its `keyring-owners` tag, or the Keyring admins when it names nobody or can't be read.

### Role use

Subject: `[Keyring] Role use`.

Sent when someone turns a PIM role on (once it is on, not while it waits for approval) or off through Keyring. Heading: "A PIM role was turned on" or "A PIM role was turned off", with **Role**, **Scope** and, when turned on, **For** (how long). A justification is only said to have been given.

Who gets it: the vault's owners, or the admins, as for deletes. A role turned on above the vault (on its resource group or subscription) reaches more than this vault, so it goes to the admins as well.

### Who isn't told

The person who acted isn't emailed about their own action, unless they are the only address. Each of these emails is sent only when the action succeeded: a refused or failed action sends nothing.

Not yet confirmed on a real tenant: the access request and activity emails. See the "Access requests" section and the "Activity email:" rows in the "Deployment" section of [real-vault-checklist.md](../real-vault-checklist.md).

## What Keyring checks

- Every recipient must be in your organisation's allowed email domains, when Keyring is set to limit them.
- Each recipient gets at most a set number of emails an hour for each kind (20 unless set otherwise).
- Addresses are never logged or put in an audit event unless whoever runs Keyring turns that on.

## What is recorded

Each email writes one Keyring audit event: `notify.sent` or `notify.failed`, with the kind of email and how many recipients. A watched read that isn't emailed because the item's hourly limit is reached is still recorded on its own event (such as `secret.reveal`). Each delivery from Event Grid writes `notify.webhook`.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| You expected an expiry email and got none | Ask whoever runs Keyring whether that vault's events go to Keyring, and who is on the list |
| An email has a link that asks you to sign in | That is expected. Keyring checks who you are before it shows anything |
| An email asks for a value or a password | It isn't from Keyring. Keyring never asks for one by email. Report it |
| A watched-read email for a read you didn't expect | Open the item's activity from the link and check who read it. If it wasn't expected, tell the vault's owners |
| Watched-read emails stopped | After 4 in an hour for one item, Keyring stops for up to an hour. The reads are still in the audit log |
| An access request shows "Given, but not shown here" | The reason held something like a web address. Read it on the `access.request` event in Keyring's audit log |

## Related walkthroughs

- [10 Access](10-access.md)
- [08 Expiry dashboard, age view and expiry emails](08-expiry.md)
- [03 Tags, notes and owners](03-tags-notes-owners.md)

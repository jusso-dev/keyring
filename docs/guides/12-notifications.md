# Notifications people receive

This walkthrough explains the emails Keyring sends, who gets each one, and what an email never contains. Keyring sends email only when whoever runs it has turned email on and chosen which kinds to send.

## Who this is for

Anyone who might receive Keyring's emails: item owners, people on a notify list, and the Keyring admins.

| To do this | You need |
| --- | --- |
| Receive an email | Nothing in Azure. Whoever runs Keyring decides who gets each kind |

## Before you start

Nothing. Emails come from a `DoNotReply` address in your organisation's domain (or an Azure-managed one), with a subject starting `[Keyring]`, so mail rules can sort them.

## What an email never contains

Every Keyring email holds a heading, a few lines, the item and vault where there is one, who and when, and a link to the item in Keyring. Each ends "Keyring never puts a secret value in an email."

An email never holds a secret value, a token, a private key, Azure's error message, or the reason a person typed. Opening the link signs you in to Keyring as usual, and you see only what your own roles allow.

## The emails on main today

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

## Coming with #259: watched reads, deletes, bulk changes and role use

A later change (#259) is to add emails to item owners and notify lists about activity: reads of watched items, deletes and bulk changes, and PIM role use. Keyring already has the settings names for them (`watched-reads`, `destructive`, `role-use`), but on main today they send nothing. This section will say what each email holds and who gets it once that change is on main.

## Coming with #258: access requests

A later change (#258) is to add an email for access requests made from the "You don't have access" page. On main today, the `access-requests` setting sends nothing. This section will be filled in when that change is on main.

## What Keyring checks

- Every recipient must be in your organisation's allowed email domains, when Keyring is set to limit them.
- Each recipient gets at most a set number of emails an hour for each kind (20 unless set otherwise).
- Addresses are never logged or put in an audit event unless whoever runs Keyring turns that on.

## What is recorded

Each email writes one Keyring audit event: `notify.sent` or `notify.failed`, with the kind of email and how many recipients. Each delivery from Event Grid writes `notify.webhook`.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| You expected an expiry email and got none | Ask whoever runs Keyring whether that vault's events go to Keyring, and who is on the list |
| An email has a link that asks you to sign in | That is expected. Keyring checks who you are before it shows anything |
| An email asks for a value or a password | It isn't from Keyring. Keyring never asks for one by email. Report it |

## Related walkthroughs

- [08 Expiry dashboard, age view and expiry emails](08-expiry.md)
- [03 Tags, notes and owners](03-tags-notes-owners.md)

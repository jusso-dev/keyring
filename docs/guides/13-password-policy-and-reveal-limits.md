# Password policy and reveal limits

This walkthrough explains Keyring's password policy: what it asks of a password you type, where it applies and what you see when a value misses it. It ends with reveal limits: how to set one on a secret or certificate, and what people see when one applies.

## Who this is for

| To do this | Key Vault role | Where |
| --- | --- | --- |
| Create a secret or set a new value | Key Vault Secrets Officer | The vault |
| Import secrets | Key Vault Secrets Officer | The vault |
| Set a reveal limit on a secret | Key Vault Secrets Officer | The vault |
| Set a reveal limit on a certificate | Key Vault Certificates Officer | The vault |

Whoever runs Keyring sets the policy for the whole Keyring, with `KEYRING_PASSWORD_POLICY`. It may be unset, in which case nothing here applies.

## Before you start

Open **Create a secret** to see whether your Keyring has a policy: if it does, the line "Keyring's password policy:" sits under the **Value** or **Password** field, saying what it asks for.

## Steps

### Create or change a password under a policy

1. Open **Create a secret**, or **Set a new value** on a secret.

2. Read the policy line under the field, such as "Keyring's password policy: at least 14 characters, an upper case letter, a lower case letter, a digit (0 to 9) and a symbol, such as ! # or %, no character more than 3 times in a row and not a common password. Checked when you save. The Azure CLI and portal don't apply it."

3. Type the password, or select **Generate a value** and **Use this value**. The generator's defaults (24 characters, all four kinds of character) meet a policy like the one above nearly every time.

4. Select **Create secret** or **Save new version**.

   If the value misses a rule, the field shows an error naming each rule it missed, in the rule's own words: never the value, its length or how close it came. The box is empty again, so type the value again.

### Know where the policy applies

| Where | Checked |
| --- | --- |
| **Password** secrets (a plain secret), and the **Password** field of a **Login** | Yes, on create and on set a new value |
| Every value imported from a file | Yes. A row that misses is skipped with "Its value doesn't meet Keyring's password policy." The rest is imported |
| **Database**, **API key** and **SSH private key** secrets | No. Their fields are machine credentials, keys and passphrases |
| Copy to another vault | No. It moves a value Keyring already holds |
| Roll back | No. It restores an old value as it was |

Every plain secret counts as a password. A PEM block or connection string in a plain secret is checked too, and may miss a rule (a PEM block has five dashes in a row). For those, pick the type that fits (**SSH private key**, **API key** or **Database**) on the create form.

The policy is a Keyring rule. Key Vault doesn't know about it, and the Azure CLI and portal aren't limited by it.

### Set a reveal limit on a secret or certificate

A reveal limit says how far Keyring will go with a sensitive item's value. It is kept in the item's `keyring-reveal` tag. Keys have no value to show, so they have no limit.

| Limit | On a secret | On a certificate |
| --- | --- | --- |
| **Copy only** (`copy-only`) | No **Show value**: **Copy value** puts it on your clipboard without showing it on screen. Copy to another vault still works, and the copy keeps the limit | The private key can't be downloaded |
| **No reveal** (`none`) | Keyring refuses to show it, copy it, or copy it to another vault | The private key can't be downloaded. The public certificate can |
| **No limit** | As usual | As usual |

Know what it does and doesn't do before you rely on it:

- It is a Keyring control, like step-up. Key Vault doesn't know about it. The Azure CLI, the portal and the SDKs aren't limited, and anyone who can change the item's tags can change it there.
- **Copy only** keeps the value off a screen someone else can see (over a shoulder, or on a shared or recorded screen). It doesn't stop the person signed in, who can paste it. The value still reaches their browser, to copy it.
- Any limit refuses the private key download, since a file has no clipboard to clear.

5. Open the secret and select **Edit details** (or **Set a new value**, or **Create a secret** for a new one). For a certificate, select **Edit details**.

6. Pick **Reveal limit**: **No limit**, **Copy only** or **No reveal**. On a certificate, **Copy only** reads "Copy only (no private key download)".

   If the page says "This limit was set outside Keyring as" a value Keyring doesn't know, Keyring treats it as **No reveal**. Leave **Keep as set elsewhere (treated as no reveal)** to keep it, or pick another.

7. Select **Save changes**, **Save new version** or **Create secret**.

   Making the limit stricter needs nothing extra. Loosening it (from **No reveal** to **Copy only** or **No limit**, or from **Copy only** to **No limit**) asks for the same checks as a reveal, when your Keyring has them: **Confirm it's you**, and a reason and ticket.

### What people see on a limited item

8. Open a **Copy only** secret. The page says "Copy only: Keyring won't show this value on screen, but Copy puts it on your clipboard." The button is **Copy value**, not **Show value**.

9. Select **Copy value**. The page says the value "isn't shown on screen" and has **Copy** buttons. Keyring tries to clear the clipboard after a set time.

10. Open a **No reveal** secret. The page says it "is set not to be shown or copied in Keyring", with no **Show value** and no **Copy to another vault**. Apps should read it with their own identity; if you need it yourself, use the Azure CLI with your own access.

11. Open a limited certificate. The page says "This certificate's private key is set not to be downloaded in Keyring". The public certificate can still be downloaded.

Old versions follow the stricter of their own limit and the current version's. Rollback, **Set a new value**, import, certificate upload and copy to another vault carry the stricter limit onto the new version, so no Keyring step drops it by accident.

Not yet confirmed on a real tenant: a limit set with the CLI, the limit carried by rollback and import, copy only in a real browser, and whether a certificate's tag reaches its backing secret. See the "Reveal limit" and "Copy only in a real browser" rows of [real-vault-checklist.md](../real-vault-checklist.md), and "Does a certificate's tag reach its backing secret".

## What Keyring checks

| Check | What you see |
| --- | --- |
| The value misses one or more rules | An error on the field naming each rule missed |
| An import row misses | "Its value doesn't meet Keyring's password policy." and the row is skipped |
| An import row has a Keyring content type | **Can't import**, policy or not. Typed secrets are made on the create form only |
| A reveal, copy or private key download on a limited item | **Not shown in Keyring**, before any value is read. "Nothing was read." |
| A limit was set while Keyring was reading the value | **Not shown in Keyring**, saying Keyring read it from Key Vault and didn't show or keep it |
| Loosening a limit without a reason, where one is asked for | "Loosening the reveal limit needs a reason of 5 to 200 characters." |
| `keyring-reveal` typed as a tag name | "The keyring-reveal tag is set with the Reveal limit control on the item's Edit details, so loosening it is checked and recorded. Leave it out of Tags." |
| `keyring-reveal` in a bulk change | "The keyring-reveal tag can't be changed in bulk." |

## What is recorded

A refused create or set writes its usual event (`secret.create` or `secret.set`) with `outcome` `refused` and `reason_code` `password_policy`. Each refused import row gets its own `secret.import` event with the same code. No event says which rule failed, and nothing about the value is logged.

A refusal by a reveal limit is the action's event (such as `secret.reveal`, `secret.copy.read` or `certificate.download_private_key`) with `outcome` `refused` and `reason_code` `reveal_limited`, and isn't a read. A save that changes a limit has `reveal_limit_from` and `reveal_limit_to` on its event (`unset`, `copy-only`, `none` or `other`).

## Troubleshooting

| Problem | What to do |
| --- | --- |
| A connection string or key is refused | Create it as a **Database**, **API key** or **SSH private key** secret |
| A password manager's suggestion is refused | The error says which rule it missed. Generate a longer one, or use Keyring's generator |
| The browser says the value is too short before you save | The browser only knows the minimum length. The other rules are checked when you save |
| **Copy value** does nothing | Copy needs JavaScript. With it off, a **Copy only** secret can't be copied in Keyring: use the Azure CLI |
| A limit you didn't set appeared | Someone set `keyring-reveal` in the portal or CLI. Ask the item's owner |

## Related walkthroughs

- [02 Secrets](02-secrets.md)
- [04 Certificates](04-certificates.md)
- [06 Copy a secret to another vault](06-copy-secret.md)
- [07 Bulk changes and secrets import](07-bulk-and-import.md)

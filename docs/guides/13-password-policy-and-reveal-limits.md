# Password policy and reveal limits

This walkthrough explains Keyring's password policy: what it asks of a password you type, where it applies and what you see when a value misses it. It ends with reveal limits on an item, which are still to come.

## Who this is for

| To do this | Key Vault role | Where |
| --- | --- | --- |
| Create a secret or set a new value | Key Vault Secrets Officer | The vault |
| Import secrets | Key Vault Secrets Officer | The vault |

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

### Coming with #261: reveal limits on an item

A later change (#261, part 2) is to add reveal limits set with a `keyring-reveal` tag on an item. On main today Keyring doesn't read that tag, and a tag of that name is an ordinary tag. This section will say how to set a limit and what people see when one applies, once that change is on main.

## What Keyring checks

| Check | What you see |
| --- | --- |
| The value misses one or more rules | An error on the field naming each rule missed |
| An import row misses | "Its value doesn't meet Keyring's password policy." and the row is skipped |
| An import row has a Keyring content type | **Can't import**, policy or not. Typed secrets are made on the create form only |

## What is recorded

A refused create or set writes its usual event (`secret.create` or `secret.set`) with `outcome` `refused` and `reason_code` `password_policy`. Each refused import row gets its own `secret.import` event with the same code. No event says which rule failed, and nothing about the value is logged.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| A connection string or key is refused | Create it as a **Database**, **API key** or **SSH private key** secret |
| A password manager's suggestion is refused | The error says which rule it missed. Generate a longer one, or use Keyring's generator |
| The browser says the value is too short before you save | The browser only knows the minimum length. The other rules are checked when you save |

## Related walkthroughs

- [02 Secrets](02-secrets.md)
- [07 Bulk changes and secrets import](07-bulk-and-import.md)

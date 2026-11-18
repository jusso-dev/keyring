# Access

This walkthrough shows how to see who can reach a vault and each item in it, what the disabled buttons tell you, how to turn on a role you are eligible for through Privileged Identity Management (PIM) from the "You don't have access" page, how to ask the vault's owners for a role when PIM isn't available, and how to read and switch off your own roles on **My access**.

## Who this is for

| To do this | Azure role | Where |
| --- | --- | --- |
| See the **Access** page and each item's **Access** section | Reader | The vault |
| Ask the vault's owners for a role | Reader, so the vault is in your vault list. Your Keyring must have access requests turned on | The vault, or above it |
| Turn on a role through PIM, see **My access**, turn a role off | An eligible PIM assignment of a Key Vault role (Entra ID P2 or Governance), and Reader on the vault to see role names | The vault, or above it |

## Before you start

- Choose the vault.
- For PIM, know whether your organisation has made you eligible for a role, and whether it needs a reason, a ticket or an approver.

## Steps

### See who can reach a vault

1. Select **Access**.

   Every role assignment that reaches the vault's contents is listed, including ones made on the resource group or subscription, with **Who**, **Type**, **Role** and **Comes from**. "People, groups and apps are shown by their Entra object ID and type, with a link to them in the Azure portal. Keyring doesn't look up their names."

   ![The Access page.](../images/guides/10-access.png)

2. Read the badges:

   - **Eligible**: "a PIM assignment the person has to turn on first".
   - **Can grant itself access**: "the role doesn't reach the contents itself, but can add a role or policy that does", such as Owner.

3. Select **Download CSV** for a spreadsheet of the list.

4. Open a secret, certificate or key to see its own **Access** section, which adds roles given on that one item.

   On a vault that uses **access policies**, the page lists each policy by object ID with what it allows, and marks those that read secret values. It also lists the role assignments that can change the vault, and so add a policy.

### Read the permission hints

5. Look for buttons that are disabled with "Needs" and a role beside them, such as "Needs Key Vault Secrets Officer".

   Keyring reads your permissions from Azure and keeps them for five minutes, so a new role can take that long to show. It is only a hint: Key Vault still decides when you use the button.

### Turn on an eligible role through PIM

6. Try what you need, such as **Show value**. If Azure says no, you see **You don't have access**, with "What to ask for:" and the role.

7. If you're eligible for that role, the page also says so, with **Activate** and the role's name. Select it.

   The **Activate** page says the role, where it applies, and whether PIM needs someone to approve it.

8. Pick **How long**, up to what PIM allows for the role. Fill in **Why you need it** (5 to 200 characters), and **Ticket system** and **Ticket number** if PIM asks for them.

9. Select **Activate** and the role's name.

   One of three things happens:

   - **Role turned on**: the role is on for the time you picked. "Key Vault can take a few minutes to see it." Select **Try again** to go back to what you were doing.
   - **Waiting for approval**: PIM turns it on once an approver says yes. **My access** shows it waiting, and **Open PIM in the Azure portal** lets you follow it.
   - PIM refused it, and nothing was turned on, with Azure's code under "Details:".

### Read and change your own roles

10. Select **My access**.

    It lists your own Key Vault roles that reach this vault: **On now** with **Time left**, **Starting later**, **Eligible** with **Activate**, and **Waiting for approval**. "Read from Azure each time; Keyring keeps nothing."

    ![My access.](../images/guides/10-my-access.png)

11. Select **Deactivate** beside a role you turned on, to switch it off before its time runs out.

    Keyring says "Role turned off. Key Vault can take a few minutes to see the change."

### Request access when PIM isn't available

Whoever runs Keyring can turn this on (email on, with `access-requests` in its notice types). If it is off, the pages are as above: ask whoever looks after the vault for the role named under "What to ask for:".

12. On the "You don't have access" page with no **Activate**, read "You can ask this vault's owners for" the role, and select **Request access**.

    You can also start from **My access**: under **Request access**, select **Request** and the role, for each Key Vault role you neither hold nor are eligible for.

13. On the **Request access** page, pick **For**: "Only the" item you were on, or "The whole vault". From **My access** the request is for the whole vault.

    The page says who it goes to: the owners named in the vault's `keyring-owners` tag, or Keyring's admins when it names nobody. You get a copy.

14. Fill in **Why you need it** (5 to 200 characters) and, if you have one, **Ticket**.

    Don't put secrets or personal details in the reason. Keyring writes it to its audit log with your name. "The email shows it only when it has no web or email address in it."

15. Select **Send request**.

    You see **Sent to the vault's owners**. You get your own copy of the email, separate from theirs, so it doesn't show who the owners are. "Keyring can't grant access itself and keeps no request: an owner grants the role in the Azure portal, and Key Vault can take a few minutes to see it." You see the same page whatever happened to the email.

16. Wait for an owner to grant the role in Azure. Keyring doesn't tell you when they do: try again later, or check **My access**.

Not yet confirmed on a real tenant: the request on a tenant without PIM, the owners from the vault tag, and the portal link. See the "Access requests" section of [real-vault-checklist.md](../real-vault-checklist.md).

## What Keyring checks

| Check | What you see |
| --- | --- |
| You can't read role assignments | A message and "What to ask for:" with the role (usually Reader), not an empty table |
| No PIM in your tenant, or no eligible role | The "You don't have access" page with no **Activate** |
| PIM couldn't be read for the role's settings | "Keyring couldn't read this role's PIM settings, so it asks for a reason and offers up to" 8 hours. PIM checks the request either way |
| You asked for longer than PIM allows | "PIM allows this role for up to" the maximum. "Pick a shorter time." Nothing is sent to Azure |
| PIM wants you to confirm it's you | Keyring sends you to sign in with the challenge and back to the form |
| The role is already on | The role "was already on", "so nothing was changed" |
| An eligibility starts later | **Eligible** shows when it starts, with no **Activate** |
| You asked for the same role on the same vault within the hour | **You've already asked**. "Keyring sends one request for each role and vault an hour." Nothing more is sent |
| You have 10 requests from the last hour, across every vault and role | **You've already asked**, and nothing is sent until an hour has passed since one of them |
| You can't see the vault in your vault list | The request page says it isn't found, and nothing is sent. Ask for Reader first |
| The reason is too short or too long | "Give a reason of 5 to 200 characters." |
| The ticket doesn't fit | "Leave the ticket empty, or give one that matches" the pattern, or, with no pattern set, "Use up to 64 characters with no spaces." |

## What is recorded

`role.activate` when you turn a role on (with the role, where, how long, and your reason and ticket), and `role.deactivate` when you turn it off. `access.request` when you send a request, with the role, the scope, your reason and ticket. A request over the hourly limit is `access.request` with `outcome` `refused` and `reason_code` `rate_limited`. The **Access** and **My access** pages write nothing.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| Turned on, but still "You don't have access" | Key Vault can take a few minutes to see a new role. Wait a minute and select **Try again** |
| A button stays disabled after the role is on | The hint is kept for five minutes. Wait, or post the form anyway: Key Vault decides |
| Object IDs instead of names | Keyring doesn't look up names. Select the ID to open it in the Azure portal |
| No **Request access** on the page | Requests are off in your Keyring, or the page offered **Activate** instead. Ask whoever looks after the vault for the role |
| You sent a request and nothing happened | Keyring keeps no request and grants nothing. Ask the vault's owners directly, and check **My access** once they say it is done |

## Related walkthroughs

- [00 About these walkthroughs](00-about.md)
- [12 Notifications people receive](12-notifications.md)
- [14 Access review report](14-access-review.md)

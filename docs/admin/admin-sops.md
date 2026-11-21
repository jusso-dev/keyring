# Keyring administrator SOPs

These standard operating procedures cover the routine and incident tasks of the people who run Keyring after it is deployed. Each one says what it is for, when to run it, who runs it and with which Azure or Entra role, what to have ready, the numbered steps and how to check the result.

Settings and template parameters are described once, in the README (Configuration) and [deploy.md](../deploy.md). The people who use Keyring have their own guide, the [walkthroughs](../guides/00-about.md).

## Rules for every SOP

- Replace each placeholder in angle brackets with your own value: `<vault>`, `<resource group>`, `<object id>`, `<subscription id>`, `<name>`, `<config vault>`, `<workspace>`. Never paste a secret value, token or key into a command you keep, a ticket or a chat.
- Keyring has no access of its own to any vault. Never give Keyring's managed identity, or its app registration, a role on a vault or a Key Vault access policy.
- Keyring's own calls (the federated credential, the audit sink and email) use its managed identity. Don't add a client secret, access key, connection string or second identity for them.
- The Event Grid webhook is protected by Event Grid's Entra token and an app role. Don't add a shared secret, a key in the URL or another way in.
- Run commands from a shell that doesn't save history, or clear it afterwards.
- Every test in Keyring runs against mock Azure services. Where a step has only been confirmed against those mocks, the SOP says "Not yet confirmed on a real tenant" and names the row in [real-vault-checklist.md](../real-vault-checklist.md). Record what you see in that row when you run it.

## Document control

| Item | Value |
| --- | --- |
| Version | 1.2 |
| Date | 21-11-2026 |
| Owner | Keyring maintainer |
| Review | After any release that changes deployment, settings or email |
| Status | Draft |

## Contents

1. [Onboard a vault](#1-onboard-a-vault)
2. [Give people access, and take it away](#2-give-people-access-and-take-it-away)
3. [Rotate Keyring's client secret, or move to the managed identity](#3-rotate-keyrings-client-secret-or-move-to-the-managed-identity)
4. [Rotate the session secret](#4-rotate-the-session-secret)
5. [Set up the audit sink and confirm rows arrive](#5-set-up-the-audit-sink-and-confirm-rows-arrive)
6. [Connect Microsoft Sentinel and respond to a Keyring alert](#6-connect-microsoft-sentinel-and-respond-to-a-keyring-alert)
7. [Set up email through Azure Communication Services](#7-set-up-email-through-azure-communication-services)
8. [Set up Event Grid expiry delivery to the webhook](#8-set-up-event-grid-expiry-delivery-to-the-webhook)
9. [Turn on step-up and the reason gate](#9-turn-on-step-up-and-the-reason-gate)
10. [Turn on permanent deletes, and turn them back off](#10-turn-on-permanent-deletes-and-turn-them-back-off)
11. [Daily and weekly health checks](#11-daily-and-weekly-health-checks)
12. [Upgrade Keyring](#12-upgrade-keyring)
13. [Remove Keyring](#13-remove-keyring)
14. [Run the real-tenant checklist](#14-run-the-real-tenant-checklist)
15. [Turn on sharing](#15-turn-on-sharing)
16. [Organise vaults into environment groups](#16-organise-vaults-into-environment-groups)

---

## 1. Onboard a vault

**Purpose.** Make a vault ready to use through Keyring: Azure RBAC, audit logs, people's roles through groups, and owner tags.

**When to run.** When a team asks to use Keyring with a vault, or a new vault is made.

**Who.** The vault's owner, with Owner, or User Access Administrator plus Contributor, on the vault or its resource group.

**Before you start.**

- The vault name, its resource group, and the Log Analytics workspace its audit logs should go to.
- An Entra group for each kind of access (readers, secrets officers, and so on), such as `kv-<vault>-secrets-officers`. Use groups, not people.
- The owners' addresses.

**Steps.**

1. Check the vault uses Azure RBAC. If it uses access policies, plan the move with the vault's users first, then switch it:

   ```sh
   az keyvault update -g <resource group> -n <vault> --enable-rbac-authorization true
   ```

2. Turn on soft delete (on by default for new vaults) and purge protection, unless the vault must allow permanent deletes:

   ```sh
   az keyvault update -g <resource group> -n <vault> --enable-purge-protection true
   ```

   Purge protection can't be turned off once on.

3. Send the vault's audit logs to Log Analytics:

   ```sh
   az monitor diagnostic-settings create --name keyvault-audit \
     --resource $(az keyvault show -n <vault> --query id -o tsv) \
     --workspace <workspace resource id> \
     --logs '[{"categoryGroup":"audit","enabled":true}]'
   ```

4. Give each group its role on the vault. For example:

   ```sh
   VAULT_ID=$(az keyvault show -n <vault> --query id -o tsv)
   az role assignment create --role "Key Vault Secrets Officer" \
     --assignee-object-id <group object id> --assignee-principal-type Group --scope "$VAULT_ID"
   az role assignment create --role "Reader" \
     --assignee-object-id <group object id> --assignee-principal-type Group --scope "$VAULT_ID"
   ```

   Pick roles from the README's role table. Give Reader too, so people see the vault in Keyring's list. Give Log Analytics Reader on the workspace to those who need the audit pages. Use PIM eligible assignments for officer roles where your organisation uses PIM.

5. Set the vault's owners:

   ```sh
   az tag update --resource-id "$VAULT_ID" --operation merge \
     --tags keyring-owners=<owner address>,<team address>
   ```

6. Ask the vault's teams to set **Owner** and **Notify** on their items in Keyring (walkthrough 03), or in bulk (walkthrough 07).

**Verification.**

- Open Keyring's **Vault health** and pick the vault: **Audit logs**, **Azure RBAC**, **Soft delete** and **Owners** pass.
- **Vaults** shows the owners and "On" under **Audit logs**.
- A member of each group can open the vault in Keyring. Role changes can take a few minutes.
- Keyring's own managed identity has no role on the vault: `az role assignment list --scope "$VAULT_ID" --assignee <Keyring identity principal id>` prints `[]`.

---

## 2. Give people access, and take it away

**Purpose.** Add, change and remove people's access to vaults when they join, move or leave.

**When to run.** On each joiner, mover or leaver, and on each access review.

**Who.** Whoever manages the groups (Groups Administrator or the group's owner in Entra ID), or User Access Administrator on the vault for direct assignments.

**Before you start.** The person's object ID or sign-in name, and the groups for each vault.

**Steps.**

1. Joiner: add the person to the vault's groups:

   ```sh
   az ad group member add --group <group object id> --member-id <object id>
   ```

2. Mover: add them to the new groups, then remove them from the old ones:

   ```sh
   az ad group member remove --group <group object id> --member-id <object id>
   ```

3. Leaver: remove them from every Keyring vault group, and remove any direct assignment:

   ```sh
   az role assignment list --all --assignee <object id> \
     --query "[?contains(scope, 'Microsoft.KeyVault')].{role:roleDefinitionName, scope:scope}" -o table
   az role assignment delete --assignee <object id> --role "<role>" --scope <scope>
   ```

4. Remove PIM eligible assignments for them in PIM (**Azure resources**, the vault or resource group, **Assignments**).

5. For a leaver, have a User Administrator revoke their sign-in sessions in Entra ID (`az rest --method POST --uri https://graph.microsoft.com/v1.0/users/<object id>/revokeSignInSessions`). A Keyring session ends after an hour without activity, or 12 hours after sign-in. Role removals take effect at Key Vault within a few minutes, whatever Keyring's session.

**Verification.**

- Open **Access** on each vault in Keyring: the person (by object ID) is listed, or no longer listed, as expected.
- For a leaver, run **Activity by one person** on **Audit** for the last 30 days and keep the CSV with the leaver record.

---

## 3. Rotate Keyring's client secret, or move to the managed identity

**Purpose.** Replace the client secret Keyring uses to prove it is its app registration before it expires, or stop using a client secret at all.

**When to run.** Before `KEYRING_CLIENT_SECRET_EXPIRES`, when a health email says "Keyring's client secret expires soon", when someone who saw it leaves, or once to move to the managed identity.

**Who.** An owner of Keyring's app registration (or Application Administrator in Entra ID), with Key Vault Secrets Officer on Keyring's config vault and Contributor on Keyring's resource group.

**Before you start.** With the managed identity already in use there is no client secret and nothing here applies.

**Steps to rotate the secret.**

1. In the app registration, **Certificates & secrets > New client secret**. Pick an expiry. The old secret keeps working meanwhile.

2. Put the new value in the config vault, with its expiry date:

   ```sh
   az keyvault secret set --vault-name <config vault> --name entra-client-secret \
     --value '<new value>' --expires '<expiry, such as 2027-05-01T00:00:00Z>'
   ```

3. Set `KEYRING_CLIENT_SECRET_EXPIRES` to the same date (`YYYY-MM-DD`) in your parameters, and redeploy (SOP 12, step 3), or restart:

   ```sh
   az webapp restart -g <resource group> -n <name>
   az containerapp revision restart -g <resource group> -n <name> --revision <active revision>
   ```

   Everyone is signed out.

4. Sign in to Keyring. Then delete the old secret in the app registration.

**Steps to move to the managed identity.** Follow deploy.md, "Moving an existing deployment to the managed identity": add the federated credential for Keyring's identity to the app registration, redeploy with `useFederatedCredential=true` (on Container Apps, first with `keepClientSecretEntry=true`, then again with `false`), check sign-in, then delete the client secret from the app registration and `entra-client-secret` from the config vault. Leave the app registration with delegated permissions only.

**Verification.**

- Sign-in works.
- `/healthz` says `ok`.
- With a secret: the config vault's `entra-client-secret` shows its new expiry on Keyring's **Expiry** page.
- With the managed identity: the app registration has no client secrets, and `ENTRA_CLIENT_SECRET` isn't set.

Not yet confirmed on a real tenant: sign-in with the federated credential. See "Sign-in" and "On-behalf-of" in the checklist's "Sign-in and tokens" section.

---

## 4. Rotate the session secret

**Purpose.** Replace `SESSION_SECRET`, which encrypts short-lived cookies.

**When to run.** When someone who could read it leaves, when it may have been exposed, or on your rotation schedule.

**Who.** Key Vault Secrets Officer on Keyring's config vault, and Contributor on Keyring's resource group.

**Before you start.** Pick a quiet time: the restart signs everyone out.

**Steps.**

1. Set a new value:

   ```sh
   az keyvault secret set --vault-name <config vault> --name session-secret --value "$(openssl rand -base64 48)"
   ```

2. Restart Keyring (as in SOP 3, step 3).

**Verification.**

- `/healthz` says `ok` and you can sign in.
- Keyring's audit events after the restart carry a different `session_ref` for the same person, since it is keyed from this secret.

---

## 5. Set up the audit sink and confirm rows arrive

**Purpose.** Send Keyring's own audit events to the `KeyringAudit_CL` table in a Log Analytics workspace, and give people the **Keyring activity** view.

**When to run.** Once, or when moving the table to another workspace.

**Who.** Contributor on Keyring's resource group, and Owner or User Access Administrator on the workspace's resource group (the template assigns Monitoring Metrics Publisher on the data collection rule).

**Before you start.** The workspace's resource ID. It can be in any resource group or subscription you can deploy to.

**Steps.**

1. Set `auditWorkspaceId` to the workspace's resource ID in your parameters. Optionally set `auditRetentionInDays` and `auditRequired`.

2. Redeploy Keyring (SOP 12, step 3). The template makes the table, a data collection rule of kind `Direct`, and Monitoring Metrics Publisher on that one rule for Keyring's managed identity.

3. Give the people who should read **Keyring activity** Log Analytics Reader on the workspace.

4. Sign in to Keyring and reveal a test secret in a test vault.

**Verification.**

- `/healthz/audit` shows `status=ok`, with `sent` rising.
- Within a few minutes:

  ```kusto
  KeyringAudit_CL
  | where TimeGenerated > ago(1h) and Action == "secret.reveal"
  | project TimeGenerated, ActorUpn, ActorObjectId, Vault, ItemName, Outcome, WriterIdentityClientId
  ```

  shows your reveal, naming you, with `WriterIdentityClientId` naming Keyring's managed identity.
- The vault's audit page in Keyring has **Keyring activity**, showing the reveal.

Not yet confirmed on a real tenant: rows arriving, the `Direct` rule, and degraded on a lost role. See "Audit sink rows arrive", "Audit sink with no data collection endpoint" and "Audit sink degraded on a lost role" in the checklist's "Deployment" section, and "Keyring activity view" in "Expiry and audit".

---

## 6. Connect Microsoft Sentinel and respond to a Keyring alert

**Purpose.** Add the parser, rules, hunting queries and workbook for `KeyringAudit_CL`, and handle an incident one raises.

**When to run.** Once SOP 5 is done and Sentinel is on for the workspace. Respond whenever an incident is raised.

**Who.** Microsoft Sentinel Contributor and Log Analytics Contributor on the workspace, and Workbook Contributor. Responders need Microsoft Sentinel Responder.

**Before you start.** The workspace name, the table your vaults log to (`AzureDiagnostics` or `AZKVAuditLogs`), and Keyring's outbound IP addresses if you want the two rules that compare with Key Vault's log.

**Steps to deploy.**

1. Copy and fill in the parameters:

   ```sh
   cp infra/sentinel/main.example.bicepparam infra/sentinel/main.bicepparam
   # Edit: workspaceName, keyVaultTable, keyringOutboundIps, and the enable... switches you want.
   az deployment group create -g <workspace resource group> \
     -f infra/sentinel/main.bicep -p infra/sentinel/main.bicepparam
   ```

   Every rule is created turned off unless its `enable...` parameter is `true`. Leave `enableUnmatchedSecretGet` off until its checklist row passes.

2. Check the parser with Microsoft's testers, as in sentinel.md.

**Steps to respond.**

1. Open the incident. Note the Account (object ID and sign-in name), the IP address and the rule.
2. In Keyring, run **Activity by one person** for that person, and open **Keyring activity** on the vaults named.
3. Ask the person whether it was them. If not, or for a forged request (`csrf`, `cross_site`): revoke their sessions in Entra ID, remove their access (SOP 2) and rotate anything they read.
4. Close the incident with what you found.

**Verification.** In Sentinel: the parsers `vimAuditEventKeyring` and `ASimAuditEventKeyring`, six hunting queries, the "Keyring audit" workbook, and the rules you turned on.

Not yet confirmed on a real tenant: every Sentinel step. See the "Sentinel:" rows in the checklist's "Deployment" section.

---

## 7. Set up email through Azure Communication Services

**Purpose.** Let Keyring send email notices, as its managed identity, through Azure Communication Services (ACS).

**When to run.** Once, before turning on any email notice.

**Who.** Owner, or User Access Administrator plus Contributor, on Keyring's resource group (the template creates a custom role and assigns it). For a custom domain, whoever manages its DNS.

**Before you start.**

- Choose `AzureManaged` (for a trial: low limits) or your own domain, such as `mail.example.com`.
- The admins' addresses, and the domains email may go to.

**Steps.**

1. Set the parameters: `notifyDomain`, `notifyTypes` (for example `health`), `notifyAdmins` and `notifyAllowedDomains`. Redeploy Keyring (SOP 12, step 3).

   The template makes the email resources in Keyring's resource group and gives Keyring's identity a role holding only Read and Write on the one Communication Services resource. No access key or connection string is used or output. Don't add one.

2. For your own domain: in the portal, open the Email Communication Service, the domain, **Provision domains**, and add the TXT, SPF and two DKIM records it shows, then **Verify** each. Add a DMARC record as your mail policy says.

3. To send emails to people as well as admins, add the types you want to `notifyTypes`, separated by commas, and redeploy:

   - `access-requests`: **Request access** on the "You don't have access" page and on My access, emailed to the vault's `keyring-owners` or the admins (walkthrough 10). Keyring grants nothing.
   - `watched-reads`: an email to an item's `notify` addresses when its value is revealed, its private key downloaded, it is copied to another vault or rolled back. At most 4 an hour per item.
   - `destructive`: deletes, permanent deletes and bulk changes, to the vault's owners or the admins.
   - `role-use`: PIM roles turned on or off through Keyring, to the vault's owners or the admins, and to the admins as well for a role above the vault.

   **Set `notifyAllowedDomains` before you turn `watched-reads` on.** Anyone who can write an item's tags can put any address in `notify`, then read the item to send that address mail. With allowed domains set, Keyring emails only those domains, and only then does a watched-read email show the address the reader came from.

   To send watched-read emails to the item's `owner` as well, set `KEYRING_NOTIFY_OWNER_ON_READ=true`. The host templates have no parameter for it, and a setting added by hand is removed by the next deployment, so set it again after each redeploy:

   ```sh
   az webapp config appsettings set -g <resource group> -n <name> --settings KEYRING_NOTIFY_OWNER_ON_READ=true
   az containerapp update -g <resource group> -n <name> --set-env-vars KEYRING_NOTIFY_OWNER_ON_READ=true
   ```

4. Make sure each onboarded vault has its `keyring-owners` tag (SOP 1, step 5). Without it, access requests, deletes, bulk changes and role use go to the admins.

5. Send a test health email: set `KEYRING_NOTIFY_BURST_THRESHOLD` to `3` for the test, then, as someone with no role on a test vault, try to show a secret there four times. The admins get "Many refused requests in a short time". Set the threshold back afterwards. This is the checklist row "Health email: refusal burst link".

**Verification.**

- `/healthz/notify` shows `status=ok`, and `delivered` rises after a send.
- The email arrives from `DoNotReply@<your domain>`, subject `[Keyring] Health`, and its headers show `dkim=pass` and `spf=pass` for a custom domain.
- `KeyringAudit_CL` (if on) has a `notify.sent` row with no address in it.
- With `access-requests` on: as a test person with no role on a test vault, open a secret there, select **Request access** and **Send request**. The vault's owners get `[Keyring] Access request` and the test person gets their own copy.
- With `watched-reads` on: put a test address in a test secret's **Notify**, reveal it, and the address gets `[Keyring] Watched item read`.

Not yet confirmed on a real tenant: every email step. See the "Email", "The two-action role is enough to send" and "Activity email:" rows in the checklist's "Deployment" section, and its "Access requests" section.

---

## 8. Set up Event Grid expiry delivery to the webhook

**Purpose.** Send a vault's near-expiry and expired events to Keyring, so Keyring emails them.

**When to run.** For each vault that should get expiry emails from Keyring, after SOP 7.

**Who.** For the one-off Entra steps (once per tenant): an owner of Keyring's app registration, or Application Administrator. For each vault: Contributor (or EventGrid Contributor) on the vault's resource group, and, while you create the subscription, the `AzureEventGridSecureWebhookSubscriber` app role on Keyring's service principal (removed again afterwards).

**Before you start.**

- `expiry` in `notifyTypes` and Keyring running at a public address (Event Grid can't reach a private one).
- Optionally a storage container for dead-lettering.

**Steps.**

1. Do the one-off Entra steps in [alerts.md](../alerts.md), "One-off Entra steps": the app role on Keyring's registration, Event Grid's service principal, and the role for Event Grid. Use placeholders such as `<Keyring's ENTRA_CLIENT_ID>`; never a secret.

2. Check whether the vault already has an Event Grid system topic, as alerts.md shows, and note its name.

3. Copy and fill in the parameters, then deploy:

   ```sh
   cp infra/alerts/keyring.example.bicepparam infra/alerts/keyring.bicepparam
   # Edit: vaultName, keyringBaseUrl, entraAudience, keyringRecipients,
   # deadLetterContainerId and existingSystemTopicName.
   az deployment group create --resource-group <vault resource group> \
     --template-file infra/alerts/main.bicep --parameters infra/alerts/keyring.bicepparam
   ```

4. Remove your own app role assignment, as alerts.md shows. Event Grid's stays.

5. Check `KEYRING_EVENTGRID_SUBSCRIPTIONS`, the list of Azure subscriptions whose vaults may send events to Keyring. The host templates set it from `eventGridSubscriptions`, which defaults to the subscription Keyring is deployed in, when `expiry` is in `notifyTypes`. If the vault is in another subscription, add that subscription's ID and redeploy Keyring (SOP 12, step 3):

   ```
   eventGridSubscriptions = '<Keyring subscription id>,<vault subscription id>'
   ```

   IDs are separated by commas, at most 50. An entry that isn't a GUID, an empty entry (such as a trailing comma) or more than 50 stops Keyring at start, naming the setting. An empty value is the same as unset: Keyring then accepts a vault in any subscription and warns at start. Don't leave it empty.

   An event from a vault in a subscription that isn't listed refuses the whole delivery with 400 and `reason_code` `subscription_not_allowed`, and Event Grid dead-letters it if a container is set. See alerts.md, "Which subscriptions may send".

**Verification.**

- The subscription `expiry-to-keyring` shows **Succeeded** in the portal.
- Keyring's audit has a `notify.webhook` event with `reason_code` `validation`.
- Set a test secret's expiry a few minutes ahead in a test vault: one email per event arrives, subject `[Keyring] Expiry: secret <name> in <vault>`, and audit shows `notify.webhook` with `queued` and a `notify.sent`.
- Keyring's start-up log has no warning that `KEYRING_EVENTGRID_SUBSCRIPTIONS` is unset.

Not yet confirmed on a real tenant: every webhook step. See "Event Grid delivers with Entra auth", "The claims Event Grid's token carries", "An expiry email arrives", "Which `aud` form arrives", "The `topic` a Key Vault event carries" and "A vault in an unlisted subscription is refused" in the checklist's "Deployment" section.

---

## 9. Turn on step-up and the reason gate

**Purpose.** Ask for a fresh or stronger sign-in before sensitive actions, and a reason (and ticket) before values are shown or anything is changed.

**When to run.** When your organisation decides to, usually piloted with one group first.

**Who.** Conditional Access Administrator (or Security Administrator) in Entra ID for the authentication context and policy; Contributor on Keyring's resource group to redeploy.

**Before you start.** Entra ID P1 for an authentication context. The ticket pattern, if you use one, such as `(INC|CHG)[0-9]{7}`.

**Steps.**

1. In the Entra admin centre, **Protection > Conditional Access > Authentication contexts**, select **New authentication context**, name it (such as "Read secret values"), tick **Publish to apps**, and note its ID (`c1` to `c99`).

2. Make a Conditional Access policy targeting that context, with the grant you want (for example phishing-resistant MFA). Start it in **Report-only**.

3. Set `stepUpAuthContext` to the ID, and optionally `stepUpMaxAge` (minutes since the last sign-in).

4. Set `requireReason` to `reveal` (values and private keys) or `all` (every change too), and optionally `reasonTicketPattern`.

5. Redeploy Keyring (SOP 12, step 3). A bad value stops Keyring at start rather than turning the check off.

6. Check the sign-in logs, then turn the policy on.

**Verification.**

- Show a test secret's value in Keyring as someone in the policy: Keyring shows **Confirm it's you**, you sign in again, and come back to the same step. Keyring's log has `step_up_required`, then `session.sign_in`, then `secret.reveal`.
- The **Value** panel asks for **Reason** (and **Ticket**). The `secret.reveal` event carries them.

These are Keyring's checks, not Key Vault's: the Azure CLI and portal aren't limited. For a hard control, also apply Conditional Access to Azure Key Vault itself.

Not yet confirmed on a real tenant: the step-up round trip. See the four "Step-up:" rows in the checklist's "Sign-in and tokens" section, and "Reason in the workspace" and "Reason and step-up together" in "Deployment".

---

## 10. Turn on permanent deletes, and turn them back off

**Purpose.** Allow **Permanently delete** in Keyring for a set time, for example to destroy secrets a policy says must go.

**When to run.** Only when a permanent delete is needed and approved. Turn it off again straight after.

**Who.** Contributor on Keyring's resource group. The person deleting needs the officer role for the item.

**Before you start.** The approval, and the list of items. Vaults with purge protection can't be purged before their retention period ends, whatever Keyring allows.

**Steps.**

1. Set `allowPurge = true` and redeploy (SOP 12, step 3). Keyring's home page says "Permanent deletes are turned on for this Keyring."
2. Have the approved person delete and permanently delete each item (walkthrough 02).
3. Set `allowPurge = false` and redeploy.

**Verification.**

- The home page no longer shows the notice.
- Audit (across vaults) **Deletes, purges and recoveries** lists only the approved purges, and Keyring's events show `secret.purge`, `certificate.purge` or `key.purge` for each.
- A purge tried afterwards shows **Permanent delete is turned off**, with `reason_code` `purge_disabled`.

---

## 11. Daily and weekly health checks

**Purpose.** Catch a failing audit sink, failing email, expiring credentials and badly set up vaults before they matter.

**When to run.** The daily checks each working day; the weekly ones each week.

**Who.** The Keyring operator. Reader on the vaults, and Log Analytics Reader on Keyring's workspace.

**Before you start.** Keyring's address.

**Daily steps.**

1. Open `/healthz`, `/healthz/audit` and `/healthz/notify`. Each should say `ok` (or `status=off` where not used). A 503 means degraded: follow the health email's advice, or SOP 5 or 7.
2. Read any `[Keyring] Health` email: sink failing or recovered, many refused requests, client secret expiring.
3. Open Keyring's **Expiry** page for **Expired** and **Next 7 days**, and tell the owners.

**Weekly steps.**

1. Open **Vault health** and work through **What to look at**.
2. Run **Refused requests** across vaults for the last 7 days, and look at anyone unexpected.
3. Check Keyring's own config vault on **Expiry**: `entra-client-secret` (if used) shouldn't be close to expiry.
4. Check the image digest is still the release you meant to run (SOP 12).
5. With sharing on (SOP 15) and no PIM licensing: open the access review (walkthrough 14) on each vault and look for **Overdue share**. Ask the sharer to revoke it, or revoke it yourself.

**Verification.** Record the date and anything found in your operations log.

Set an availability test or alert on `/healthz/audit` and `/healthz/notify` so a degraded state is noticed without email. Not yet confirmed on a real tenant: the health emails. See "Health email: audit sink failing" and "Health email: refusal burst link" in the checklist's "Deployment" section.

---

## 12. Upgrade Keyring

**Purpose.** Run a new Keyring version.

**When to run.** For a security fix as soon as possible; otherwise on your change schedule.

**Who.** Contributor on Keyring's resource group, and push rights on your registry if you build the image.

**Before you start.**

- Read CHANGELOG.md for new settings, changed settings and anything that needs a template rerun (such as new audit table columns).
- Pick a quiet time: the restart signs everyone out.

**Steps.**

1. Build and push the image by digest, or take a published release's digest and check its attestation:

   ```sh
   gh attestation verify oci://ghcr.io/jusso-dev/keyring@sha256:<digest> --repo jusso-dev/keyring
   ```

2. Set `image` to `<registry>/keyring@sha256:<digest>` in your parameters.

3. Preview, then deploy:

   ```sh
   az deployment group what-if -g <resource group> -f infra/<app-service or container-apps>/main.bicep -p <your parameters file>
   az deployment group create -g <resource group> -f infra/<app-service or container-apps>/main.bicep -p <your parameters file>
   ```

**Verification.**

- `/healthz` says `ok`; sign in and open a vault.
- The running image's `org.opencontainers.image.revision` label is the commit you expected.
- `/healthz/audit` and `/healthz/notify` are as before.

---

## 13. Remove Keyring

**Purpose.** Take Keyring away cleanly.

**When to run.** When Keyring is retired.

**Who.** Owner on Keyring's resource group, an owner of its app registration, and the workspace's owner for the audit table and Sentinel content.

**Before you start.** Export what must be kept: `KeyringAudit_CL` rows for your retention period, and the audit reports you need.

**Steps.**

1. Delete each vault's `expiry-to-keyring` Event Grid subscription (alerts.md, "Turn it off").
2. Delete the Sentinel rules, saved searches and workbook (sentinel.md, "Deploy").
3. Delete Keyring's resource group, or the resources deploy.md lists. The config vault has purge protection, so its name stays reserved for 90 days.
4. Delete the audit sink's data collection rule and, once its data is exported, the `KeyringAudit_CL` table from the workspace's resource group.
5. Delete Keyring's app registration, including its federated credentials, and the `AzureEventGridSecureWebhookSubscriber` role assignment for Event Grid.

**Verification.**

- Keyring's address no longer answers.
- `az ad app list --display-name <name>` prints nothing.
- No role assignment names Keyring's identity: `az role assignment list --all --assignee <Keyring identity principal id>` prints `[]` (or the identity is gone).

---

## 14. Run the real-tenant checklist

**Purpose.** Confirm on a real tenant and real vaults what Keyring's tests only check against mock Azure services.

**When to run.** After the first deployment, after any release that changes sign-in, Azure calls, deployment or email, and before relying on a feature marked "not yet confirmed on a real tenant".

**Who.** An administrator with a test tenant or test resource group: Key Vault Administrator on two test vaults, Reader on their resource group, and the roles each section asks for (PIM needs Entra ID P2 or Governance).

**Before you start.**

- Two test vaults: one Standard with soft delete and no purge protection, one with purge protection. Nothing in them that matters: some rows delete, purge or disable.
- Test people: one with each role the rows name.

**Steps.**

1. Open [real-vault-checklist.md](../real-vault-checklist.md) and pick the sections you need.
2. For each row, do what it says and compare with "Expected".
3. Write the result in the row's **Result** column: `ok`, or what Azure actually did. Keep tenant IDs, object IDs, names and messages that identify your tenant out of it.
4. Where a result differs, open an issue naming the row, and change the mock in `tests/support/` to match, with a test.
5. Add a line to **Record of runs** with the date (DD-MM-YYYY), who, the Keyring commit and notes.
6. Run the automated rows where you can (see [real-vault-automation.md](../real-vault-automation.md)).
7. Delete and purge the test vaults afterwards.

**Verification.** The rows you ran have a result, and a pull request with the updated checklist (and any mock fixes) is open.

---

## 15. Turn on sharing

**Purpose.** Let people share one secret with a colleague or a security group until a date, from the secret's page (walkthrough 16).

**When to run.** When your organisation decides people may share single secrets through Keyring. Pilot it on a test vault first.

**Who.** An owner of Keyring's app registration and a Privileged Role Administrator (or Global Administrator) in Entra ID to grant admin consent; Contributor on Keyring's resource group to change its settings; Microsoft Sentinel Contributor on the workspace for the alert rule.

**Before you start.**

- Know whether your tenant has Entra ID P2 (PIM). It decides whether shares end by themselves (see below).
- Decide the longest a share may last, from 1 to 365 days. The default is 30.
- Turn on step-up and the reason gate first (SOP 9), so a share needs the same confirmation and reason as a reveal.

**What a share is.** Keyring gives the person or group the Key Vault Secrets User role on that one secret, as the person sharing, with their own token. Only someone Azure lets create a role assignment on the secret can share: Owner, User Access Administrator, or Key Vault Data Access Administrator (which can be limited by a condition to assigning only Key Vault Secrets User). Keyring's managed identity makes no assignment and needs no new permission. Keyring stores nothing about shares.

- **With PIM licensing**, a share is a PIM assignment with an end date, and Azure removes the access at the end of that day.
- **Without PIM licensing**, Keyring makes a plain role assignment. Azure does NOT remove it on the end date. Keyring shows it as **Overdue** on the secret's **Shared with** section and in the access review until someone revokes it.
- **When a PIM setting refuses the request** (multifactor sign-in, a shorter time, a ticket), the share is refused. There is no fallback to a plain assignment.

**Steps.**

1. In Keyring's app registration, open **API permissions > Add a permission > Microsoft Graph > Delegated permissions**, and add `User.ReadBasic.All` and `GroupMember.Read.All`. Or run:

   ```sh
   az ad app permission add --id <Keyring's ENTRA_CLIENT_ID> --api 00000003-0000-0000-c000-000000000000 \
     --api-permissions <User.ReadBasic.All permission id>=Scope <GroupMember.Read.All permission id>=Scope
   ```

2. Select **Grant admin consent for** your tenant. `GroupMember.Read.All` needs admin consent. Keyring calls Graph as the signed-in person, so they find only who they could find themselves. Without consent, the picker says so and people can't be picked.

3. Set `KEYRING_SHARING=true`, and `KEYRING_SHARE_MAX_DAYS` if you want other than 30. To email the person shared with and the sharer, add `shares` to `notifyTypes` and redeploy (SOP 12, step 3). The host templates have no parameter for the two sharing settings, and a setting added by hand is removed by the next deployment, so set them again after each redeploy:

   ```sh
   az webapp config appsettings set -g <resource group> -n <name> \
     --settings KEYRING_SHARING=true KEYRING_SHARE_MAX_DAYS=<days>
   az containerapp update -g <resource group> -n <name> \
     --set-env-vars KEYRING_SHARING=true KEYRING_SHARE_MAX_DAYS=<days>
   ```

   A `KEYRING_SHARE_MAX_DAYS` outside 1 to 365 stops Keyring at start.

4. Recommended: check step-up (`stepUpAuthContext` or `stepUpMaxAge`) and `requireReason` (`reveal` or `all`) are set (SOP 9). Sharing then asks for the same confirmation and reason as a reveal.

5. Turn on the Sentinel rule `rules/shares.kql` (SOP 6): set `enableShares = true`, and optionally `shareThreshold` (default 5) and `shareWindowMinutes` (default 60), and redeploy `infra/sentinel`. It alerts on a share to a guest account, or more than `shareThreshold` shares by one person in the window. It needs the audit sink (SOP 5).

6. Tell the vault owners: without PIM licensing, shares stay until revoked. Add a check for **Overdue** shares to the access review (walkthrough 14) and the weekly checks (SOP 11).

**Verification.**

- A secret's page on an RBAC vault has **Share** and a **Shared with** section. A vault on access policies has no **Share**.
- As a test person with User Access Administrator on a test vault, share a test secret with a second test person until tomorrow. The page says which way it was made. In the portal, the secret's **Access control (IAM)** shows one Key Vault Secrets User assignment at the secret's scope.
- The second person can read the value. After **Revoke**, they can't (Azure can take a few minutes).
- Keyring's audit has `share.grant` and `share.revoke`, and `KeyringAudit_CL` (if on) has the same.
- As someone with only Key Vault Secrets Officer, a share is refused naming the roles that can share.

Not yet confirmed on a real tenant: every sharing step, including the PIM end date, the plain fallback, revoke, the Graph search with and without consent, and the guest alert. See the "Sharing a secret" section of [real-vault-checklist.md](../real-vault-checklist.md).

---

## 16. Organise vaults into environment groups

**Purpose.** Tag each workload's Key Vaults (`dev`, `test`, `staging`, `prod`) so Keyring's **Environments** matrix and **Across environments** panel group them automatically in promotion order.

**When to run.** When onboarding a workload with multiple environments, or migrating folders from Delinea Secret Server onto per-environment Key Vaults.

**Who.** The vault or resource group owner (Contributor or Tag Contributor on each vault).

**Before you start.**

- The list of Key Vault resource IDs for one workload (for example `kv-payments-dev`, `kv-payments-test`, `kv-payments-prod`).
- The agreed workload name (e.g. `payments`) and environment names (`dev`, `test`, `uat`, `staging`, `preprod`, `prod`, `dr`).
- Separate Entra ID security groups per environment so non-production officers do not hold standing write access in production.

**Steps.**

1. Tag each vault with its workload group and environment label:

   ```sh
   for pair in "kv-payments-dev:dev" "kv-payments-test:test" "kv-payments-prod:prod"; do
     vault="${pair%%:*}"
     env="${pair##*:}"
     VAULT_ID=$(az keyvault show -n "$vault" --query id -o tsv)
     az tag update --resource-id "$VAULT_ID" --operation merge \
       --tags app=payments env="$env"
   done
   ```

   Keyring also recognises `keyring-group`, `application`, `service`, `workload` and `system` for the group, and `keyring-env`, `environment` and `stage` for the environment. Vaults following `<prefix>-<env>` naming are grouped automatically even before tags are added.

2. Verify least-privilege RBAC across the environments:
   - Grant the engineering team **Key Vault Reader** (names and properties only) across `dev`, `test` and `prod` so they can spot missing or drifting secrets in **Environments** without viewing production values.
   - Grant **Key Vault Secrets Officer** directly on `dev` and `test`, and as a **PIM eligible** role (with approval) on `prod`.

3. Ask the workload owner to review parity in Keyring's **Environments** page (`/environments`) and archive a baseline **Download CSV** parity report.

**Verification.**

- **Vaults** shows the **Environment** badge on each vault (`prod` highlighted).
- **Environments** displays the workload tab with vaults ordered `dev` -> `test` -> `prod`.
- Opening any secret in `kv-payments-dev` shows the **Across environments** panel with `kv-payments-test` and `kv-payments-prod`.
- A developer without `prod` Secrets Officer who uses **Set across environments** sees `dev` and `test` succeed and `prod` cleanly reported as **Refused** with a link to **My access**.

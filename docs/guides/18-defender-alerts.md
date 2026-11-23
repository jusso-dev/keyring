# Defender alerts

This walkthrough shows how to see what Microsoft Defender for Key Vault has noticed on the vaults you can see: which subscriptions it watches, and the alerts it raised when a vault was used in an unusual way, such as secrets listed and read in bulk or access from a suspicious address.

## Who this is for

| To do this | Azure role | Where |
| --- | --- | --- |
| See the vaults and subscriptions on the page | Reader | Each vault, its resource group or subscription |
| See whether Defender for Key Vault is on, and its alerts | Security Reader (or Reader) | Each subscription |
| Dismiss or resolve an alert | Security Admin | In Defender for Cloud, not in Keyring |

## Before you start

- Defender for Key Vault is a plan in Microsoft Defender for Cloud. It only raises alerts on subscriptions where whoever looks after Defender for Cloud has turned the Key Vault plan on.
- Keyring reads the plan and the alerts from Azure Resource Graph, as you. It changes nothing and writes no audit event.

## Steps

1. Select **Defender alerts** in the left menu, under **Across vaults**.

   **Coverage** lists each subscription your vaults are in, how many of those vaults you can see, and whether **Defender for Key Vault** is **On**, **Off** or **Unknown**. Unknown has the reason beside it, for example that Resource Graph returned no plan for that subscription.

2. Read the notice above the table if there is one: "Defender for Key Vault is off on 1 subscription. Nothing watches those vaults for unusual access." Pass it on to whoever looks after Defender for Cloud.

3. Read **Alerts**. By default it lists open alerts (Active or In progress), newest first, with:

   | Column | What it shows |
   | --- | --- |
   | **Alert** | Microsoft's title for it, and its type, such as `KV_ListGetAnomaly` |
   | **Severity** | High, Medium, Low or Informational |
   | **Status** | Active, In progress, Resolved or Dismissed |
   | **Vault** | The vault it is about, linked when you can see the vault |
   | **When** | When Defender raised it, in UTC |
   | **Tactic** | The MITRE ATT&CK tactic Defender gives, such as `CredentialAccess` |
   | **Open in Azure** | The alert in the Azure portal, with Defender's full details and remediation steps |

4. Narrow the list with **Vault**, **Severity** and **Status**, then select **Apply**. Pick **Open, resolved and dismissed** in **Status** to see closed alerts from the last 90 days as well.

5. Select **Download CSV** for a spreadsheet of the alerts you're looking at.

6. Select **Open in Azure** on an alert to investigate it, and dismiss or resolve it there once you know what happened. If the alert means a secret may have been read by the wrong person, set a new value for it in Keyring.

## Where else Defender shows

- **Home**: a **Defender alerts** tile with the open alerts and how many vaults are unprotected, and a table of the most urgent open alerts.
- **Vault health**: the **Defender for Key Vault** check warns when the plan is off or the vault has open alerts. See [09 Vault health](09-vault-health.md).
- **Executive reports**: a "Defender for Key Vault on" control, open alerts in each vault's risk, remediation actions, and a Defender row in the CSV.

## What Keyring checks

| Check | What you see |
| --- | --- |
| You don't have Security Reader or Reader on the subscription | "Couldn't read Defender's alerts" with the reason, and "This isn't the same as having none." The CSV has a `NOT READ` line |
| A subscription has no plan Keyring can read | **Unknown**, with the reason, never On |
| More than 1,000 open alerts | Keyring says it couldn't read them all and points you to Defender for Cloud, rather than showing a short count |
| An alert's text contains odd characters or a link | Alert titles and entities come from whoever set the alert off, so they're shown as plain text. Only links to the Azure portal are kept |

## What is recorded

Nothing. The Defender alerts page and its CSV write no audit event.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| Every subscription says **Unknown** | Ask for Security Reader on the subscriptions, or check that Defender for Cloud has been set up there |
| No alerts, but you expected some | Check that the Key Vault plan is **On** for that subscription. Alerts can take a few hours to appear after the activity that causes them |
| An alert has no vault | Defender didn't name one Keyring could read. It's shown under its subscription, and **Open in Azure** has the details |

Not yet confirmed on a real tenant: the alert fields and the plan rows. See "Defender: plan row", "Defender: sample alerts" and "Defender: without Security Reader" in the checklist's "Expiry and audit" section.

## Related walkthroughs

- [09 Vault health](09-vault-health.md)
- [11 Audit](11-audit.md)
- [15 For auditors](15-auditors.md)

# App registration credentials

Keyring doesn't show or manage the client secrets and certificates on Entra app registrations and service principals. The expiry dashboard covers secrets, certificates and keys in Key Vault only.

## Why not

Those credentials live in Microsoft Entra ID, not in Key Vault. Reading them needs a Microsoft Graph permission (`Application.Read.All`, which needs admin consent). Keyring asks for no Graph permission at all: it signs in as you and only calls Resource Manager (with Resource Graph), Key Vault and Log Analytics. Adding Graph would widen what Keyring can read across the whole tenant, for every person who uses it, so it is left out on purpose. See the threat model in [architecture.md](architecture.md).

## What to use instead

### Entra's recommendations

Entra has two recommendations, **Renew expiring application credentials** and **Renew expiring service principal credentials**. They list credentials that expire within the next 30 days, with a link to each app's **Certificates & secrets** page.

- Find them in the Microsoft Entra admin centre under **Entra ID** > **Overview** > **Recommendations**.
- Reading them needs Reports Reader, Security Reader or Global Reader.
- They only look 30 days ahead. Microsoft's sample response lists a Workload ID licence (`microsoftEntraWorkloadId`), so check whether your tenant has them.

Microsoft's docs: [Renew expiring application credentials](https://learn.microsoft.com/entra/identity/monitoring-health/recommendation-renew-expiring-application-credential), [Renew expiring service principal credentials](https://learn.microsoft.com/entra/identity/monitoring-health/recommendation-renew-expiring-service-principal-credential).

### SAML signing certificate emails

For enterprise apps that use SAML single sign-on, Entra sends an email 60, 30 and 7 days before the signing certificate expires. Set up to five addresses on the app's **Single sign-on** > **SAML Certificates** section. Use a distribution list if more people need it. Check the addresses in the admin centre: Microsoft notes the emails might not be sent if the SAML settings were only set through Graph or PowerShell and never opened there.

Microsoft's docs: [Manage federation certificates](https://learn.microsoft.com/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on#add-email-notification-addresses-for-certificate-expiration).

### A one-off query

To see every app registration's credentials and their end dates at once, run this with the Azure CLI. It only reads, and prints each credential's key ID, name and end date. It never prints a secret value or the first characters of one (`hint`).

```sh
az ad app list --all --query "[].{app: displayName, appId: appId, secrets: passwordCredentials[].{keyId: keyId, name: displayName, ends: endDateTime}, certificates: keyCredentials[].{keyId: keyId, name: displayName, ends: endDateTime}}" --output json
```

- Without `--all`, the CLI returns only the first 100 apps.
- By default, any member user in the tenant can list app registrations, so no directory role is needed. Guests, and members in a tenant that has restricted default permissions, need Directory Readers or Global Reader.
- It covers credentials on app registrations, which is where Microsoft recommends keeping them. Credentials added straight to a service principal, such as SAML signing certificates, aren't listed. The recommendations and emails above cover those.
- Keep the output to yourself. App names and IDs describe your tenant.

Microsoft's docs: [az ad app list](https://learn.microsoft.com/cli/azure/ad/app#az-ad-app-list), [passwordCredential](https://learn.microsoft.com/graph/api/resources/passwordcredential), [keyCredential](https://learn.microsoft.com/graph/api/resources/keycredential), [default user permissions](https://learn.microsoft.com/entra/fundamentals/users-default-permissions).

### Better: no secret to expire

The surest fix is a credential that can't expire unnoticed:

- **Managed identities** for workloads that run in Azure. Azure handles the credential.
- **Federated credentials** (workload identity federation) for GitHub Actions, Kubernetes and other platforms. The app trusts the platform's tokens, so there is no secret or certificate to store or rotate.

Keyring does this for itself: it can prove itself to Entra with its managed identity instead of a client secret (see the README, [step 2, option B](../README.md#option-b-managed-identity-azure-deployments-nothing-to-rotate)).

Microsoft's docs: [Managed identities](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview), [Workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation).

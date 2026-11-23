# Enterprise Terraform Packaging for Keyring

Modular Terraform (`>= 1.6`, `azurerm ~> 4.0`, `azapi ~> 2.0`, optional `azuread ~> 3.0`) mirroring the security invariants of Keyring's Bicep templates in `infra/`:

- **Zero standing user-vault roles:** Keyring's user-assigned managed identity only receives `Key Vault Secrets User` on its own config vault, `Monitoring Metrics Publisher` on its own audit DCR (when enabled), and the two-action ACS email sender role on its own Communication Services resource (when enabled).
- **No secrets in Terraform state:** `session-secret` (and `entra-client-secret` if not using federated credentials) are never Terraform variables or resources; populate them directly in the config vault after deployment.
- **Schema parity enforced by tests:** `tests/audit_events.rs` verifies that `modules/audit-sink/main.tf` defines the exact same `KeyringAudit_CL` column schema as `src/audit/sink.rs` and `infra/modules/audit-sink.bicep`.

## Layout

| Path | What it provisions |
| --- | --- |
| `modules/config-vault/` | Config Key Vault (RBAC, 90-day soft delete, purge protection, optional private endpoint) + user-assigned managed identity |
| `modules/audit-sink/` | `KeyringAudit_CL` custom Log Analytics table, Direct DCR, and `Monitoring Metrics Publisher` role |
| `modules/notify/` | Azure Communication Services email + two-action custom sender role (no access keys) |
| `modules/entra-app/` | Single-tenant Entra ID app registration (`api://<client_id>/access_as_user`, delegated permissions only, redirect URIs, optional federated credential for Keyring's managed identity) |
| `stacks/container-apps/` | Enterprise Azure Container Apps deployment (internal/external ingress, VNet, zone redundancy, private DNS, audit sink, ACS email) |
| `stacks/app-service/` | Enterprise Azure App Service (Linux container) deployment (VNet integration, inbound & config-vault private endpoints, zone redundancy, ARR affinity, diagnostic logs) |
| `stacks/vm/` | Enterprise Azure VM / Confidential VM deployment (Trusted Launch or AMD SEV-SNP Confidential VM, private VNet NIC, NSG, IMDS managed identity, Compute Gallery image or Azure Linux 3.0) |

## Quick start (Container Apps)

```sh
cd infra/terraform/stacks/container-apps
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars (never committed; .gitignore skips *.tfvars)

terraform init
# First pass: create the config vault and managed identity
terraform apply -var="config_only=true"

# Set session-secret in the config vault (and add the federated credential in Entra)
az keyvault secret set --vault-name <config_vault_name> --name session-secret --value "$(openssl rand -base64 48)"

# Second pass: deploy the Container App
terraform apply
```

## Optional: automate the Entra ID app registration

Call `modules/entra-app` from your identity/platform Terraform workspace:

```hcl
module "keyring_entra_app" {
  source = "git::https://github.com/jusso-dev/keyring.git//infra/terraform/modules/entra-app?ref=v1.0.0"

  display_name                  = "Keyring"
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  app_base_urls                 = ["https://keyring.example.com"]
  enable_sharing                = false
  managed_identity_principal_id = module.keyring.identity_principal_id
}
```

Then open the `admin_consent_url` output as a tenant administrator to grant delegated consent.

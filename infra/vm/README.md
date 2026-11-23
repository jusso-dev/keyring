# Keyring on Azure Virtual Machines (Trusted Launch & Confidential VM)

This directory packages Keyring for organisations that require VM-based hosting (Azure Compute Gallery golden images, VNet-only air-gapped estates, Azure Marketplace VM offers, or **Azure Confidential VMs** with AMD SEV-SNP encrypted memory to protect in-memory OBO sessions from host-level inspection).

## Contents

| Path | Purpose |
| --- | --- |
| `main.bicep` | Enterprise Azure VM deployment template (Trusted Launch or Confidential VM, private VNet NIC with no public IP, locked-down NSG, config Key Vault, user-assigned managed identity, optional audit sink & ACS email) |
| `main.example.bicepparam` | Example Bicep parameters |
| `packer/keyring.pkr.hcl` | Packer template that bakes a hardened Azure Linux 3.0 Gen2 image into an Azure Compute Gallery |
| `packer/keyring.pkrvars.hcl.example` | Example Packer variables |
| `systemd/keyring.service` | Hardened `systemd` unit (unprivileged `keyring` user, `ProtectSystem=strict`, `MemoryDenyWriteExecute=true`, zero Linux capabilities) |
| `scripts/fetch-config-secrets.sh` | `ExecStartPre` helper that fetches `session-secret` (and `entra-client-secret` when not using federated credentials) from the config vault via IMDS into RAM-only tmpfs (`/run/keyring/secrets.env`), never writing secrets to disk |
| `cloud-init.yaml` | Standalone cloud-init reference |

## How Managed Identity Works on a VM

On App Service and Container Apps, Azure injects `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`. On an Azure VM, Keyring uses the Instance Metadata Service (IMDS) by setting:

```env
KEYRING_MANAGED_IDENTITY_MODE=imds
KEYRING_MANAGED_IDENTITY_CLIENT_ID=<user-assigned-identity-client-id>
```

Keyring then calls `http://169.254.169.254/metadata/identity/oauth2/token` (`api-version=2018-02-01`, `Metadata: true`) strictly for its own federated client assertion, audit sink ingestion and ACS email. The VM's managed identity holds **zero** roles on any user Key Vault.

## Building an Azure Compute Gallery Image with Packer

1. Extract the static `linux/amd64` `keyring` binary from a verified release image (or compile with `cargo build --release --target x86_64-unknown-linux-musl`):

   ```sh
   cid=$(docker create --platform linux/amd64 ghcr.io/jusso-dev/keyring@sha256:<digest>)
   docker cp "$cid:/keyring" ./keyring-linux-amd64
   docker rm "$cid"
   ```

2. Create a Compute Gallery and Gen2 image definition:

   ```sh
   az sig create -g rg-images --gallery-name sig_keyring -l australiaeast
   az sig image-definition create -g rg-images --gallery-name sig_keyring \
     --gallery-image-definition keyring \
     --publisher Keyring --offer keyring --sku azure-linux-3-gen2 \
     --os-type Linux --os-state Generalized --hyper-v-generation V2 \
     --features SecurityType=TrustedLaunchAndConfidentialVmSupported
   ```

3. Build and publish the image version:

   ```sh
   cd infra/vm/packer
   cp keyring.pkrvars.hcl.example keyring.pkrvars.hcl
   packer init .
   packer validate -var-file=keyring.pkrvars.hcl .
   packer build -var-file=keyring.pkrvars.hcl .
   ```

4. Deploy the VM via Bicep (`infra/vm/main.bicep`) or Terraform (`infra/terraform/stacks/vm/`), passing the gallery image version ID, and put a TLS-terminating Azure Application Gateway or Front Door Private Link in front of port `3000`.

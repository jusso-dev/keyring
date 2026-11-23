# Packer template: build a hardened Azure Linux 3.0 (Gen2) VM image for
# Keyring and publish it to an Azure Compute Gallery (ready for direct VM
# deployments, VMSS, Confidential VMs or Azure Marketplace VM offers).
#
# Prerequisites:
#   - Packer >= 1.11 with the azure plugin (`packer init .`)
#   - A pre-built static linux/amd64 Keyring binary (e.g. extracted from the
#     attested ghcr.io/jusso-dev/keyring@sha256:... image or `cargo build
#     --release --target x86_64-unknown-linux-musl`)
#   - An existing Azure Compute Gallery and Gen2 image definition
#     (HyperVGeneration = V2, SecurityType = TrustedLaunchSupported or
#     ConfidentialVMSupported)
#
# Usage:
#   cp keyring.pkrvars.hcl.example keyring.pkrvars.hcl
#   packer init .
#   packer validate -var-file=keyring.pkrvars.hcl .
#   packer build -var-file=keyring.pkrvars.hcl .

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    azure = {
      source  = "github.com/hashicorp/azure"
      version = "~> 2.2"
    }
  }
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID hosting the build and Compute Gallery."
}

variable "location" {
  type        = string
  default     = "australiaeast"
  description = "Azure region for the temporary build VM."
}

variable "gallery_resource_group" {
  type        = string
  description = "Resource group containing the Azure Compute Gallery."
}

variable "gallery_name" {
  type        = string
  description = "Azure Compute Gallery name."
}

variable "image_name" {
  type        = string
  default     = "keyring"
  description = "Image definition name inside the Compute Gallery."
}

variable "image_version" {
  type        = string
  default     = "1.0.0"
  description = "SemVer image version (MAJOR.MINOR.PATCH) for the gallery."
}

variable "replication_regions" {
  type        = list(string)
  default     = ["australiaeast"]
  description = "Azure regions to replicate the Compute Gallery image version to."
}

variable "keyring_binary_path" {
  type        = string
  description = "Local path to the verified static linux/amd64 keyring binary."
}

variable "security_type" {
  type        = string
  default     = "TrustedLaunch"
  description = "TrustedLaunch or ConfidentialVM (must match the gallery image definition)."
}

variable "vm_size" {
  type        = string
  default     = "Standard_DC2as_v5"
  description = "Build VM size (DCas_v5 supports both TrustedLaunch and ConfidentialVM)."
}

source "azure-arm" "keyring" {
  use_azure_cli_auth = true
  subscription_id    = var.subscription_id
  location           = var.location
  vm_size            = var.vm_size

  os_type         = "Linux"
  image_publisher = "MicrosoftCBLMariner"
  image_offer     = "azure-linux-3"
  image_sku       = "azure-linux-3-gen2"
  image_version   = "latest"

  security_type      = var.security_type
  secure_boot_enabled = true
  vtpm_enabled       = true

  shared_image_gallery_destination {
    subscription        = var.subscription_id
    resource_group      = var.gallery_resource_group
    gallery_name        = var.gallery_name
    image_name          = var.image_name
    image_version       = var.image_version
    replication_regions = var.replication_regions
    storage_account_type = "Standard_ZRS"
  }

  azure_tags = {
    application = "keyring"
    version     = var.image_version
    managed_by  = "packer"
  }
}

build {
  name    = "keyring-azure-vm"
  sources = ["source.azure-arm.keyring"]

  provisioner "file" {
    source      = var.keyring_binary_path
    destination = "/tmp/keyring"
  }

  provisioner "file" {
    source      = "${path.root}/../systemd/keyring.service"
    destination = "/tmp/keyring.service"
  }

  provisioner "file" {
    source      = "${path.root}/../scripts/fetch-config-secrets.sh"
    destination = "/tmp/fetch-config-secrets.sh"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E sh '{{ .Path }}'"
    inline = [
      "set -eu",
      # Update OS packages and ensure curl + python3 + ca-certificates are present.
      "tdnf -y update",
      "tdnf -y install ca-certificates curl python3",
      # Create dedicated non-login service account.
      "id -u keyring >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin keyring",
      # Install static binary (read + execute only, owned by root).
      "install -D -m 0555 -o root -g root /tmp/keyring /usr/local/bin/keyring",
      "rm -f /tmp/keyring",
      # Install tmpfs config-vault secret fetcher (owned by root, executable by keyring).
      "install -D -m 0550 -o root -g keyring /tmp/fetch-config-secrets.sh /usr/local/libexec/keyring/fetch-config-secrets.sh",
      "rm -f /tmp/fetch-config-secrets.sh",
      # Prepare /etc/keyring (populated at boot by cloud-init / customData; no secrets).
      "install -d -m 0750 -o root -g keyring /etc/keyring",
      # Install hardened systemd service (enabled; waits for /etc/keyring/keyring.env).
      "install -D -m 0644 -o root -g root /tmp/keyring.service /etc/systemd/system/keyring.service",
      "rm -f /tmp/keyring.service",
      "systemctl daemon-reload",
      "systemctl enable keyring.service",
      # Harden SSH defaults and disable password auth.
      "printf 'PasswordAuthentication no\\nPermitRootLogin no\\nX11Forwarding no\\n' > /etc/ssh/sshd_config.d/99-keyring-hardening.conf",
      # Clean package caches and generalize image for Azure Compute Gallery.
      "tdnf clean all",
      "/usr/sbin/waagent -force -deprovision+user && export HISTSIZE=0 && sync"
    ]
  }
}

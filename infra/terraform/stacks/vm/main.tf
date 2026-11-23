data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

locals {
  location         = var.location != "" ? var.location : data.azurerm_resource_group.this.location
  tenant_id        = var.tenant_id != "" ? var.tenant_id : data.azurerm_client_config.current.tenant_id
  use_audit_sink   = var.audit_workspace_id != ""
  use_notify       = var.notify_domain != ""
  is_confidential  = var.security_type == "ConfidentialVM"
  notify_types_set = [for t in split(",", lower(var.notify_types)) : trimspace(t)]
  has_expiry       = contains(local.notify_types_set, "expiry")
  eg_subs          = var.eventgrid_subscriptions != "" ? var.eventgrid_subscriptions : data.azurerm_client_config.current.subscription_id

  env_lines = compact(concat(
    [
      "ENTRA_TENANT_ID=${local.tenant_id}",
      "ENTRA_CLIENT_ID=${var.client_id}",
      "APP_BASE_URL=${var.app_base_url}",
      "KEYRING_LISTEN=0.0.0.0:3000",
      "KEYRING_ALLOW_PURGE=${tostring(var.allow_purge)}",
      "KEYRING_TRUSTED_PROXY_HOPS=${tostring(var.trusted_proxy_hops)}",
      "KEYRING_MANAGED_IDENTITY_MODE=imds",
      "KEYRING_MANAGED_IDENTITY_CLIENT_ID=${module.config_vault.identity_client_id}",
      "KEYRING_CONFIG_VAULT_URI=${module.config_vault.vault_uri}",
      "KEYRING_USE_FEDERATED_CREDENTIAL=${tostring(var.use_federated_credential)}",
      var.api_scope != "" ? "ENTRA_API_SCOPE=${var.api_scope}" : "",
      var.log_level != "" ? "KEYRING_LOG_LEVEL=${var.log_level}" : "",
      var.log_format != "" ? "KEYRING_LOG_FORMAT=${var.log_format}" : "",
      var.stale_after_days > 0 ? "KEYRING_STALE_AFTER_DAYS=${tostring(var.stale_after_days)}" : "",
      var.expiry_warn_days > 0 ? "KEYRING_EXPIRY_WARN_DAYS=${tostring(var.expiry_warn_days)}" : "",
      var.step_up_auth_context != "" ? "KEYRING_STEP_UP_AUTH_CONTEXT=${var.step_up_auth_context}" : "",
      var.step_up_max_age > 0 ? "KEYRING_STEP_UP_MAX_AGE=${tostring(var.step_up_max_age)}" : "",
      var.require_reason != "" ? "KEYRING_REQUIRE_REASON=${var.require_reason}" : "",
      var.reason_ticket_pattern != "" ? "KEYRING_REASON_TICKET_PATTERN=${var.reason_ticket_pattern}" : "",
      var.password_policy != "" ? "KEYRING_PASSWORD_POLICY=${var.password_policy}" : "",
      var.require_owner ? "KEYRING_REQUIRE_OWNER=true" : "",
      var.sharing ? "KEYRING_SHARING=true" : "",
      var.share_max_days > 0 ? "KEYRING_SHARE_MAX_DAYS=${tostring(var.share_max_days)}" : "",
    ],
    local.use_audit_sink ? [
      "KEYRING_AUDIT_INGESTION_ENDPOINT=${module.audit_sink[0].ingestion_endpoint}",
      "KEYRING_AUDIT_DCR_ID=${module.audit_sink[0].rule_immutable_id}",
      "KEYRING_AUDIT_STREAM=${module.audit_sink[0].stream_name}",
      "KEYRING_AUDIT_REQUIRED=${tostring(var.audit_required)}",
      "KEYRING_AUDIT_WORKSPACE_ID=${var.audit_workspace_id}",
    ] : [],
    local.use_notify ? [
      "KEYRING_NOTIFY_ACS_ENDPOINT=${module.notify[0].endpoint}",
      "KEYRING_NOTIFY_SENDER=${module.notify[0].sender_address}",
      var.notify_types != "" ? "KEYRING_NOTIFY_TYPES=${var.notify_types}" : "",
      var.notify_admins != "" ? "KEYRING_NOTIFY_ADMINS=${var.notify_admins}" : "",
      var.notify_allowed_domains != "" ? "KEYRING_NOTIFY_ALLOWED_DOMAINS=${var.notify_allowed_domains}" : "",
      local.has_expiry && local.eg_subs != "" ? "KEYRING_EVENTGRID_SUBSCRIPTIONS=${local.eg_subs}" : "",
      local.has_expiry && var.eventgrid_audience != "" ? "KEYRING_EVENTGRID_AUDIENCE=${var.eventgrid_audience}" : "",
    ] : []
  ))

  cloud_init = <<-EOT
    #cloud-config
    write_files:
      - path: /etc/keyring/keyring.env
        owner: root:keyring
        permissions: "0640"
        content: |
          ${join("\n      ", local.env_lines)}
    runcmd:
      - systemctl daemon-reload
      - systemctl enable --now keyring.service
  EOT
}

module "config_vault" {
  source = "../../modules/config-vault"

  resource_group_name        = data.azurerm_resource_group.this.name
  location                   = local.location
  vault_name                 = var.config_vault_name
  identity_name              = "${var.name}-id"
  disable_public_access      = var.config_vault_private_endpoint_subnet_id != ""
  private_endpoint_subnet_id = var.config_vault_private_endpoint_subnet_id
  private_dns_zone_id        = var.vault_private_dns_zone_id
  tags                       = var.tags
}

module "audit_sink" {
  count  = local.use_audit_sink ? 1 : 0
  source = "../../modules/audit-sink"

  workspace_id                = var.audit_workspace_id
  workspace_resource_group_id = var.audit_workspace_resource_group_id != "" ? var.audit_workspace_resource_group_id : data.azurerm_resource_group.this.id
  location                    = var.audit_workspace_location != "" ? var.audit_workspace_location : local.location
  rule_name                   = "${var.name}-audit"
  identity_principal_id       = module.config_vault.identity_principal_id
  retention_in_days           = var.audit_retention_in_days
  tags                        = var.tags
}

module "notify" {
  count  = local.use_notify ? 1 : 0
  source = "../../modules/notify"

  resource_group_name   = data.azurerm_resource_group.this.name
  resource_group_id     = data.azurerm_resource_group.this.id
  name                  = var.name
  notify_domain         = var.notify_domain
  data_location         = var.notify_data_location
  identity_principal_id = module.config_vault.identity_principal_id
  tags                  = var.tags
}

resource "azurerm_network_security_group" "this" {
  name                = "${var.name}-nsg"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.this.name
  tags                = var.tags

  security_rule {
    name                       = "AllowKeyringHttpFromProxy"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3000"
    source_address_prefix      = var.allowed_proxy_source_prefix
    destination_address_prefix = "VirtualNetwork"
  }

  security_rule {
    name                       = "AllowAzureLoadBalancerProbe"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3000"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllOtherInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "this" {
  name                = "${var.name}-nic"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.this.name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "this" {
  network_interface_id      = azurerm_network_interface.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = "${var.name}-vm"
  location                        = local.location
  resource_group_name             = data.azurerm_resource_group.this.name
  size                            = var.vm_size
  zone                            = var.availability_zone != "" ? var.availability_zone : null
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.this.id]
  custom_data                     = base64encode(local.cloud_init)
  secure_boot_enabled             = true
  vtpm_enabled                    = true
  encryption_at_host_enabled      = !local.is_confidential
  patch_mode                      = "AutomaticByPlatform"
  patch_assessment_mode           = "AutomaticByPlatform"
  source_image_id                 = var.gallery_image_id != "" ? var.gallery_image_id : null
  tags                            = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [module.config_vault.identity_id]
  }

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  os_disk {
    caching                  = "ReadWrite"
    storage_account_type     = "Premium_LRS"
    security_encryption_type = local.is_confidential ? var.confidential_disk_encryption_type : null
  }

  dynamic "source_image_reference" {
    for_each = var.gallery_image_id == "" ? [1] : []
    content {
      publisher = "MicrosoftCBLMariner"
      offer     = "azure-linux-3"
      sku       = "azure-linux-3-gen2"
      version   = "latest"
    }
  }

  boot_diagnostics {}
}

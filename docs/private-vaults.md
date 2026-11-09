# Private vaults

Many vaults turn off public access and only accept traffic through a private endpoint. Keyring can manage those vaults, but only if Keyring itself runs inside a network that can reach them.

## How it fits together

```
                         Your Azure network (VNet)
  +--------------------------------------------------------------------+
  |                                                                    |
  |   Keyring subnet                      Private endpoint subnet      |
  |  +--------------------+               +-------------------------+  |
  |  | App Service (VNet  |   HTTPS       | Private endpoint        |  |
  |  | integration) or    | ------------> | for kv-app-prod         |--+--> Key Vault
  |  | Container Apps env |  10.0.2.5     | 10.0.2.5                |  |    (public access off)
  |  +--------------------+               +-------------------------+  |
  |            |                                                       |
  |            | DNS: kv-app-prod.vault.azure.net                      |
  |            v                                                       |
  |   Private DNS zone privatelink.vaultcore.azure.net                 |
  |   (linked to this VNet): kv-app-prod -> 10.0.2.5                    |
  +--------------------------------------------------------------------+
               |
               | Entra ID sign-in, on-behalf-of and Resource Graph
               v   still go over the internet (or your egress path)
       login.microsoftonline.com, management.azure.com
```

Keyring still calls each vault as the signed-in person. The network only decides whether the call can reach the vault. Key Vault's own access rules still decide what that person can do.

## What you need

1. **Keyring in the VNet.**
   - App Service: set `vnetIntegrationSubnetId` in `infra/app-service/main.bicep` to a subnet delegated to `Microsoft.Web/serverFarms`. The template turns on "route all", so vault traffic goes through the VNet. Needs a Basic plan or above; the default `P0v3` works.
   - Container Apps: set `infrastructureSubnetId` in `infra/container-apps/main.bicep` to a subnet of at least /27 delegated to `Microsoft.App/environments`.
2. **A private endpoint for each vault**, in a subnet the Keyring subnet can route to. Vault owners usually have these already.
3. **Private DNS.** A private DNS zone `privatelink.vaultcore.azure.net` linked to Keyring's VNet, with a record for each vault's private endpoint. `infra/modules/private-dns.bicep` creates and links the zone; the private endpoint's DNS zone group adds the records. If your organisation runs DNS centrally (a hub VNet with forwarders), link the zone there instead.
4. **Outbound access to Entra ID and Azure Resource Manager**, either straight out or through your firewall: `login.microsoftonline.com` and `management.azure.com` on port 443.

Keyring's own config vault can be private too: set `configVaultPrivateEndpointSubnetId` and `vaultPrivateDnsZoneId` and the template turns off its public access.

## What people see when it isn't set up

Seeing a private vault in the vault list only needs Azure Resource Manager, which is still public. Opening it then fails to connect. Keyring shows **"Can't reach this vault"** and suggests asking an admin whether the vault has public access turned off.

If the vault has a firewall that allows some public addresses but not Keyring's, Key Vault answers with a 403 instead, and Keyring shows **"This vault is blocked from here"**. Either add Keyring's outbound address to the vault firewall, or use a private endpoint.

## Checking it works

From inside Keyring's network (for example the App Service console or a VM in the same VNet):

```sh
nslookup kv-app-prod.vault.azure.net
```

It should answer with a private address (10.x, 172.16 to 31.x or 192.168.x) via `kv-app-prod.privatelink.vaultcore.azure.net`. A public address means the DNS zone isn't linked to this VNet.

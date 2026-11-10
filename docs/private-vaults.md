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
               | Entra ID sign-in, on-behalf-of, Resource Graph, the audit
               | view and image pulls still go over the internet (or your
               v   egress path), on port 443
       login.microsoftonline.com, management.azure.com,
       api.loganalytics.io, your container registry
```

Keyring still calls each vault as the signed-in person. The network only decides whether the call can reach the vault. Key Vault's own access rules still decide what that person can do.

## What you need

1. **Keyring in the VNet.**
   - App Service: set `vnetIntegrationSubnetId` in `infra/app-service/main.bicep` to a subnet delegated to `Microsoft.Web/serverFarms`. The template turns on "route all", so vault traffic goes through the VNet. Needs a Basic (`B1`) plan or above; the default `P0v3` works too.
   - Container Apps: set `infrastructureSubnetId` in `infra/container-apps/main.bicep` to a subnet of at least /27 delegated to `Microsoft.App/environments`.
2. **A private endpoint for each vault**, in a subnet the Keyring subnet can route to. Vault owners usually have these already.
3. **Private DNS.** A private DNS zone `privatelink.vaultcore.azure.net` linked to Keyring's VNet, with a record for each vault's private endpoint. The private endpoint's DNS zone group adds the records. If your organisation runs DNS centrally (a hub VNet with forwarders), link the zone there instead, and skip this step if the zone already exists. Otherwise create and link it with `infra/modules/private-dns.bicep`, which the main templates don't call:

   ```sh
   az deployment group create -g <rg with your network> \
     --template-file infra/modules/private-dns.bicep \
     --parameters vnetId=<Keyring's VNet resource ID>
   ```

   Its `zoneId` output is the `vaultPrivateDnsZoneId` the main templates ask for, and the zone to put vault private endpoints in.
4. **Outbound access**, either straight out or through your firewall, on port 443:

   | Host | Why |
   | --- | --- |
   | `login.microsoftonline.com` | Sign-in, on-behalf-of and refresh, and the v2.0 sign-in metadata and signing keys Keyring reads at start |
   | `management.azure.com` | Vault list (Resource Graph) and the audit view's diagnostic settings |
   | `api.loganalytics.io` | Audit view queries |
   | `<vault>.vault.azure.net` | Vaults that are reached publicly, not through a private endpoint |
   | Your container registry, for example `<name>.azurecr.io` and `<name>.<region>.data.azurecr.io` | So the platform can pull the image on start and restart. Without it a restart fails |

   If you use an outbound proxy rather than routing, see the README, "Behind a proxy".

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

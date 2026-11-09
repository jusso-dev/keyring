// Private DNS zone for Key Vault private endpoints, linked to a VNet.
//
// Keyring needs this to reach vaults that only accept private traffic:
// with it, <vault>.vault.azure.net resolves to the private endpoint's
// address inside the VNet.

@description('VNet the zone is linked to (the one Keyring runs in).')
param vnetId string

@description('Zone name. The default is right for Azure public cloud.')
param zoneName string = 'privatelink.vaultcore.azure.net'

param tags object = {}

resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: zoneName
  location: 'global'
  tags: tags
}

resource link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zone
  name: 'keyring-vnet'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnetId
    }
  }
}

output zoneId string = zone.id

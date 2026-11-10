// Private DNS for an internal Container Apps environment.
//
// An internal environment's default domain (for example
// <random>.<region>.azurecontainerapps.io) has no public DNS record. This
// zone, linked to the VNet, resolves every name under it to the
// environment's private address.

@description('The environment\'s default domain.')
param zoneName string

@description('The environment\'s private address.')
param staticIp string

@description('VNet to link the zone to (the one people reach Keyring from, or the hub that forwards their DNS).')
param vnetId string

param tags object = {}

resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: zoneName
  location: 'global'
  tags: tags
}

resource wildcard 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: zone
  name: '*'
  properties: {
    ttl: 300
    aRecords: [
      {
        ipv4Address: staticIp
      }
    ]
  }
}

resource apex 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: zone
  name: '@'
  properties: {
    ttl: 300
    aRecords: [
      {
        ipv4Address: staticIp
      }
    ]
  }
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

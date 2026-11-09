// A private endpoint with its DNS record in a private DNS zone.

param location string
param name string

@description('Resource the endpoint connects to.')
param targetId string

@description('Sub-resource, for example vault or sites.')
param groupId string

param subnetId string

@description('Private DNS zone to register the endpoint in. Leave empty to manage DNS yourself.')
param privateDnsZoneId string = ''

param tags object = {}

resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: name
        properties: {
          privateLinkServiceId: targetId
          groupIds: [
            groupId
          ]
        }
      }
    ]
  }
}

resource dns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = if (!empty(privateDnsZoneId)) {
  parent: endpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'zone'
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

output id string = endpoint.id

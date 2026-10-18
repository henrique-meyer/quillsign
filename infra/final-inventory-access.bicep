targetScope = 'resourceGroup'

@description('Temporary, approved operator access. Remove the role assignment after inventory.')
param operatorObjectId string
param storageAccountName string

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageAccountName }
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = { parent: storage, name: 'default' }
resource final 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = { parent: blobs, name: 'final' }
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: final
  name: guid(final.id, operatorObjectId, 'temporary-inventory')
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
  }
}
output assignmentId string = reader.id

targetScope = 'resourceGroup'

@description('Run only after approved empty, lease-free inventory. Migrate with the explicit Azure operation afterward. Never lock this default policy.')
param storageAccountName string
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageAccountName }
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = { parent: storage, name: 'default' }
resource final 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = { parent: blobs, name: 'final' }
resource policy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: final
  name: 'default'
  properties: { immutabilityPeriodSinceCreationInDays: 1 }
}

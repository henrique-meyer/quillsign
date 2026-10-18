targetScope = 'resourceGroup'
param storageAccountName string
param workerIdentityName string
param purgeRecoveryJobName string
param versionCleanupRoleName string
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageAccountName }
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = { parent: storage, name: 'default' }
var documentContainers = ['originals', 'normalized', 'previews', 'checkpoints', 'final']
resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = [for name in documentContainers: { parent: blobs, name: name }]
resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: workerIdentityName }
resource recovery 'Microsoft.App/jobs@2025-07-01' existing = { name: purgeRecoveryJobName }
resource versionCleanupRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'document-version-cleanup')
  properties: {
    roleName: versionCleanupRoleName
    description: 'Delete document versions after approved application retention checks. No policy management.'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [{
      actions: []
      notActions: []
      dataActions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action']
      notDataActions: []
    }]
  }
}
resource workerVersionCleanup 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, i) in documentContainers: if (name != 'final') {
  scope: containers[i]
  name: guid(containers[i].id, worker.id, 'worker-version-cleanup')
  properties: {
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: versionCleanupRole.id
  }
}]

resource recoveryVersionCleanup 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, i) in documentContainers: {
  scope: containers[i]
  name: guid(containers[i].id, purgeRecoveryJobName, 'purge-recovery-versions')
  properties: {
    principalId: recovery.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: versionCleanupRole.id
  }
}]

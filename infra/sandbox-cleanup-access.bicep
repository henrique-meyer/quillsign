targetScope = 'resourceGroup'

@description('Existing approved dedicated sandbox group in this project resource group; supplied privately.')
param sandboxGroupName string
@description('Existing storage-only purge-recovery job; supplied privately.')
param purgeRecoveryJobName string

resource group 'Microsoft.App/sandboxGroups@2026-07-01' existing = { name: sandboxGroupName }
resource recovery 'Microsoft.App/jobs@2025-07-01' existing = { name: purgeRecoveryJobName }

// Azure's public built-in role. No operator grant, subscription-wide scope,
// new identity, sandbox, image, network, environment or service is provisioned.
var dataOwnerRole = 'c24cf47c-5077-412d-a19c-45202126392c'
resource cleanupAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: group
  name: guid(group.id, purgeRecoveryJobName, 'sandbox-cleanup', dataOwnerRole)
  properties: {
    principalId: recovery.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', dataOwnerRole)
  }
}

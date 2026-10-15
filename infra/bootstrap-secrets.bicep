targetScope = 'resourceGroup'

param vaultName string
param operatorObjectId string

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
// Temporary bootstrap grant. Remove this assignment after transferring credentials.
resource secretOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, operatorObjectId, 'temporary-secret-bootstrap')
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  }
}
output assignmentId string = secretOperator.id

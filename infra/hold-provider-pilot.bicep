targetScope = 'resourceGroup'

@description('Existing approved project storage account. This template does not modify its settings.')
param storageAccountName string

@description('Existing approved Entra user object ID. No identity or credential is created.')
param operatorPrincipalId string

@description('New private synthetic-only container. Execution must reject an existing name.')
@minLength(3)
@maxLength(63)
param validationContainerName string

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}
resource service 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = {
  parent: storage
  name: 'default'
}
resource proof 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: service
  name: validationContainerName
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: { enabled: true }
  }
}

// Data Owner is needed for the version-policy negative tests, not just writes.
// Limit this temporary assignment to the new, disposable container.
resource temporaryOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(proof.id, operatorPrincipalId, 'QUILS-147-provider-pilot')
  scope: proof
  properties: {
    principalId: operatorPrincipalId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
  }
}

output containerResourceId string = proof.id
output temporaryAssignmentResourceId string = temporaryOperator.id

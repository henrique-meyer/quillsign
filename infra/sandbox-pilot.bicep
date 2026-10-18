targetScope = 'resourceGroup'

@description('Owner-approved private name for the proposed converter sandbox group.')
param sandboxGroupName string

@description('Existing project deployment region, supplied privately.')
param location string

@description('Existing web managed-identity object ID, supplied privately after explicit approval.')
param webPrincipalId string

@description('Current operator object ID; temporary access removed after pilot.')
param operatorPrincipalId string

@description('Enable only for an approved pilot; remove this temporary grant after cleanup.')
param grantTemporaryOperatorAccess bool = false

// Deploy only after owner approval of a bounded pilot and its private parameters.
// The data-plane pilot must enforce one active sandbox, bounded 1 CPU/2 GiB,
// an operator-enforced 180-second deadline, deny-all/full-inspection egress, no public ports,
// two synthetic conversions maximum, and exact sandbox cleanup.
// GA ARM schema does not expose the limits shown in older preview quickstarts.
resource converterSandboxGroup 'Microsoft.App/sandboxGroups@2026-07-01' = {
  name: sandboxGroupName
  location: location
  tags: { project: 'QuillSign', purpose: 'converter-feasibility-pilot' }
  properties: {}
}

// Public Azure built-in role definition; this is not a project identity.
var sandboxDataRole = 'c24cf47c-5077-412d-a19c-45202126392c'
resource converterSandboxAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(converterSandboxGroup.id, webPrincipalId, sandboxDataRole)
  scope: converterSandboxGroup
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sandboxDataRole)
    principalId: webPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource temporaryOperatorSandboxAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (grantTemporaryOperatorAccess) {
  name: guid(converterSandboxGroup.id, operatorPrincipalId, sandboxDataRole)
  scope: converterSandboxGroup
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sandboxDataRole)
    principalId: operatorPrincipalId
    principalType: 'User'
  }
}

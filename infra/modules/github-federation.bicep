targetScope = 'resourceGroup'
param deploymentIdentityName string
@description('Exact subject from the GitHub production environment token; keep its private value in ignored parameters.')
param federationSubject string

resource deployment 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: deploymentIdentityName
}
resource federation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: deployment
  name: 'github-production'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: federationSubject
    audiences: [ 'api://AzureADTokenExchange' ]
  }
}

targetScope = 'resourceGroup'

@description('Supply exact existing deployment names through ignored parameters. This template creates no identities or role assignments.')
param location string
param environmentName string
param webAppName string
param dispatchJobName string
param runtimeIdentityName string
param workerIdentityName string
param image string
param revisionSuffix string
@description('Optional references to the existing send-only credentials. Supply both, or leave both empty.')
param sesAccessKeySecretUri string = ''
param sesSecretKeySecretUri string = ''
@secure()
@description('Captured existing web/dispatch configuration, template, tags and workloadProfileName. Only approved private environment deltas may be merged before deployment. Preserve all other values.')
param runtimeState object

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = { name: environmentName }
resource runtime 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: runtimeIdentityName }
resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: workerIdentityName }

var haveCredentials = !empty(sesAccessKeySecretUri) && !empty(sesSecretKeySecretUri)
var secretNames = ['ses-access-key', 'ses-secret-key']
var credentialEnvironment = haveCredentials ? [
  { name: 'AWS_ACCESS_KEY_ID', secretRef: 'ses-access-key' }
  { name: 'AWS_SECRET_ACCESS_KEY', secretRef: 'ses-secret-key' }
] : []
var credentialEnvironmentNames = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
var webSecrets = haveCredentials ? concat(filter(runtimeState.web.configuration.secrets, item => !contains(secretNames, item.name)), [
  { name: 'ses-access-key', keyVaultUrl: sesAccessKeySecretUri, identity: runtime.id }
  { name: 'ses-secret-key', keyVaultUrl: sesSecretKeySecretUri, identity: runtime.id }
]) : runtimeState.web.configuration.secrets
var dispatchSecrets = haveCredentials ? concat(filter(runtimeState.dispatch.configuration.secrets, item => !contains(secretNames, item.name)), [
  { name: 'ses-access-key', keyVaultUrl: sesAccessKeySecretUri, identity: worker.id }
  { name: 'ses-secret-key', keyVaultUrl: sesSecretKeySecretUri, identity: worker.id }
]) : runtimeState.dispatch.configuration.secrets
var webContainer = runtimeState.web.template.containers[0]
var dispatchContainer = runtimeState.dispatch.template.containers[0]
var replacedEnvironmentNames = concat(['Email__Enabled'], haveCredentials ? credentialEnvironmentNames : [])

resource web 'Microsoft.App/containerApps@2024-03-01' = {
  name: webAppName
  location: location
  tags: runtimeState.web.tags
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${runtime.id}': {} } }
  properties: {
    managedEnvironmentId: environment.id
    workloadProfileName: runtimeState.web.workloadProfileName
    configuration: union(runtimeState.web.configuration, { secrets: webSecrets })
    template: union(runtimeState.web.template, {
      revisionSuffix: revisionSuffix
      containers: [union(webContainer, {
        image: image
        env: concat(filter(webContainer.env, item => !contains(replacedEnvironmentNames, item.name)), credentialEnvironment, [{ name: 'Email__Enabled', value: 'false' }])
      })]
    })
  }
}

resource dispatch 'Microsoft.App/jobs@2025-07-01' = {
  name: dispatchJobName
  location: location
  tags: runtimeState.dispatch.tags
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${worker.id}': {} } }
  properties: {
    environmentId: environment.id
    workloadProfileName: runtimeState.dispatch.workloadProfileName
    configuration: union(runtimeState.dispatch.configuration, { secrets: dispatchSecrets })
    template: union(runtimeState.dispatch.template, {
      containers: [union(dispatchContainer, {
        image: image
        env: concat(filter(dispatchContainer.env, item => !contains(replacedEnvironmentNames, item.name)), credentialEnvironment, [{ name: 'Email__Enabled', value: 'false' }])
      })]
    })
  }
}

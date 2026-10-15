targetScope = 'resourceGroup'

param location string
param environmentName string
param storageAccountName string
param vaultName string
param dataProtectionKeyName string
param runtimeIdentityName string
param workerIdentityName string
param dispatchJobName string
param recoveryJobName string
param queueName string
param hintContainerName string
param image string
param databaseConnectionSecretUri string = ''
param deployJobs bool = false

var tags = { project: 'quillsign' }
resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = { name: environmentName }
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageAccountName }
resource runtime 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: runtimeIdentityName }
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
resource key 'Microsoft.KeyVault/vaults/keys@2023-07-01' existing = { parent: vault, name: dataProtectionKeyName }
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = { parent: storage, name: 'default' }
resource keys 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = { parent: blobs, name: 'keys' }
resource queues 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' existing = { parent: storage, name: 'default' }
resource queue 'Microsoft.Storage/storageAccounts/queueServices/queues@2023-05-01' = { parent: queues, name: queueName }
resource hints 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: hintContainerName
  properties: { publicAccess: 'None' }
}
resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: workerIdentityName
  location: location
  tags: tags
}
resource workerQueue 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: queue
  name: guid(queue.id, worker.id, 'worker-queue')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource appQueue 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: queue
  name: guid(queue.id, runtime.id, 'app-queue')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a')
    principalId: runtime.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource workerHints 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: hints
  name: guid(hints.id, worker.id, 'worker-hints')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource workerKeys 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keys
  name: guid(keys.id, worker.id, 'worker-keys')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource workerCrypto 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: key
  name: guid(key.id, worker.id, 'worker-key-encryption')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'e147488a-f6f5-4113-8e2d-b22465e65bf6')
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
resource workerSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, worker.id, 'worker-secrets')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

var signalEnvironment = [
  { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
  { name: 'Work__Enabled', value: 'true' }
  { name: 'Work__QueueServiceUri', value: storage.properties.primaryEndpoints.queue }
  { name: 'Work__QueueName', value: queueName }
  { name: 'Work__HintContainer', value: hintContainerName }
  { name: 'Storage__Provider', value: 'Azure' }
  { name: 'Storage__BlobServiceUri', value: storage.properties.primaryEndpoints.blob }
]
resource dispatch 'Microsoft.App/jobs@2025-07-01' = if (deployJobs) {
  name: dispatchJobName
  location: location
  tags: union(tags, { component: 'dispatch' })
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${worker.id}': {} } }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Event'
      replicaTimeout: 300
      replicaRetryLimit: 0
      secrets: [{ name: 'database-connection', keyVaultUrl: databaseConnectionSecretUri, identity: worker.id }]
      eventTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: 0
          maxExecutions: 1
          pollingInterval: 60
          rules: [{
            name: 'work-queue'
            type: 'azure-queue'
            identity: worker.id
            metadata: { accountName: storageAccountName, queueName: queueName, queueLength: '1', queueLengthStrategy: 'visibleonly' }
          }]
        }
      }
    }
    template: {
      containers: [{
        name: 'dispatch'
        image: image
        command: ['dotnet', 'QuillSign.dll', 'work', 'once']
        resources: { cpu: json('0.25'), memory: '0.5Gi' }
        env: concat(signalEnvironment, [
          { name: 'Storage__ManagedIdentityClientId', value: worker.properties.clientId }
          { name: 'ConnectionStrings__Database', secretRef: 'database-connection' }
          { name: 'DataProtection__ApplicationName', value: 'QuillSign:Production' }
          { name: 'DataProtection__KeyVaultKeyIdentifier', value: '${vault.properties.vaultUri}keys/${dataProtectionKeyName}' }
          { name: 'Email__Enabled', value: 'false' }
        ])
      }]
    }
  }
  dependsOn: [workerQueue, workerHints, workerKeys, workerCrypto, workerSecrets]
}

resource recovery 'Microsoft.App/jobs@2025-07-01' = if (deployJobs) {
  name: recoveryJobName
  location: location
  tags: union(tags, { component: 'work-recovery' })
  identity: { type: 'SystemAssigned' }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 60
      replicaRetryLimit: 0
      scheduleTriggerConfig: { cronExpression: '0 * * * *', parallelism: 1, replicaCompletionCount: 1 }
    }
    template: {
      containers: [{
        name: 'recovery'
        image: image
        command: ['dotnet', 'QuillSign.dll', 'work', 'recover']
        resources: { cpu: json('0.25'), memory: '0.5Gi' }
        env: signalEnvironment
      }]
    }
  }
}
resource recoveryHints 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployJobs) {
  scope: hints
  name: guid(hints.id, recoveryJobName, 'recovery-hints')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: recovery!.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
resource recoveryQueue 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployJobs) {
  scope: queue
  name: guid(queue.id, recoveryJobName, 'recovery-queue')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a')
    principalId: recovery!.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
output workerClientId string = worker.properties.clientId

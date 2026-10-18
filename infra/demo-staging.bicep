targetScope = 'resourceGroup'

param location string
param environmentName string
param storageAccountName string
param vaultName string
param dataProtectionKeyName string
param workerIdentityName string
param purgeRecoveryJobName string
param hintContainerName string
param queueName string
param image string

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = { name: environmentName }
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageAccountName }
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = { parent: storage, name: 'default' }
var documentContainers = ['originals', 'normalized', 'previews', 'checkpoints', 'final']
resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = [for name in documentContainers: { parent: blobs, name: name }]
resource hints 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = { parent: blobs, name: hintContainerName }
resource keys 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = { parent: blobs, name: 'keys' }
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
resource key 'Microsoft.KeyVault/vaults/keys@2023-07-01' existing = { parent: vault, name: dataProtectionKeyName }
resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: workerIdentityName }

// Ownership is required only for per-version final-policy operations. Other
// document containers permit ordinary worker reads/writes and bounded deletion.
resource workerDocuments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, i) in documentContainers: {
  scope: containers[i]
  name: guid(containers[i].id, worker.id, 'worker-document-staging')
  properties: {
    principalId: worker.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', name == 'final' ? 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b' : 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}]

resource recovery 'Microsoft.App/jobs@2025-07-01' = {
  name: purgeRecoveryJobName
  location: location
  tags: { project: 'quillsign', component: 'purge-recovery' }
  identity: { type: 'SystemAssigned' }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 90
      replicaRetryLimit: 0
      scheduleTriggerConfig: { cronExpression: '0 * * * *', parallelism: 1, replicaCompletionCount: 1 }
    }
    template: {
      containers: [{
        name: 'purge-recovery'
        image: image
        command: ['dotnet', 'QuillSign.dll', 'work', 'purge-recover', '32']
        resources: { cpu: json('0.25'), memory: '0.5Gi' }
        env: [
          { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
          { name: 'Work__Enabled', value: 'true' }
          { name: 'Work__QueueServiceUri', value: storage.properties.primaryEndpoints.queue }
          { name: 'Work__QueueName', value: queueName }
          { name: 'Work__HintContainer', value: hintContainerName }
          { name: 'Storage__Provider', value: 'Azure' }
          { name: 'Storage__BlobServiceUri', value: storage.properties.primaryEndpoints.blob }
          { name: 'DataProtection__ApplicationName', value: 'QuillSign:Production' }
          { name: 'DataProtection__KeyVaultKeyIdentifier', value: '${vault.properties.vaultUri}keys/${dataProtectionKeyName}' }
          { name: 'Email__Enabled', value: 'false' }
        ]
      }]
    }
  }
}
resource recoveryDocuments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, i) in documentContainers: {
  scope: containers[i]
  name: guid(containers[i].id, purgeRecoveryJobName, 'purge-recovery-documents')
  properties: {
    principalId: recovery.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}]
resource recoveryHints 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: hints
  name: guid(hints.id, purgeRecoveryJobName, 'purge-recovery-hints')
  properties: {
    principalId: recovery.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}
resource recoveryKeys 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keys
  name: guid(keys.id, purgeRecoveryJobName, 'purge-recovery-keys')
  properties: {
    principalId: recovery.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}
resource recoveryCrypto 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: key
  name: guid(key.id, purgeRecoveryJobName, 'purge-recovery-key-encryption')
  properties: {
    principalId: recovery.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'e147488a-f6f5-4113-8e2d-b22465e65bf6')
  }
}

// Enrollment-aware cleanup owns deadlines; age-based deletion is disabled.
// This replaces the reviewed single legacy rule, not arbitrary operator rules.
resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [{
        name: 'demo-document-purge'
        enabled: false
        type: 'Lifecycle'
        definition: {
          filters: { blobTypes: ['blockBlob'], prefixMatch: [for name in documentContainers: '${name}/'] }
          actions: {
            baseBlob: { delete: { daysAfterModificationGreaterThan: 7 } }
            version: { delete: { daysAfterCreationGreaterThan: 7 } }
            snapshot: { delete: { daysAfterCreationGreaterThan: 7 } }
          }
        }
      }]
    }
  }
}

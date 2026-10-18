targetScope = 'resourceGroup'
param location string
param environmentName string
param storageAccountName string
param workerIdentityName string
param dispatchJobName string
param queueName string
param databaseConnectionSecretUri string
param image string
param signalEnvironment array
param applicationEnvironment array = []
param dataProtectionKeyName string
param vaultName string
@secure()
param tsaRootPem string = ''
resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = { name: environmentName }
resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: workerIdentityName }
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
var tags = { project: 'quillsign' }
resource dispatch 'Microsoft.App/jobs@2025-07-01' = {
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
      secrets: concat([{ name: 'database-connection', keyVaultUrl: databaseConnectionSecretUri, identity: worker.id }], empty(tsaRootPem) ? [] : [{ name: 'tsa-root', value: tsaRootPem }])
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
        volumeMounts: empty(tsaRootPem) ? [] : [{ volumeName: 'tsa-trust', mountPath: '/app/trust' }]
        env: concat(signalEnvironment, [
          { name: 'Storage__ManagedIdentityClientId', value: worker.properties.clientId }
          { name: 'ConnectionStrings__Database', secretRef: 'database-connection' }
          { name: 'DataProtection__ApplicationName', value: 'QuillSign:Production' }
          { name: 'DataProtection__KeyVaultKeyIdentifier', value: '${vault.properties.vaultUri}keys/${dataProtectionKeyName}' }
          { name: 'Email__Enabled', value: 'false' }
        ], applicationEnvironment)
      }]
      volumes: empty(tsaRootPem) ? [] : [{ name: 'tsa-trust', storageType: 'Secret', secrets: [{ secretRef: 'tsa-root', path: 'tsa-root.pem' }] }]
    }
  }
}


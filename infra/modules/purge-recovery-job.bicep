targetScope = 'resourceGroup'
param location string
param environmentId string
param purgeRecoveryJobName string
param queueServiceUri string
param blobServiceUri string
param dataProtectionKeyIdentifier string
param hintContainerName string
param queueName string
param image string
param sandboxMaintenanceEnabled bool = false
param sandboxMaintenanceRegion string = ''
param sandboxGroupName string = ''

resource recovery 'Microsoft.App/jobs@2025-07-01' = {
  name: purgeRecoveryJobName
  location: location
  tags: { project: 'quillsign', component: 'purge-recovery' }
  identity: { type: 'SystemAssigned' }
  properties: {
    environmentId: environmentId
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
        env: concat([
          { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
          { name: 'Work__Enabled', value: 'true' }
          { name: 'Work__QueueServiceUri', value: queueServiceUri }
          { name: 'Work__QueueName', value: queueName }
          { name: 'Work__HintContainer', value: hintContainerName }
          { name: 'Storage__Provider', value: 'Azure' }
          { name: 'Storage__BlobServiceUri', value: blobServiceUri }
          { name: 'DataProtection__ApplicationName', value: 'QuillSign:Production' }
          { name: 'DataProtection__KeyVaultKeyIdentifier', value: dataProtectionKeyIdentifier }
          { name: 'Email__Enabled', value: 'false' }
        ], sandboxMaintenanceEnabled ? [
          { name: 'Gotenberg__Sandbox__MaintenanceEnabled', value: 'true' }
          { name: 'Gotenberg__Sandbox__Region', value: sandboxMaintenanceRegion }
          { name: 'Gotenberg__Sandbox__SubscriptionId', value: subscription().subscriptionId }
          { name: 'Gotenberg__Sandbox__ResourceGroup', value: resourceGroup().name }
          { name: 'Gotenberg__Sandbox__GroupName', value: sandboxGroupName }
        ] : [])
      }]
    }
  }
}
output principalId string = recovery.identity.principalId

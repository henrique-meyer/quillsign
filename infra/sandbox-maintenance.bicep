targetScope = 'resourceGroup'

// Narrow configuration rollout for the existing recovery job. Its shared
// module keeps this and the original staging template in agreement. No storage
// policy or existing storage/Key Vault/worker permission is redeployed here.
param location string
param environmentId string
param purgeRecoveryJobName string
param queueServiceUri string
param blobServiceUri string
param dataProtectionKeyIdentifier string
param hintContainerName string
param queueName string
param image string
param sandboxMaintenanceRegion string
param sandboxGroupName string

module recovery './modules/purge-recovery-job.bicep' = {
  name: 'sandbox-cleanup-job-configuration'
  params: {
    location: location
    environmentId: environmentId
    purgeRecoveryJobName: purgeRecoveryJobName
    queueServiceUri: queueServiceUri
    blobServiceUri: blobServiceUri
    dataProtectionKeyIdentifier: dataProtectionKeyIdentifier
    hintContainerName: hintContainerName
    queueName: queueName
    image: image
    sandboxMaintenanceEnabled: true
    sandboxMaintenanceRegion: sandboxMaintenanceRegion
    sandboxGroupName: sandboxGroupName
  }
}

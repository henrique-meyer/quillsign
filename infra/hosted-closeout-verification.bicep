targetScope = 'resourceGroup'

@description('Opt in only for one reviewed, separately owned read-only verification job. Creation does not start an execution or authorize pilot/provider activity.')
param enabled bool = false

@description('New, uniquely owned temporary job name. The private driver must verify absence before deployment and exact ownership before deletion.')
@minLength(1)
@maxLength(32)
param jobName string

@minLength(1)
param location string

@description('Existing project Container Apps environment in this resource group; never creates or changes the environment.')
@minLength(1)
param environmentName string

@description('Existing runtime user-assigned identity name in this resource group, distinct from the worker identity. Supply privately.')
@minLength(1)
param runtimeIdentityName string

@description('Existing worker user-assigned identity name in this resource group. Supply privately.')
@minLength(1)
param workerIdentityName string

@description('Reviewed lowercase SHA-256 image digest, without a prefix. The private driver must bind it to exact-head CI and image provenance.')
@minLength(64)
@maxLength(64)
param imageDigest string

@description('Canonical GUID for the one owned diagnostic run. Supply privately and bind to the durable control ledger.')
@minLength(36)
@maxLength(36)
param verificationRunId string

@description('Reviewed exact source revision, supplied privately. This tag alone is not source or execution authority.')
@minLength(40)
@maxLength(40)
param verifiedSourceRevision string

@description('SHA-256 of the exact decoded diagnostic configuration, supplied privately and checked by the reviewed driver.')
@minLength(64)
@maxLength(64)
param configurationSha256 string

@description('Closed diagnostic configuration encoded as base64, at most 64 KiB decoded. No connection strings, provider/DP credentials or arbitrary SQL. The early command validates the actual packet before connecting.')
@secure()
@maxLength(87384)
param diagnosticConfigBase64 string = ''

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: environmentName
}

resource runtime 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: runtimeIdentityName
}

resource worker 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: workerIdentityName
}

// This template has no access grants, secrets, automatic trigger or cleanup
// authority. The private driver owns the once-only start, finite accounting,
// stop/delete finally path and exact native absence verification.
resource verification 'Microsoft.App/jobs@2025-07-01' = if (enabled) {
  name: jobName
  location: location
  tags: {
    project: 'quillsign'
    Purpose: 'QUILS-139-readonly-verification'
    verificationRunId: verificationRunId
    verifiedSourceRevision: verifiedSourceRevision
    configurationSha256: configurationSha256
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${runtime.id}': {}
      '${worker.id}': {}
    }
  }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Manual'
      replicaTimeout: 300
      replicaRetryLimit: 0
      manualTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
      }
    }
    template: {
      containers: [
        {
          name: 'verify'
          image: 'ghcr.io/henrique-meyer/quillsign@sha256:${imageDigest}'
          command: ['dotnet', 'QuillSign.dll']
          args: ['database', 'verify-hosted-closeout-state']
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            { name: 'HostedCloseoutVerification__Enabled', value: 'true' }
            { name: 'HostedCloseoutVerification__ConfigurationBase64', value: diagnosticConfigBase64 }
            { name: 'Work__Enabled', value: 'false' }
            { name: 'Email__Enabled', value: 'false' }
            { name: 'EmailPilot__Enabled', value: 'false' }
            { name: 'EmailPilot__Closeout__Enabled', value: 'false' }
          ]
        }
      ]
    }
  }
}

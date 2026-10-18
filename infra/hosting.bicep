targetScope = 'resourceGroup'

@description('All deployment names and addresses belong in ignored parameter files.')
param location string
param environmentName string
param webAppName string
param storageAccountName string
param vaultName string
param runtimeIdentityName string
param deploymentIdentityName string
param workspaceName string
param insightsName string
param failureAlertName string
param budgetName string
param budgetStartDate string
param alertEmails array = []
param githubFederationSubject string
param image string = ''
param deployWeb bool = false
param dataProtectionKeyName string
param customDomainName string = ''
param managedCertificateName string = ''
param enableManagedCertificate bool = false
param databaseConnectionSecretUri string = ''
param applicationEnvironment array = []
param analyticsEnabled bool = false
param analyticsMeasurementId string = ''
param provisionManagedCertificate bool = true
@description('Set true only after the approved, verified final-container migration.')
param finalVersionSupportEnabled bool = false
@secure()
param tsaRootPem string = ''

var tags = { project: 'quillsign' }

resource runtime 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: runtimeIdentityName
  location: location
  tags: tags
}

resource deployment 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: deploymentIdentityName
  location: location
  tags: tags
}

module federation './modules/github-federation.bicep' = {
  name: 'github-production'
  params: {
    deploymentIdentityName: deployment.name
    federationSubject: githubFederationSubject
  }
}

resource deployRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, deployment.id, 'contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: deployment.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    encryption: {
      keySource: 'Microsoft.Storage'
      services: { blob: { enabled: true, keyType: 'Account' } }
    }
  }
}

resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

var documentContainers = [ 'originals', 'normalized', 'previews', 'checkpoints', 'final' ]
resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = [for container in concat(documentContainers, ['keys']): {
  parent: blobs
  name: container
  properties: union({ publicAccess: 'None' }, container == 'final' && finalVersionSupportEnabled ? { immutableStorageWithVersioning: { enabled: true } } : {})
}]

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
          filters: { blobTypes: ['blockBlob'], prefixMatch: [for container in documentContainers: '${container}/'] }
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

resource blobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, runtime.id, 'blob-contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: runtime.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
    publicNetworkAccess: 'Enabled'
    accessPolicies: []
  }
}

resource protectionKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: vault
  name: dataProtectionKeyName
  properties: {
    kty: 'RSA'
    keySize: 2048
    keyOps: [ 'wrapKey', 'unwrapKey' ]
    attributes: { enabled: true }
  }
}

resource secretRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, runtime.id, 'secrets-user')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: runtime.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource cryptoRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: protectionKey
  name: guid(protectionKey.id, runtime.id, 'key-encryption')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'e147488a-f6f5-4113-8e2d-b22465e65bf6')
    principalId: runtime.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: json('0.1') }
    features: { enableLogAccessUsingOnlyResourcePermissions: true }
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: insightsName
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    SamplingPercentage: 10
    DisableLocalAuth: true
  }
}

module isolatedFailureAlert './modules/smart-detection.bicep' = {
  name: 'isolated-failure-alert'
  params: {
    alertRuleName: failureAlertName
    insightsResourceId: insights.id
  }
}

// Consumption profile without a custom VNet or customer-managed network resources.
resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
  }
}

module web './modules/web.bicep' = if (deployWeb) {
  name: 'web-application'
  params: {
    location: location
    environmentName: environment.name
    webAppName: webAppName
    runtimeIdentityName: runtime.name
    image: image
    customDomainName: customDomainName
    managedCertificateName: managedCertificateName
    enableManagedCertificate: enableManagedCertificate
    databaseConnectionSecretUri: databaseConnectionSecretUri
    applicationEnvironment: applicationEnvironment
    analyticsEnabled: analyticsEnabled
    analyticsMeasurementId: analyticsMeasurementId
    provisionManagedCertificate: provisionManagedCertificate
    tsaRootPem: tsaRootPem
  }
}

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: budgetName
  properties: {
    category: 'Cost'
    amount: 15
    timeGrain: 'Monthly'
    timePeriod: { startDate: budgetStartDate, endDate: '2036-10-01T00:00:00Z' }
    notifications: empty(alertEmails) ? {} : {
      actual50: { enabled: true, operator: 'GreaterThanOrEqualTo', threshold: 50, thresholdType: 'Actual', contactEmails: alertEmails }
      actual80: { enabled: true, operator: 'GreaterThanOrEqualTo', threshold: 80, thresholdType: 'Actual', contactEmails: alertEmails }
      actual100: { enabled: true, operator: 'GreaterThanOrEqualTo', threshold: 100, thresholdType: 'Actual', contactEmails: alertEmails }
      forecast100: { enabled: true, operator: 'GreaterThanOrEqualTo', threshold: 100, thresholdType: 'Forecasted', contactEmails: alertEmails }
    }
  }
}

output deploymentClientId string = deployment.properties.clientId
output runtimeClientId string = runtime.properties.clientId
output blobEndpoint string = storage.properties.primaryEndpoints.blob
output vaultUri string = vault.properties.vaultUri
output fqdn string = deployWeb ? web!.outputs.fqdn : ''
output domainVerificationId string = deployWeb ? web!.outputs.domainVerificationId : ''

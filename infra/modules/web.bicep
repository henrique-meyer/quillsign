targetScope = 'resourceGroup'
param location string
param environmentName string
param webAppName string
param runtimeIdentityName string
param image string
param customDomainName string = ''
param managedCertificateName string = ''
param enableManagedCertificate bool = false
param databaseConnectionSecretUri string = ''
param applicationEnvironment array = []
var tags = { project: 'quillsign' }
// ARM still validates conditional resource IDs when certificate creation is disabled.
var certificateResourceName = empty(managedCertificateName) ? '${webAppName}-tls' : managedCertificateName
resource environment 'Microsoft.App/managedEnvironments@2024-03-01' existing = { name: environmentName }
resource runtime 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: runtimeIdentityName }

resource web 'Microsoft.App/containerApps@2024-03-01' = {
  name: webAppName
  location: location
  tags: union(tags, { component: 'web' })
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${runtime.id}': {} } }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      secrets: empty(databaseConnectionSecretUri) ? [] : [{
        name: 'database-connection'
        keyVaultUrl: databaseConnectionSecretUri
        identity: runtime.id
      }]
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
        customDomains: empty(customDomainName) ? [] : [{
          name: customDomainName
          bindingType: enableManagedCertificate ? 'SniEnabled' : 'Disabled'
          certificateId: enableManagedCertificate ? managedCertificate!.id : null
        }]
      }
    }
    template: {
      containers: [{
        name: 'web'
        image: image
        resources: { cpu: json('0.5'), memory: '1Gi' }
        env: concat([{ name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }], empty(databaseConnectionSecretUri) ? [] : [{
          name: 'ConnectionStrings__Database'
          secretRef: 'database-connection'
        }], applicationEnvironment)
        probes: [for probe in [ 'Liveness', 'Readiness', 'Startup' ]: {
          type: probe
          httpGet: { path: '/health', port: 8080 }
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 2
          failureThreshold: probe == 'Startup' ? 30 : 3
        }]
      }]
      scale: { minReplicas: 0, maxReplicas: 2, rules: [{ name: 'http', http: { metadata: { concurrentRequests: '20' } } }] }
    }
  }
}

// Enable only after DNS verification and an initial Disabled hostname binding.
resource managedCertificate 'Microsoft.App/managedEnvironments/managedCertificates@2024-03-01' = if (enableManagedCertificate) {
  parent: environment
  name: certificateResourceName
  location: location
  properties: { subjectName: customDomainName, domainControlValidation: 'CNAME' }
}

output fqdn string = web.properties.configuration.ingress.fqdn
output domainVerificationId string = web.properties.customDomainVerificationId

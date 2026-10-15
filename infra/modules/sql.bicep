@description('Azure region compatible with the subscription free database offer.')
param location string

@minLength(1)
param serverName string

@minLength(1)
param databaseName string

@minLength(36)
@maxLength(36)
param administratorObjectId string

@minLength(1)
param administratorName string

@allowed([
  'User'
  'Group'
  'Application'
])
param administratorType string

@description('Enable the public SQL endpoint and Allow Azure services only with operator approval.')
param allowAzureServices bool = false

@description('Leave existing database/backup resources untouched during a network-only deployment.')
param deployDatabase bool = true

resource server 'Microsoft.Sql/servers@2023-08-01' = {
  name: serverName
  location: location
  properties: {
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: allowAzureServices ? 'Enabled' : 'Disabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true
      login: administratorName
      principalType: administratorType
      sid: administratorObjectId
      tenantId: tenant().tenantId
    }
  }
}

// This is Azure-wide network access, including other subscriptions. Entra
// authentication and database permissions still govern every connection.
resource azureServices 'Microsoft.Sql/servers/firewallRules@2023-08-01' = if (allowAzureServices) {
  parent: server
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource database 'Microsoft.Sql/servers/databases@2023-08-01' = if (deployDatabase) {
  parent: server
  name: databaseName
  location: location
  sku: {
    name: 'GP_S_Gen5'
    tier: 'GeneralPurpose'
    family: 'Gen5'
    capacity: 2
  }
  properties: {
    // Keep free-offer enforcement fixed; a deployment must never enable paid overflow.
    useFreeLimit: true
    freeLimitExhaustionBehavior: 'AutoPause'
    maxSizeBytes: 34359738368
    // ARM represents this fractional vCore value as a JSON number.
    minCapacity: json('0.5')
    // The free offer requires the default 60-minute idle delay.
    autoPauseDelay: 60
    requestedBackupStorageRedundancy: 'Local'
    zoneRedundant: false
    readScale: 'Disabled'
    licenseType: 'LicenseIncluded'
  }
}

resource retention 'Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies@2023-08-01' = if (deployDatabase) {
  parent: database
  name: 'default'
  properties: {
    retentionDays: 7
  }
}

// Azure enables service-managed TDE for every new database.
// Verify the effective encryption state after deployment instead of issuing
// a redundant encryption update while database provisioning is settling.

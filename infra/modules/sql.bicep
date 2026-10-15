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

resource server 'Microsoft.Sql/servers@2023-08-01' = {
  name: serverName
  location: location
  properties: {
    version: '12.0'
    minimalTlsVersion: '1.2'
    // App connectivity will be introduced with the app's approved networking.
    publicNetworkAccess: 'Disabled'
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

resource database 'Microsoft.Sql/servers/databases@2023-08-01' = {
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
    autoPauseDelay: 15
    requestedBackupStorageRedundancy: 'Local'
    zoneRedundant: false
    readScale: 'Disabled'
    licenseType: 'LicenseIncluded'
  }
}

resource retention 'Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies@2023-08-01' = {
  parent: database
  name: 'default'
  properties: {
    retentionDays: 7
  }
}

resource encryption 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-08-01' = {
  parent: database
  name: 'current'
  properties: {
    state: 'Enabled'
  }
}

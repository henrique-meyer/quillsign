targetScope = 'subscription'

@description('Dedicated application resource group. Set only in ignored deployment parameters.')
@minLength(1)
param resourceGroupName string

@description('Resource group metadata location. This cannot change after group creation.')
@minLength(1)
param location string

@description('SQL region allowed by subscription provisioning policy and the free database offer.')
@minLength(1)
param sqlLocation string

@description('Globally unique SQL logical server name. Set only in ignored deployment parameters.')
@minLength(1)
param sqlServerName string

@description('Application database name. Set only in ignored deployment parameters.')
@minLength(1)
param sqlDatabaseName string

@description('Microsoft Entra administrator object ID. Set only in ignored deployment parameters.')
@minLength(36)
@maxLength(36)
param sqlAdministratorObjectId string

@description('Microsoft Entra administrator display name. Set only in ignored deployment parameters.')
@minLength(1)
param sqlAdministratorName string

@allowed([
  'User'
  'Group'
  'Application'
])
param sqlAdministratorType string = 'User'

resource applicationGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

module database './modules/sql.bicep' = {
  name: 'sql-foundation'
  scope: applicationGroup
  params: {
    location: sqlLocation
    serverName: sqlServerName
    databaseName: sqlDatabaseName
    administratorObjectId: sqlAdministratorObjectId
    administratorName: sqlAdministratorName
    administratorType: sqlAdministratorType
  }
}

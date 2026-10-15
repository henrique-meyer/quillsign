targetScope = 'resourceGroup'
param alertRuleName string
param insightsResourceId string

// Azure can automatically create this rule with a default action group outside
// the project. Own its configuration explicitly and keep it disabled until a
// project-specific notification destination is approved.
resource failureAlert 'Microsoft.AlertsManagement/smartDetectorAlertRules@2021-04-01' = {
  name: alertRuleName
  location: 'global'
  properties: {
    state: 'Disabled'
    severity: 'Sev3'
    frequency: 'PT1M'
    detector: { id: 'FailureAnomaliesDetector' }
    scope: [ insightsResourceId ]
    actionGroups: { groupIds: [] }
  }
}

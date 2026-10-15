targetScope = 'resourceGroup'

param serverName string
param firewallRuleName string
@secure()
param operatorIp string

resource server 'Microsoft.Sql/servers@2023-08-01' existing = { name: serverName }
resource temporaryAccess 'Microsoft.Sql/servers/firewallRules@2023-08-01' = {
  parent: server
  name: firewallRuleName
  properties: { startIpAddress: operatorIp, endIpAddress: operatorIp }
}

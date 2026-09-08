$ErrorActionPreference = 'Continue'
Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress
Get-NetIPConfiguration
Get-DnsClientServerAddress
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric,DestinationPrefix

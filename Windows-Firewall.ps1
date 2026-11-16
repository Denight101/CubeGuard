[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([ValidateSet('Preview', 'Apply', 'Remove')][string]$Action = 'Preview')
$ErrorActionPreference = 'Stop'
$groupName = 'CubeGuard prototype v1'
$policy = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'policy.json') -Raw | ConvertFrom-Json
$addresses = @($policy.windowsBlockedIPs | Select-Object -Unique)
foreach ($address in $addresses) {
    $parsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsedAddress)) {
        throw "Invalid literal IP address: $address. CIDR ranges and domains are not accepted."
    }
}
if ($Action -eq 'Preview') {
    Write-Output 'No rules changed. Proposed outbound IP blocks (all applications):'
    $addresses
    Write-Output 'Apply requires an elevated PowerShell. Remove deletes only CubeGuard prototype v1 rules.'
    return
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator to apply or remove firewall rules.'
}
if ($Action -eq 'Remove') {
    Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.DisplayName, 'Remove CubeGuard rule')) {
            $_ | Remove-NetFirewallRule
        }
    }
    return
}
foreach ($address in $addresses) {
    $ruleName = 'CubeGuard-v1-block-' + $address.Replace(':', '_')
    $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($existing -and $existing.Group -ne $groupName) { throw "Rule name collision: $ruleName" }
    if (-not $existing -and $PSCmdlet.ShouldProcess($address, 'Block outbound traffic for all applications')) {
        New-NetFirewallRule -Name $ruleName -DisplayName "CubeGuard block $address" -Group $groupName `
            -Direction Outbound -Action Block -RemoteAddress $address -Profile Any | Out-Null
    }
}

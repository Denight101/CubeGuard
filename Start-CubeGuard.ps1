$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js 22 or newer is required. Install it, then reopen PowerShell.'
}
if (-not $env:CUBE_TOKEN) {
    $secret = Read-Host 'Enter a proxy password of at least 32 characters' -AsSecureString
    $credential = [System.Net.NetworkCredential]::new('cube', $secret)
    $env:CUBE_TOKEN = $credential.Password
}
try { & node (Join-Path $PSScriptRoot 'cube.js') }
finally { Remove-Item Env:CUBE_TOKEN -ErrorAction SilentlyContinue }

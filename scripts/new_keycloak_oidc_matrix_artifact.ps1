[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$KeycloakVersion,

    [Parameter(Mandatory)]
    [ValidatePattern('^sha256:[a-f0-9]{64}$')]
    [string]$KeycloakImageDigest,

    [ValidateSet('https', 'internal_http')]
    [string]$TransportMode = 'https',

    [string]$ArtifactDirectory = 'artifacts/oidc-matrix'
)

$ErrorActionPreference = 'Stop'

# Start every real IdP run as incomplete so only observed scenarios can become passed.
$scenarios = @(
    'first_login',
    'repeat_login',
    'userinfo_completion',
    'email_change',
    'disabled_keylo_user',
    'disabled_identity_source'
) | ForEach-Object {
    [ordered]@{
        name = $_
        status = 'not_executed'
        result = 'not_run'
    }
}

New-Item -ItemType Directory -Force -Path $ArtifactDirectory | Out-Null
$artifact = [ordered]@{
    executed_at_utc = [DateTime]::UtcNow.ToString('o')
    keylo_commit = (git rev-parse HEAD).Trim()
    keycloak_version = $KeycloakVersion
    keycloak_image_digest = $KeycloakImageDigest
    status = 'not_executed'
    transport_mode = $TransportMode
    security_boundary = $(if ($TransportMode -eq 'internal_http') { 'internal_http_requires_network_isolation' } else { 'https' })
    scenarios = $scenarios
}
$path = Join-Path $ArtifactDirectory "keycloak-run-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).json"
$artifact | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding utf8

Write-Host "[NOT_EXECUTED] Created Keycloak OIDC matrix artifact: $path" -ForegroundColor Yellow
exit 2

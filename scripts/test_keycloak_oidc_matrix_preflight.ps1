[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$KeyloPublicIssuer,

    [Parameter(Mandatory)]
    [string]$KeycloakIssuer,

    [string]$ArtifactDirectory = "artifacts/oidc-matrix"
)

$ErrorActionPreference = "Stop"

function Assert-HttpsIssuer([string]$Name, [string]$Value) {
    # Reject endpoint forms that cannot be a stable, externally verifiable OIDC issuer.
    $uri = [Uri]$Value
    if ($uri.Scheme -ne "https" -or !$uri.IsAbsoluteUri -or $uri.Query -or $uri.Fragment) {
        throw "$Name must be an absolute HTTPS issuer without query or fragment"
    }
    return $uri.AbsoluteUri.TrimEnd('/')
}

function Assert-HttpsOrigin([string]$Name, [string]$Value) {
    # Keylo's public issuer is intentionally an origin, unlike Keycloak realm issuers which have a path.
    $issuer = Assert-HttpsIssuer $Name $Value
    if (([Uri]$issuer).AbsolutePath -ne "/") {
        throw "$Name must be an HTTPS origin without a path"
    }
    return $issuer
}

function Assert-DiscoveryContract([string]$Name, [string]$Issuer) {
    # Fetch only public Discovery metadata and verify the capabilities Keylo's upstream flow requires.
    $document = Invoke-RestMethod -Uri "$Issuer/.well-known/openid-configuration" -Method Get
    if ($document.issuer -ne $Issuer) {
        throw "$Name Discovery issuer does not exactly match the configured issuer"
    }
    foreach ($field in @("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint")) {
        $value = [string]$document.$field
        if ([string]::IsNullOrWhiteSpace($value) -or ([Uri]$value).Scheme -ne "https") {
            throw "$Name Discovery $field must be an HTTPS URL"
        }
    }
    if ($document.response_types_supported -notcontains "code") {
        throw "$Name Discovery must advertise the authorization code response type"
    }
    if ($document.grant_types_supported -and $document.grant_types_supported -notcontains "authorization_code") {
        throw "$Name Discovery must advertise authorization_code when grant types are declared"
    }
    if ($document.token_endpoint_auth_methods_supported -and $document.token_endpoint_auth_methods_supported -notcontains "client_secret_basic") {
        throw "$Name Discovery must advertise client_secret_basic when auth methods are declared"
    }
    if ($document.id_token_signing_alg_values_supported -and $document.id_token_signing_alg_values_supported -notcontains "RS256") {
        throw "$Name Discovery must advertise RS256 when signing algorithms are declared"
    }
    return $document
}

New-Item -ItemType Directory -Force -Path $ArtifactDirectory | Out-Null
$commit = (git rev-parse HEAD).Trim()
$artifact = [ordered]@{
    executed_at_utc = [DateTime]::UtcNow.ToString("o")
    keylo_commit = $commit
    status = "not_executed"
    reason = "preflight_not_run"
    note = "This record contains public endpoint metadata only; it contains no credentials, codes, or tokens."
}

try {
    $keyloIssuer = Assert-HttpsOrigin "KeyloPublicIssuer" $KeyloPublicIssuer
    $keycloakIssuer = Assert-HttpsIssuer "KeycloakIssuer" $KeycloakIssuer
    $keyloDiscovery = Assert-DiscoveryContract "Keylo" $keyloIssuer
    $keycloakDiscovery = Assert-DiscoveryContract "Keycloak" $keycloakIssuer
    $artifact.keylo_issuer = $keyloDiscovery.issuer
    $artifact.keycloak_issuer = $keycloakDiscovery.issuer
    $artifact.keycloak_authorization_endpoint = $keycloakDiscovery.authorization_endpoint
    $artifact.keycloak_token_endpoint = $keycloakDiscovery.token_endpoint
    $artifact.keycloak_userinfo_endpoint = $keycloakDiscovery.userinfo_endpoint
    $artifact.keycloak_jwks_uri = $keycloakDiscovery.jwks_uri
    $artifact.status = "preflight_passed"
    $artifact.reason = ""
}
catch {
    # Keep an auditable result without serializing remote error bodies or credentials.
    $artifact.reason = "https_discovery_or_endpoint_validation_failed"
}

$path = Join-Path $ArtifactDirectory "preflight-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).json"
$artifact | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
if ($artifact.status -eq "preflight_passed") {
    Write-Host "[SUCCESS] Keycloak OIDC matrix preflight passed: $path" -ForegroundColor Green
    exit 0
}
Write-Host "[NOT_EXECUTED] Keycloak OIDC matrix preflight prerequisites unavailable: $path" -ForegroundColor Yellow
exit 2

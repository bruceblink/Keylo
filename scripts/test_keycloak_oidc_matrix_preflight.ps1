[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$KeyloPublicIssuer,

    [Parameter(Mandatory)]
    [string]$KeycloakIssuer,

    [switch]$AllowInsecureInternalHttp,

    [string]$ArtifactDirectory = "artifacts/oidc-matrix"
)

$ErrorActionPreference = "Stop"

function Assert-Issuer([string]$Name, [string]$Value, [bool]$AllowInternalHttp) {
    # HTTP is accepted only after an explicit internal-deployment opt-in.
    $uri = [Uri]$Value
    $allowedScheme = $uri.Scheme -eq "https" -or ($AllowInternalHttp -and $uri.Scheme -eq "http")
    if (!$allowedScheme -or !$uri.IsAbsoluteUri -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) {
        throw "$Name must be an absolute HTTPS issuer, or explicit internal HTTP issuer, without credentials, query, or fragment"
    }
    return $uri.AbsoluteUri.TrimEnd('/')
}

function Assert-Origin([string]$Name, [string]$Value, [bool]$AllowInternalHttp) {
    # Keylo's public issuer is intentionally an origin, unlike Keycloak realm issuers which have a path.
    $issuer = Assert-Issuer $Name $Value $AllowInternalHttp
    if (([Uri]$issuer).AbsolutePath -ne "/") {
        throw "$Name must be an origin without a path"
    }
    return $issuer
}

function Assert-DiscoveryContract([string]$Name, [string]$Issuer, [bool]$AllowInternalHttp) {
    # Fetch only public Discovery metadata and verify the capabilities Keylo's upstream flow requires.
    $document = Invoke-RestMethod -Uri "$Issuer/.well-known/openid-configuration" -Method Get
    if ($document.issuer -ne $Issuer) {
        throw "$Name Discovery issuer does not exactly match the configured issuer"
    }
    foreach ($field in @("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint")) {
        $value = [string]$document.$field
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "$Name Discovery $field must be present"
        }
        $uri = [Uri]$value
        $allowedScheme = $uri.Scheme -eq "https" -or ($AllowInternalHttp -and $uri.Scheme -eq "http")
        if (!$uri.IsAbsoluteUri -or !$allowedScheme -or $uri.UserInfo) {
            throw "$Name Discovery $field must be an HTTPS URL, or explicit internal HTTP URL"
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
    transport_mode = $(if ($AllowInsecureInternalHttp) { "internal_http_allowed" } else { "https_required" })
    security_boundary = $(if ($AllowInsecureInternalHttp) { "internal_http_requires_network_isolation" } else { "https" })
    note = "This record contains public endpoint metadata only; it contains no credentials, codes, or tokens."
}

try {
    $keyloIssuer = Assert-Origin "KeyloPublicIssuer" $KeyloPublicIssuer $AllowInsecureInternalHttp
    $keycloakIssuer = Assert-Issuer "KeycloakIssuer" $KeycloakIssuer $AllowInsecureInternalHttp
    $keyloDiscovery = Assert-DiscoveryContract "Keylo" $keyloIssuer $AllowInsecureInternalHttp
    $keycloakDiscovery = Assert-DiscoveryContract "Keycloak" $keycloakIssuer $AllowInsecureInternalHttp
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
    $artifact.reason = "discovery_or_endpoint_validation_failed"
}

$path = Join-Path $ArtifactDirectory "preflight-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).json"
$artifact | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
if ($artifact.status -eq "preflight_passed") {
    Write-Host "[SUCCESS] Keycloak OIDC matrix preflight passed: $path" -ForegroundColor Green
    exit 0
}
Write-Host "[NOT_EXECUTED] Keycloak OIDC matrix preflight prerequisites unavailable: $path" -ForegroundColor Yellow
exit 2

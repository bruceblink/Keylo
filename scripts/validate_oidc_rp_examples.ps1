$ErrorActionPreference = "Stop"

# Build every published RP sample so protocol documentation cannot drift from runnable code.
function Invoke-ExampleCheck {
    param(
        [string]$Name,
        [string]$Directory,
        [scriptblock]$Command
    )

    Write-Host "[INFO] Validating $Name" -ForegroundColor Cyan
    Push-Location $Directory
    try {
        & $Command
        if ($LASTEXITCODE -ne 0) {
            throw "$Name validation failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot

Invoke-ExampleCheck "Node Express OIDC RP" (Join-Path $repositoryRoot "examples\node-express-oidc") {
    npm ci --ignore-scripts
    if ($LASTEXITCODE -ne 0) { return }
    npm run check
}
Invoke-ExampleCheck "Go net/http OIDC RP" (Join-Path $repositoryRoot "examples\go-net-http-oidc") {
    go test ./...
}
Invoke-ExampleCheck "Rust Axum OIDC RP" (Join-Path $repositoryRoot "examples\rust-axum-oidc") {
    cargo test
}
Invoke-ExampleCheck "Spring Boot OIDC RP" (Join-Path $repositoryRoot "examples\spring-boot-oidc") {
    .\gradlew.bat test --no-daemon
}

Write-Host "[SUCCESS] All OIDC relying party examples passed" -ForegroundColor Green

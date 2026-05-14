$ErrorActionPreference = "Stop"

Write-Host "[INFO] Starting Keylo Integration Tests" -ForegroundColor Cyan

function Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Success($msg) { Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# Check docker
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Fail "Docker is not running. Please start Docker and try again."
}

Info "Starting PostgreSQL test database..."
New-Item -ItemType Directory -Force -Path "secrets" *> $null
$testPasswordFile = (Resolve-Path "secrets").Path + "\test_postgres_password"
$testPasswordEncFile = (Resolve-Path "secrets").Path + "\test_postgres_password.enc"
$testPasswordKeyFile = (Resolve-Path "secrets").Path + "\test_database_password.key"
if (!(Test-Path $testPasswordFile) -or ((Get-Item $testPasswordFile).Length -eq 0)) {
    [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) | Set-Content -NoNewline $testPasswordFile
}
if (!(Test-Path $testPasswordKeyFile) -or ((Get-Item $testPasswordKeyFile).Length -eq 0)) {
    [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) | Set-Content -NoNewline $testPasswordKeyFile
}
$env:DATABASE_PASSWORD_FILE = $testPasswordFile
$env:DATABASE_PASSWORD_KEY_FILE = $testPasswordKeyFile
cargo run --quiet --bin keylo-encrypt-db-password | Set-Content -NoNewline $testPasswordEncFile
Remove-Item Env:DATABASE_PASSWORD_FILE
docker run -d --name keylo-test-db `
    -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password `
    -e POSTGRES_DB=keylo_test `
    -v "${testPasswordFile}:/run/secrets/postgres_password:ro" `
    -p 5432:5432 postgres:15 *> $null
if ($LASTEXITCODE -eq 0) {
    Success "PostgreSQL test database started"
} else {
    Warn "PostgreSQL container already exists or failed to start"
}

Info "Waiting for database to be ready..."
for ($i = 0; $i -lt 30; $i++) {
    docker exec keylo-test-db pg_isready -U postgres -d keylo_test *> $null
    if ($LASTEXITCODE -eq 0) {
        Success "Database is ready"
        break
    }
    Start-Sleep -Seconds 1
}
if ($i -eq 30) {
    Fail "Database failed to start within 30 seconds"
}

$testDbPassword = (Get-Content -Raw $testPasswordFile).Trim()
$env:TEST_DATABASE_URL = "postgres://postgres:${testDbPassword}@localhost:5432/keylo_test"
$env:DATABASE_PASSWORD_ENC_FILE = $testPasswordEncFile
$env:DATABASE_PASSWORD_KEY_FILE = $testPasswordKeyFile
$env:RUST_LOG = "debug"

Info "Running formatting checks..."
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { Fail "Formatting check failed" }
Success "Formatting checks passed"

Info "Running clippy checks..."
cargo clippy -- -D warnings
if ($LASTEXITCODE -ne 0) { Fail "Clippy checks failed" }
Success "Clippy checks passed"

Info "Running full test suite..."
cargo test
if ($LASTEXITCODE -ne 0) { Fail "Tests failed" }
Success "All tests passed"

Info "Cleaning up test database..."
docker stop keylo-test-db *> $null
docker rm keylo-test-db *> $null
Success "Test database cleaned up"

Success "All checks completed successfully"

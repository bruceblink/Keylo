$ErrorActionPreference = "Stop"

Write-Host "[INFO] Starting Keylo Integration Tests" -ForegroundColor Cyan

function Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Success($msg) { Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Fail($msg) {
    Write-Host "[ERROR] $msg" -ForegroundColor Red
    if ($script:cleanupTestDatabase) {
        Remove-TestDatabaseContainer
    }
    exit 1
}

$testContainerName = "keylo-test-db"
$script:cleanupTestDatabase = $false

function Invoke-NativeQuiet($command) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $command *> $null
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Remove-TestDatabaseContainer {
    $existingContainer = docker ps -a -q --filter "name=^/${testContainerName}$"
    if ($existingContainer) {
        Invoke-NativeQuiet { docker rm -f $testContainerName } *> $null
    }
}

function New-Base64RandomBytes($length) {
    $bytes = New-Object byte[] $length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    [Convert]::ToBase64String($bytes)
}

# Check docker
if ((Invoke-NativeQuiet { docker info }) -ne 0) {
    Fail "Docker is not running. Please start Docker and try again."
}

Info "Starting PostgreSQL test database..."
New-Item -ItemType Directory -Force -Path ".secrets" *> $null
$secretDir = Get-Item -Force -LiteralPath ".secrets"
$secretDir.Attributes = $secretDir.Attributes -bor [System.IO.FileAttributes]::Hidden
$testPasswordFile = Join-Path $secretDir.FullName ".test_postgres_password"
$testPasswordEncFile = Join-Path $secretDir.FullName ".test_postgres_password.enc"
$testPasswordKeyFile = Join-Path $secretDir.FullName ".test_database_password.key"
if (!(Test-Path $testPasswordFile) -or ((Get-Item $testPasswordFile).Length -eq 0)) {
    New-Base64RandomBytes 32 | Set-Content -NoNewline $testPasswordFile
}
if (!(Test-Path $testPasswordKeyFile) -or ((Get-Item $testPasswordKeyFile).Length -eq 0)) {
    New-Base64RandomBytes 32 | Set-Content -NoNewline $testPasswordKeyFile
}
$env:DATABASE_PASSWORD_FILE = $testPasswordFile
$env:DATABASE_PASSWORD_KEY_FILE = $testPasswordKeyFile
cargo run --quiet --bin keylo-encrypt-db-password | Set-Content -NoNewline $testPasswordEncFile
Remove-Item Env:DATABASE_PASSWORD_FILE
Remove-TestDatabaseContainer
$dockerRunExitCode = Invoke-NativeQuiet {
    docker run -d --name $testContainerName `
        -e POSTGRES_PASSWORD_FILE=/run/secrets/.postgres_password `
        -e POSTGRES_DB=keylo_test `
        -v "${testPasswordFile}:/run/secrets/.postgres_password:ro" `
        -p 5432:5432 postgres:15
}
if ($dockerRunExitCode -eq 0) {
    $script:cleanupTestDatabase = $true
    Success "PostgreSQL test database started"
} else {
    Warn "PostgreSQL container already exists or failed to start"
}

Info "Waiting for database to be ready..."
for ($i = 0; $i -lt 30; $i++) {
    if ((Invoke-NativeQuiet { docker exec $testContainerName pg_isready -U postgres -d keylo_test }) -eq 0) {
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
Remove-TestDatabaseContainer
$script:cleanupTestDatabase = $false
Success "Test database cleaned up"

Success "All checks completed successfully"

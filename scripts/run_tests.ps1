param(
    [int]$DatabasePort = 55432,
    [string]$PostgresImage = "postgres:17-alpine",
    [int]$SmtpPort = 11025,
    [int]$SmtpApiPort = 18025,
    [string]$MailpitImage = "axllent/mailpit:v1.21.8"
)

$ErrorActionPreference = "Stop"

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success([string]$Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-WarningMessage([string]$Message) {
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function New-Base64RandomBytes([int]$Length) {
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    [Convert]::ToBase64String($bytes)
}

if ($DatabasePort -lt 1024 -or $DatabasePort -gt 65535) {
    throw "DatabasePort must be between 1024 and 65535."
}
if ([string]::IsNullOrWhiteSpace($PostgresImage)) {
    throw "PostgresImage must not be empty."
}
if ($SmtpPort -lt 1024 -or $SmtpPort -gt 65535) {
    throw "SmtpPort must be between 1024 and 65535."
}
if ($SmtpApiPort -lt 1024 -or $SmtpApiPort -gt 65535) {
    throw "SmtpApiPort must be between 1024 and 65535."
}
if ([string]::IsNullOrWhiteSpace($MailpitImage)) {
    throw "MailpitImage must not be empty."
}

$runId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$testContainerName = "keylo-test-db-$runId"
$mailpitContainerName = "keylo-test-mail-$runId"
$testTempDir = Join-Path ([System.IO.Path]::GetTempPath()) "keylo-test-$runId"
$containerStarted = $false
$mailpitContainerStarted = $false
$tempDirCreated = $false
$succeeded = $false

function Remove-TestResources {
    if ($script:containerStarted) {
        try {
            docker rm -f -v $script:testContainerName *> $null
        } catch {
            Write-WarningMessage "Failed to remove Docker test container $($script:testContainerName): $($_.Exception.Message)"
        }
        $script:containerStarted = $false
    }

    if ($script:mailpitContainerStarted) {
        try {
            docker rm -f -v $script:mailpitContainerName *> $null
        } catch {
            Write-WarningMessage "Failed to remove Docker SMTP test container $($script:mailpitContainerName): $($_.Exception.Message)"
        }
        $script:mailpitContainerStarted = $false
    }

    if ($script:tempDirCreated -and (Test-Path -LiteralPath $script:testTempDir)) {
        try {
            Remove-Item -LiteralPath $script:testTempDir -Recurse -Force
        } catch {
            Write-WarningMessage "Failed to remove temporary test secrets: $($_.Exception.Message)"
        }
        $script:tempDirCreated = $false
    }
}

$script:testContainerName = $testContainerName
$script:mailpitContainerName = $mailpitContainerName
$script:testTempDir = $testTempDir
$script:containerStarted = $false
$script:mailpitContainerStarted = $false
$script:tempDirCreated = $false

try {
    Write-Info "Checking Docker availability..."
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Start Docker Desktop and retry."
    }

    New-Item -ItemType Directory -Force -Path $testTempDir *> $null
    $tempDirCreated = $true
    $script:tempDirCreated = $true
    $testPasswordFile = Join-Path $testTempDir "postgres_password"
    $testPasswordKeyFile = Join-Path $testTempDir "database_password.key"
    $testPasswordEncFile = Join-Path $testTempDir "postgres_password.enc"

    Write-Info "Creating temporary database credentials..."
    New-Base64RandomBytes 32 | Set-Content -LiteralPath $testPasswordFile -NoNewline -Encoding ascii
    New-Base64RandomBytes 32 | Set-Content -LiteralPath $testPasswordKeyFile -NoNewline -Encoding ascii
    $env:DATABASE_PASSWORD_FILE = $testPasswordFile
    $env:DATABASE_PASSWORD_KEY_FILE = $testPasswordKeyFile
    cargo run --quiet --bin keylo-encrypt-db-password | Set-Content -LiteralPath $testPasswordEncFile -NoNewline -Encoding ascii
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to generate the encrypted PostgreSQL password."
    }
    Remove-Item Env:DATABASE_PASSWORD_FILE -ErrorAction SilentlyContinue
    Remove-Item Env:DATABASE_PASSWORD_KEY_FILE -ErrorAction SilentlyContinue

    Write-Info "Starting $PostgresImage on 127.0.0.1:$DatabasePort..."
    # Mark the generated name before starting Docker so a partially created
    # container is also removed if the native command fails.
    $script:containerStarted = $true
    docker run --detach --name $testContainerName `
        --env POSTGRES_USER=postgres `
        --env POSTGRES_PASSWORD_FILE=/run/secrets/.postgres_password `
        --env POSTGRES_DB=keylo_test `
        --volume "${testPasswordFile}:/run/secrets/.postgres_password:ro" `
        --publish "127.0.0.1:${DatabasePort}:5432" `
        $PostgresImage | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start the PostgreSQL Docker container."
    }
    $containerStarted = $true
    $containerState = docker inspect --format '{{.Config.Image}} {{.State.Status}}' $testContainerName
    Write-Info "Docker service: $testContainerName ($containerState), port 127.0.0.1:$DatabasePort -> 5432"

    Write-Info "Waiting for PostgreSQL readiness..."
    $databaseReady = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        docker exec $testContainerName pg_isready -U postgres -d keylo_test *> $null
        if ($LASTEXITCODE -eq 0) {
            $databaseReady = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $databaseReady) {
        throw "PostgreSQL did not become ready within 30 seconds."
    }
    Write-Success "PostgreSQL is ready."

    Write-Info "Starting $MailpitImage on 127.0.0.1:$SmtpPort (API $SmtpApiPort)..."
    $script:mailpitContainerStarted = $true
    docker run --detach --name $mailpitContainerName `
        --publish "127.0.0.1:${SmtpPort}:1025" `
        --publish "127.0.0.1:${SmtpApiPort}:8025" `
        $MailpitImage | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start the Mailpit Docker container."
    }
    $mailpitContainerState = docker inspect --format '{{.Config.Image}} {{.State.Status}}' $mailpitContainerName
    Write-Info "Docker service: $mailpitContainerName ($mailpitContainerState), SMTP 127.0.0.1:$SmtpPort -> 1025, API 127.0.0.1:$SmtpApiPort -> 8025"

    Write-Info "Waiting for Mailpit readiness..."
    $mailpitReady = $false
    $mailpitApiUrl = "http://127.0.0.1:${SmtpApiPort}/api/v1/messages"
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $mailpitResponse = Invoke-WebRequest -UseBasicParsing -Uri $mailpitApiUrl -TimeoutSec 2
            if ($mailpitResponse.StatusCode -eq 200) {
                $mailpitReady = $true
                break
            }
        } catch {
            # Mailpit may need a few seconds before its HTTP listener is ready.
        }
        Start-Sleep -Seconds 1
    }
    if (-not $mailpitReady) {
        throw "Mailpit did not become ready within 30 seconds."
    }
    Write-Success "Mailpit is ready."

    $testDbPassword = (Get-Content -LiteralPath $testPasswordFile -Raw).Trim()
    # Base64 passwords can contain URL-reserved characters such as '/', so encode them before building the DSN.
    $encodedTestDbPassword = [System.Uri]::EscapeDataString($testDbPassword)
    $env:TEST_DATABASE_URL = "postgres://postgres:${encodedTestDbPassword}@127.0.0.1:${DatabasePort}/keylo_test"
    $env:DATABASE_PASSWORD_ENC_FILE = $testPasswordEncFile
    $env:DATABASE_PASSWORD_KEY_FILE = $testPasswordKeyFile
    $env:SMTP_TEST_HOST = "127.0.0.1"
    $env:SMTP_TEST_PORT = [string]$SmtpPort
    $env:SMTP_TEST_API_URL = $mailpitApiUrl
    $env:SMTP_TEST_CONTAINER_NAME = $mailpitContainerName
    $env:RUST_TEST_THREADS = "1"

    Write-Info "Running formatting checks..."
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "Formatting check failed." }
    Write-Success "Formatting checks passed."

    Write-Info "Running workspace Clippy checks..."
    cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "Clippy checks failed." }
    Write-Success "Workspace Clippy checks passed."

    Write-Info "Running workspace tests with one test thread..."
    cargo test --workspace --all-targets -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "Workspace tests failed." }
    Write-Success "Workspace tests passed."
    $succeeded = $true
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Write-Info "Cleaning up Docker test resources..."
    Remove-TestResources
    Remove-Item Env:SMTP_TEST_HOST -ErrorAction SilentlyContinue
    Remove-Item Env:SMTP_TEST_PORT -ErrorAction SilentlyContinue
    Remove-Item Env:SMTP_TEST_API_URL -ErrorAction SilentlyContinue
    Remove-Item Env:SMTP_TEST_CONTAINER_NAME -ErrorAction SilentlyContinue
    Write-Success "Docker test resources cleaned up."
}

if (-not $succeeded) {
    exit 1
}

Write-Success "All local Docker validation checks completed successfully."

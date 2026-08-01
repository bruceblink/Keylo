[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path
)

$ErrorActionPreference = "Stop"

$requiredScenarios = @(
    "first_login",
    "repeat_login",
    "userinfo_completion",
    "email_change",
    "disabled_keylo_user",
    "disabled_identity_source"
)
$forbiddenFieldPattern = '(?i)(secret|password|token|authorization.?code|client.?credential|private.?key)'

function Assert-Property([object]$Object, [string]$Name) {
    if ($null -eq $Object.PSObject.Properties[$Name]) {
        throw "Artifact is missing required field: $Name"
    }
}

function Assert-NoSensitiveFields([object]$Object, [string]$Location = "artifact") {
    if ($null -eq $Object) {
        return
    }
    if ($Object -is [string] -or $Object.GetType().IsValueType) {
        return
    }
    if ($Object -is [System.Collections.IEnumerable]) {
        $index = 0
        foreach ($item in $Object) {
            Assert-NoSensitiveFields $item "$Location[$index]"
            $index++
        }
        return
    }
    if ($Object.PSObject.Properties.Count -gt 0) {
        foreach ($property in $Object.PSObject.Properties) {
            if ($property.Name -match $forbiddenFieldPattern) {
                throw "Sensitive field is not allowed in matrix artifacts: $Location.$($property.Name)"
            }
            Assert-NoSensitiveFields $property.Value "$Location.$($property.Name)"
        }
    }
}

if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Artifact file does not exist: $Path"
}

$artifact = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
foreach ($field in @("executed_at_utc", "keylo_commit", "keycloak_version", "keycloak_image_digest", "status", "scenarios")) {
    Assert-Property $artifact $field
}
Assert-NoSensitiveFields $artifact

if ([string]$artifact.keycloak_image_digest -notmatch '^sha256:[a-f0-9]{64}$') {
    throw "keycloak_image_digest must be a sha256 image digest"
}

if ([string]$artifact.status -notin @("passed", "failed", "not_executed")) {
    throw "Artifact status must be passed, failed, or not_executed"
}

$scenarioMap = @{}
foreach ($scenario in @($artifact.scenarios)) {
    Assert-Property $scenario "name"
    Assert-Property $scenario "status"
    if ($scenario.status -notin @("passed", "failed", "not_executed")) {
        throw "Scenario '$($scenario.name)' has an invalid status"
    }
    if ($scenarioMap.ContainsKey([string]$scenario.name)) {
        throw "Scenario is duplicated: $($scenario.name)"
    }
    $scenarioMap[[string]$scenario.name] = [string]$scenario.status
}

foreach ($name in $requiredScenarios) {
    if (!$scenarioMap.ContainsKey($name)) {
        throw "Artifact is missing required scenario: $name"
    }
}
if ($scenarioMap.Count -ne $requiredScenarios.Count) {
    throw "Artifact contains an unknown scenario"
}

$failed = @($scenarioMap.GetEnumerator() | Where-Object { $_.Value -eq "failed" })
$notExecuted = @($scenarioMap.GetEnumerator() | Where-Object { $_.Value -eq "not_executed" })
if ($artifact.status -eq "passed" -and ($failed.Count -gt 0 -or $notExecuted.Count -gt 0)) {
    throw "Artifact cannot be passed while a scenario is failed or not_executed"
}
if ($failed.Count -gt 0) {
    Write-Host "[FAILED] Keycloak OIDC matrix artifact is structurally valid but contains failed scenarios" -ForegroundColor Red
    exit 1
}
if ($notExecuted.Count -gt 0) {
    Write-Host "[NOT_EXECUTED] Keycloak OIDC matrix artifact is structurally valid but incomplete" -ForegroundColor Yellow
    exit 2
}

Write-Host "[SUCCESS] Keycloak OIDC matrix artifact is complete and sanitized" -ForegroundColor Green
exit 0

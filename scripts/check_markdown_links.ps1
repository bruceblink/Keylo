[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot "..")
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$markdownPattern = '\[[^\]]*\]\((?<target>[^)\r\n]+)\)'

function Get-MarkdownFiles([string]$Root) {
    $readme = Join-Path $Root "README.md"
    if (Test-Path -LiteralPath $readme -PathType Leaf) {
        Write-Output $readme
    }

    Get-ChildItem -LiteralPath (Join-Path $Root "docs") -Recurse -Filter "*.md" -File |
        ForEach-Object { $_.FullName }
}

function Get-RelativeMarkdownLinks([string]$Path) {
    # Ignore fenced examples so command snippets do not become accidental link targets.
    $insideFence = $false
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber++
        if ($line -match '^\s*(```|~~~)') {
            $insideFence = -not $insideFence
            continue
        }
        if ($insideFence) {
            continue
        }

        foreach ($match in [regex]::Matches($line, $markdownPattern)) {
            $target = $match.Groups["target"].Value.Trim()
            if ([string]::IsNullOrWhiteSpace($target)) {
                continue
            }
            if ($target.StartsWith("#") -or $target -match '^(?i)(https?|mailto|tel):') {
                continue
            }

            $target = ($target -split '#', 2)[0].Trim().Trim('<', '>')
            if ([string]::IsNullOrWhiteSpace($target)) {
                continue
            }

            [pscustomobject]@{
                Target = [Uri]::UnescapeDataString($target)
                Line = $lineNumber
            }
        }
    }
}

$brokenLinks = [System.Collections.Generic.List[string]]::new()
foreach ($file in Get-MarkdownFiles $repositoryRoot) {
    $baseDirectory = Split-Path -Parent $file
    $relativeFile = $file.Substring($repositoryRoot.Length + 1)
    foreach ($link in Get-RelativeMarkdownLinks $file) {
        $targetPath = $link.Target -replace '/', [IO.Path]::DirectorySeparatorChar
        $resolvedPath = [IO.Path]::GetFullPath((Join-Path $baseDirectory $targetPath))
        if (-not (Test-Path -LiteralPath $resolvedPath)) {
            $brokenLinks.Add("$relativeFile`:$($link.Line) -> $($link.Target)")
        }
    }
}

if ($brokenLinks.Count -gt 0) {
    Write-Error ("Broken relative Markdown links:`n" + ($brokenLinks -join "`n"))
    exit 1
}

Write-Host "[SUCCESS] Markdown relative links are valid." -ForegroundColor Green

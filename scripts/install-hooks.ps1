# 将 pre-commit hook 安装到本地 .git/hooks/
# 用法：.\scripts\install-hooks.ps1
# 注意：需要 Git for Windows（附带 sh.exe）才能执行 shell hook

$hookSrc = "scripts\pre-commit.hook"
$hookDst = ".git\hooks\pre-commit"

if (-not (Test-Path $hookSrc)) {
    Write-Error "ERROR: $hookSrc not found. Run this script from the repo root."
    exit 1
}

Copy-Item -Force $hookSrc $hookDst
Write-Host "pre-commit hook installed to $hookDst"
Write-Host "Note: Git for Windows (sh.exe) is required to execute the hook."

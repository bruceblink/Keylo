#!/usr/bin/env sh
# 将 pre-commit hook 安装到本地 .git/hooks/
# 用法：sh scripts/install-hooks.sh
set -e

HOOK_SRC="scripts/pre-commit.hook"
HOOK_DST=".git/hooks/pre-commit"

if [ ! -f "$HOOK_SRC" ]; then
    echo "ERROR: $HOOK_SRC not found. Run this script from the repo root."
    exit 1
fi

cp "$HOOK_SRC" "$HOOK_DST"
chmod +x "$HOOK_DST"
echo "pre-commit hook installed to $HOOK_DST"

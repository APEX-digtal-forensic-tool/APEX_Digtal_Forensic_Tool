$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $RepoRoot
try {
    uv sync --locked --extra desktop --extra desktop-build --extra report-renderer
    if ($LASTEXITCODE -ne 0) { throw 'Runtime dependency installation failed' }
    uv run --no-sync python tools/build_desktop_runtime.py
    if ($LASTEXITCODE -ne 0) { throw 'Runtime packaging failed' }
} finally { Pop-Location }

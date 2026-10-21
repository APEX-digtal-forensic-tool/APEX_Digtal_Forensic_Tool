# Launch the APEX desktop GUI (dev mode) with the live AI provider connected.
# The API key is never stored here: it is read from the Windows user environment.
param(
    [string]$ProviderId = "moonshot-kimi",
    [string]$BaseUrl = "https://api.moonshot.ai/v1",
    [string]$Model = "kimi-k3",
    [string]$KeyEnv = "APEX_AI_API_KEY",
    [double]$Temperature = 1.0,
    [int]$MaxOutput = 16384,
    [double]$Timeout = 240
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not (Get-Item "env:$KeyEnv" -ErrorAction SilentlyContinue)) {
    $value = [Environment]::GetEnvironmentVariable($KeyEnv, "User")
    if (-not $value) { throw "$KeyEnv is not set (setx $KeyEnv <key>)." }
    Set-Item "env:$KeyEnv" $value
}

$env:APEX_DESKTOP_AI_CONFIG = (@{
    provider_id = $ProviderId
    base_url    = $BaseUrl
    model_id    = $Model
    api_key_env = $KeyEnv
    temperature = $Temperature
    max_output  = $MaxOutput
    timeout     = $Timeout
} | ConvertTo-Json -Compress)

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Missing $python (run: uv sync --extra desktop)." }

Push-Location (Join-Path $root "frontend")
try { npm run dev } finally { Pop-Location }

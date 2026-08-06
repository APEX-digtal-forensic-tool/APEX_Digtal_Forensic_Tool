[CmdletBinding()]
param(
    [string]$Python = "",
    [string]$FixtureRoot = "",
    [string]$FixtureManifestPath = "",
    [string]$ResultPath = "",
    [string]$NssLibraryPath = "",
    [int]$TimeoutSeconds = 120,
    [switch]$KeepFixtures,
    [switch]$SkipHostExecution
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$CreatedFixtureRoot = $false

function Resolve-ApexPython {
    param([string]$RequestedPython)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPython)) {
        return $RequestedPython
    }

    $venvPython = Join-Path $env:TEMP "apex-advanced-runtime-venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        return $venvPython
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $pythonCommand) {
        return $pythonCommand.Source
    }

    $pyCommand = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $pyCommand) {
        return $pyCommand.Source
    }

    throw "Python was not found. Create $env:TEMP\apex-advanced-runtime-venv or pass -Python."
}

function Invoke-ApexJsonCommand {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [int]$Timeout
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    foreach ($Argument in $Arguments) {
        [void]$psi.ArgumentList.Add($Argument)
    }
    $psi.WorkingDirectory = $RepoRoot
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $process) {
        throw "Failed to start Python verifier."
    }
    if (-not $process.WaitForExit($Timeout * 1000)) {
        try {
            $process.Kill($true)
        } catch {
            $process.Kill()
        }
        throw "Verifier timed out after $Timeout seconds."
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    if ($process.ExitCode -ne 0) {
        throw "Verifier failed with exit code $($process.ExitCode): $stderr"
    }
    return $stdout | ConvertFrom-Json
}

function Test-ApexAiProviderReady {
    $keyEnv = [Environment]::GetEnvironmentVariable("APEX_AI_VERIFY_API_KEY_ENV")
    if ([string]::IsNullOrWhiteSpace($keyEnv)) {
        return $false
    }
    $baseUrlConfigured = -not [string]::IsNullOrWhiteSpace(
        [Environment]::GetEnvironmentVariable("APEX_AI_VERIFY_BASE_URL")
    )
    $modelConfigured = -not [string]::IsNullOrWhiteSpace(
        [Environment]::GetEnvironmentVariable("APEX_AI_VERIFY_MODEL")
    )
    $keyConfigured = -not [string]::IsNullOrWhiteSpace(
        [Environment]::GetEnvironmentVariable($keyEnv)
    )
    return $baseUrlConfigured -and $modelConfigured -and $keyConfigured
}

function Get-ApexJsonProperty {
    param(
        [object]$Object,
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ""
    }
    return [string]$property.Value
}

function Resolve-ApexManifestPath {
    param(
        [string]$ManifestDirectory,
        [object]$Section,
        [string]$Name
    )

    $relative = Get-ApexJsonProperty -Object $Section -Name ($Name + "_relative")
    $value = if (-not [string]::IsNullOrWhiteSpace($relative)) {
        $relative
    } else {
        Get-ApexJsonProperty -Object $Section -Name $Name
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        return ""
    }
    if ([System.IO.Path]::IsPathRooted($value)) {
        return [System.IO.Path]::GetFullPath($value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $ManifestDirectory $value))
}

$Python = Resolve-ApexPython -RequestedPython $Python
$UsingExistingManifest = -not [string]::IsNullOrWhiteSpace($FixtureManifestPath)
if ($UsingExistingManifest) {
    $ManifestPath = (Resolve-Path -LiteralPath $FixtureManifestPath).Path
    if ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
        $FixtureRoot = Split-Path -Parent $ManifestPath
    }
} elseif ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
    $FixtureRoot = Join-Path $env:TEMP ("apex-windows-runtime-fixtures-" + [guid]::NewGuid())
    $CreatedFixtureRoot = $true
}
if ([string]::IsNullOrWhiteSpace($ResultPath)) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $ResultPath = Join-Path $env:TEMP "apex-windows-runtime-verification-$stamp.json"
}
if (-not $UsingExistingManifest) {
    $ManifestPath = Join-Path $FixtureRoot "windows-runtime-fixtures.manifest.json"
}
$env:APEX_DPAPI_FIXTURE_PASSWORD = "apex synthetic dpapi fixture password v1"
$env:APEX_NSS_PRIMARY_PASSWORD = "apex synthetic nss primary password v1"

try {
    if ($UsingExistingManifest) {
        $generation = [ordered]@{
            status = "PREGENERATED_MANIFEST"
            manifest_path = $ManifestPath
            secret_values_emitted = $false
        }
    } else {
        $generatorArgs = @(
            (Join-Path $RepoRoot "tools\generate_windows_runtime_fixtures.py"),
            "--output-dir",
            $FixtureRoot,
            "--manifest-path",
            $ManifestPath,
            "--require-all",
            "--json"
        )
        if (-not [string]::IsNullOrWhiteSpace($NssLibraryPath)) {
            $generatorArgs += @("--nss-library-path", $NssLibraryPath)
        }
        $generation = Invoke-ApexJsonCommand `
            -Executable $Python `
            -Arguments $generatorArgs `
            -Timeout $TimeoutSeconds
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $ManifestDirectory = Split-Path -Parent $ManifestPath
    $dpapiInputFile = Resolve-ApexManifestPath `
        -ManifestDirectory $ManifestDirectory `
        -Section $manifest.dpapi `
        -Name "input_file"
    $dpapiLocalStatePath = Resolve-ApexManifestPath `
        -ManifestDirectory $ManifestDirectory `
        -Section $manifest.dpapi `
        -Name "local_state_path"
    $dpapiChromiumInputFile = Resolve-ApexManifestPath `
        -ManifestDirectory $ManifestDirectory `
        -Section $manifest.dpapi `
        -Name "chromium_input_file"
    $dpapiMasterkeyPath = Resolve-ApexManifestPath `
        -ManifestDirectory $ManifestDirectory `
        -Section $manifest.dpapi `
        -Name "masterkey_path"
    $nssRootPath = Resolve-ApexManifestPath `
        -ManifestDirectory $ManifestDirectory `
        -Section $manifest.nss `
        -Name "root_path"
    $nssProfilePath = Resolve-ApexManifestPath `
        -ManifestDirectory $ManifestDirectory `
        -Section $manifest.nss `
        -Name "profile_path"

    $dpapiArgs = @(
        (Join-Path $RepoRoot "tools\verify_dpapi_runtime.py"),
        "--input-file",
        $dpapiInputFile,
        "--local-state-path",
        $dpapiLocalStatePath,
        "--decrypt-local-state-key",
        "--chromium-input-file",
        $dpapiChromiumInputFile,
        "--sid",
        $manifest.dpapi.sid,
        "--masterkey-path",
        $dpapiMasterkeyPath,
        "--password-env",
        "APEX_DPAPI_FIXTURE_PASSWORD",
        "--require-available"
    )
    $dpapiResult = Invoke-ApexJsonCommand `
        -Executable $Python `
        -Arguments $dpapiArgs `
        -Timeout $TimeoutSeconds

    $nssArgs = @(
        (Join-Path $RepoRoot "tools\verify_nss_runtime.py"),
        "--root-path",
        $nssRootPath,
        "--profile-path",
        $nssProfilePath,
        "--primary-password-env",
        "APEX_NSS_PRIMARY_PASSWORD",
        "--require-available"
    )
    $nssResult = Invoke-ApexJsonCommand `
        -Executable $Python `
        -Arguments $nssArgs `
        -Timeout $TimeoutSeconds

    $hostArgs = @(
        (Join-Path $RepoRoot "tools\verify_windows_host_runtime.py"),
        "--python",
        $Python,
        "--fixture-manifest",
        $ManifestPath,
        "--timeout",
        [string]$TimeoutSeconds
    )
    if ($SkipHostExecution) {
        $hostArgs += "--skip-execution"
    }
    $hostResult = Invoke-ApexJsonCommand `
        -Executable $Python `
        -Arguments $hostArgs `
        -Timeout $TimeoutSeconds

    $expectedMatches = [ordered]@{
        dpapi_blob = (
            $dpapiResult.decrypt.status -eq $manifest.dpapi.expected_redacted_result.dpapi_blob.status `
            -and $dpapiResult.decrypt.content_sha256 -eq `
                $manifest.dpapi.expected_redacted_result.dpapi_blob.content_sha256
        )
        chromium_local_state_key = (
            $dpapiResult.local_state_decrypt.status -eq `
                $manifest.dpapi.expected_redacted_result.chromium_local_state_key.status `
            -and $dpapiResult.local_state_decrypt.content_sha256 -eq `
                $manifest.dpapi.expected_redacted_result.chromium_local_state_key.content_sha256
        )
        chromium_secret = (
            $dpapiResult.chromium_decrypt.status -eq `
                $manifest.dpapi.expected_redacted_result.chromium_secret.status `
            -and $dpapiResult.chromium_decrypt.content_sha256 -eq `
                $manifest.dpapi.expected_redacted_result.chromium_secret.content_sha256
        )
        nss_login_count = (
            $nssResult.decrypt.Count -eq $manifest.nss.expected_login_count
        )
    }

    $aiStatus = if (Test-ApexAiProviderReady) {
        "CONFIGURED_FOR_LIVE_SMOKE"
    } else {
        "EXTERNAL_PROVIDER_NOT_CONFIGURED"
    }

    $payload = [ordered]@{
        schema_version = "apex.windows-runtime-verification.v1"
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        fixture_manifest_path = $ManifestPath
        fixture_generation = $generation
        host_platform = [System.Environment]::OSVersion.VersionString
        secret_values_emitted = $false
        windows_runtime_success_claimed = $hostResult.windows_runtime_success_claimed
        expected_matches = $expectedMatches
        dpapi = $dpapiResult
        nss = $nssResult
        windows_host = $hostResult
        ai_provider_status = $aiStatus
        kakaotalk_status = "BLOCKED_EXTERNAL_FIXTURE"
    }

    $ResultDirectory = Split-Path -Parent $ResultPath
    if (-not [string]::IsNullOrWhiteSpace($ResultDirectory)) {
        New-Item -ItemType Directory -Force -Path $ResultDirectory | Out-Null
    }
    $json = $payload | ConvertTo-Json -Depth 80
    [System.IO.File]::WriteAllText(
        $ResultPath,
        $json + [System.Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Output $ResultPath
} finally {
    Remove-Item Env:\APEX_DPAPI_FIXTURE_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:\APEX_NSS_PRIMARY_PASSWORD -ErrorAction SilentlyContinue
    if ($CreatedFixtureRoot -and -not $KeepFixtures -and (Test-Path -LiteralPath $FixtureRoot)) {
        Remove-Item -LiteralPath $FixtureRoot -Recurse -Force
    }
}

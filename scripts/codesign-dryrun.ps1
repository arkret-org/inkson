#requires -Version 7.0
<#
.SYNOPSIS
    Reproducible codesign / notarization DRY-RUN for yougen desktop.

.DESCRIPTION
    NOT FOR PRODUCTION USE. This script never submits to Apple, Microsoft
    timestamp authorities, or external signing services. It records what
    the live signing flow WOULD do given the current host environment,
    and surfaces missing inputs (signing identity, timestamp authority,
    notary credentials) before they trip a real release.

    P5 (2026-05-27): replaces the platform-conditional branches of
    `signing-dry-run.ps1` with a single reproducible plan that:
      - emits a stable JSON evidence schema per platform
      - hashes the artifact (sha256) for reproducibility checks
      - records the script version + host metadata
      - never reaches out to a remote service

.PARAMETER ArtifactPath
    Path to the desktop binary. Defaults per host OS.

.PARAMETER DistDir
    Where to write evidence. Default: dist/signing/.

.PARAMETER NoBuild
    Skip `cargo build --release` even if the artifact is missing.

.EXAMPLE
    pwsh -File scripts/codesign-dryrun.ps1
#>
param(
    [string]$ArtifactPath,
    [string]$DistDir = "dist/signing",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

$SCRIPT_VERSION = "P5.codesign-dryrun.v1"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $isWindowsHost = ($PSVersionTable.PSEdition -eq "Desktop") -or `
                     ($PSVersionTable.Platform -eq "Win32NT") -or `
                     ($env:OS -eq "Windows_NT")
    $isMacHost = $false
    $isLinuxHost = $false
    if (-not $isWindowsHost) {
        try {
            $uname = (& uname -s).Trim()
            $isMacHost = $uname -eq "Darwin"
            $isLinuxHost = $uname -eq "Linux"
        } catch {
            $isLinuxHost = $true
        }
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    if (-not $ArtifactPath) {
        if ($isWindowsHost) {
            $ArtifactPath = "target/release/yougen.exe"
        } else {
            $ArtifactPath = "target/release/yougen"
        }
    }

    if (-not $NoBuild -and -not (Test-Path -LiteralPath $ArtifactPath)) {
        Write-Host "Artifact missing; running cargo build --release"
        & cargo build --release
    }

    $artifactExists = Test-Path -LiteralPath $ArtifactPath
    $artifactHash = $null
    if ($artifactExists) {
        $artifactHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToLowerInvariant()
    }

    $evidence = [ordered]@{
        schema = "yougen/codesign-dryrun/v1"
        script_version = $SCRIPT_VERSION
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        host = [ordered]@{
            os = if ($isMacHost) { "darwin" } elseif ($isWindowsHost) { "windows" } else { "linux" }
            ps_edition = $PSVersionTable.PSEdition
            ps_version = $PSVersionTable.PSVersion.ToString()
        }
        artifact = [ordered]@{
            path = $ArtifactPath
            exists = $artifactExists
            sha256 = $artifactHash
        }
        production_use = $false
        remote_submit = $false
        timestamp_server = $false
        transparency_log = $false
        platforms = @()
        notes = @(
            "NOT FOR PRODUCTION USE — this is a reproducible dry-run only.",
            "No remote endpoint (Apple notarytool, MS timestamp authority, GPG keyserver) is contacted.",
            "Real signing happens through a separate manual flow with a paid Developer ID / EV cert."
        )
    }

    if ($isMacHost) {
        $codesign = Get-Command codesign -ErrorAction SilentlyContinue
        $xcrun = Get-Command xcrun -ErrorAction SilentlyContinue
        $identity = $env:YOUGEN_MACOS_SIGN_IDENTITY
        $mac = [ordered]@{
            platform = "macos"
            codesign_available = [bool]$codesign
            signing_identity_present = [bool]$identity
            notarytool_available = [bool]$xcrun
            notary_input_present = [bool]($env:APPLE_ID -and $env:APPLE_TEAM_ID -and `
                ($env:APPLE_APP_SPECIFIC_PASSWORD -or $env:APPLE_KEYCHAIN_PROFILE))
            would_sign = ($artifactExists -and $codesign -and $identity)
            would_submit_notary = $false
            would_staple = $false
            notes = @(
                "Local plan validates codesign/notarytool inputs only.",
                "Never runs notarytool submit or stapler in dry-run mode."
            )
        }
        $evidence.platforms += $mac
    } elseif ($isWindowsHost) {
        $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        $certPath = $env:YOUGEN_WINDOWS_CERT_PATH
        $win = [ordered]@{
            platform = "windows"
            signtool_available = [bool]$signtool
            certificate_path_present = [bool]$certPath
            certificate_path_exists = [bool]($certPath -and (Test-Path -LiteralPath $certPath))
            would_sign = ($artifactExists -and $signtool -and $certPath -and `
                (Test-Path -LiteralPath ([string]$certPath)))
            would_timestamp = $false
            notes = @(
                "Local signing omits /tr and /t so no timestamp authority is contacted.",
                "Dry-run plan only — no signtool sign invocation."
            )
        }
        $evidence.platforms += $win
    } else {
        $gpg = Get-Command gpg -ErrorAction SilentlyContinue
        $tarball = Join-Path $DistDir "yougen-linux-x64.tar.gz"
        $linux = [ordered]@{
            platform = "linux"
            gpg_available = [bool]$gpg
            tarball = $tarball
            would_tar = $artifactExists
            would_sign = ($artifactExists -and [bool]$gpg)
            detached_signature_path = "$tarball.asc"
            package_formats = @("tar.gz", "deb", "rpm", "AppImage", "Flatpak")
            notes = @(
                "Plan only — no tar / gpg invocation in dry-run mode.",
                "Real package builds live in scripts/linux-package-local.ps1."
            )
        }
        $evidence.platforms += $linux
    }

    $evidencePath = Join-Path $DistDir "codesign-dryrun.json"
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $evidencePath
    Write-Host "Wrote codesign dry-run evidence to $evidencePath"
    Write-Host "NOT FOR PRODUCTION USE — see SECURITY.md for the real signing flow."
}
finally {
    Pop-Location
}

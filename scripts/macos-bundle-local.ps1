param(
    [string]$BinaryPath,
    [string]$DistDir = "dist/macos-bundles",
    [string]$Version = "0.1.0-local"
)

# P3B.7.1 — macOS .app bundle generation, DRY-RUN.
#
# Produces `inkson.app` next to `inkson` in `dist/macos-bundles/` via
# either `cargo bundle` (if installed) or a hand-rolled bundle
# structure (Info.plist + Contents/MacOS/inkson). The signing path is
# delegated to `signing-dry-run.ps1` so this script never invokes
# `codesign` or `xcrun notarytool submit` directly. NO uploads happen
# anywhere in this script.

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib/cargo.ps1")

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $isMacHost = ($PSVersionTable.Platform -eq "Unix") -and ((uname -s) -eq "Darwin")
    if (-not $isMacHost) {
        Write-Host "macOS bundle creation skipped on non-Darwin runner."
        exit 0
    }

    if (-not $BinaryPath) {
        # `cargo build --release --features desktop` writes into the target directory configured
        # by the workspace-level `../.cargo/config.toml`, which is shared by
        # every sibling repository and is not `<repo>/target`. Ask cargo.
        $BinaryPath = Get-InksonBinaryPath -RepositoryRoot $repoRoot
    }

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        throw "inkson binary not found at $BinaryPath — run `cargo build --release --features desktop` first"
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $cargoBundle = Get-Command cargo-bundle -ErrorAction SilentlyContinue

    $evidence = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        binary = $BinaryPath
        version = $Version
        bundler = $null
        bundle_path = $null
        signed = $false
        notarized = $false
        notes = @("DRY-RUN: nothing is uploaded; codesign / notarytool only run when signing-dry-run.ps1 is invoked separately.")
    }

    if ($cargoBundle) {
        Write-Host "Using cargo-bundle ($($cargoBundle.Source))"
        & cargo bundle --release --features desktop --target-dir $DistDir 2>&1 | Tee-Object -Variable bundleOutput
        $evidence.bundler = "cargo-bundle"
        $candidate = Get-ChildItem -Path $DistDir -Recurse -Filter "inkson.app" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) {
            $evidence.bundle_path = $candidate.FullName
        }
    }
    else {
        Write-Host "cargo-bundle is unavailable; creating the native .app layout."
        $appRoot = Join-Path $DistDir "inkson.app"
        $contents = Join-Path $appRoot "Contents"
        $macos = Join-Path $contents "MacOS"
        New-Item -ItemType Directory -Force -Path $macos | Out-Null
        Copy-Item -Force -LiteralPath $BinaryPath -Destination (Join-Path $macos "inkson")
        chmod 0755 (Join-Path $macos "inkson")
        $resources = Join-Path $contents "Resources"
        New-Item -ItemType Directory -Force -Path $resources | Out-Null
        $assetOutput = Join-Path $resources "assets"
        New-Item -ItemType Directory -Force -Path $assetOutput | Out-Null
        Get-ChildItem -LiteralPath (Join-Path $repoRoot "assets") -Force | Copy-Item -Destination $assetOutput -Recurse -Force

        $infoPlist = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>inkson</string>
  <key>CFBundleIdentifier</key><string>com.arkret.inkson</string>
  <key>CFBundleName</key><string>inkson</string>
  <key>CFBundleVersion</key><string>$Version</string>
  <key>CFBundleShortVersionString</key><string>$Version</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSCameraUsageDescription</key><string>Inkson uses the camera for video calls.</string>
  <key>NSMicrophoneUsageDescription</key><string>Inkson uses the microphone for calls.</string>
</dict>
</plist>
"@
        Set-Content -Path (Join-Path $contents "Info.plist") -Value $infoPlist
        $evidence.bundler = "hand-rolled"
        $evidence.bundle_path = $appRoot
    }

    if (-not $evidence.bundle_path) { throw "The native bundler produced no application bundle" }
    $finalContents = Join-Path $evidence.bundle_path "Contents"
    $finalPlist = Join-Path $finalContents "Info.plist"
    foreach ($permission in @(
        @{ Key = "NSCameraUsageDescription"; Text = "Inkson uses the camera for video calls." },
        @{ Key = "NSMicrophoneUsageDescription"; Text = "Inkson uses the microphone for calls." }
    )) {
        & /usr/bin/plutil -replace $permission.Key -string $permission.Text $finalPlist
        if ($LASTEXITCODE -ne 0) { throw "Could not set media permission metadata" }
    }
    $finalAssets = Join-Path $finalContents "Resources/assets"
    New-Item -ItemType Directory -Force -Path $finalAssets | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $repoRoot "assets") -Force | Copy-Item -Destination $finalAssets -Recurse -Force

    $evidencePath = Join-Path $DistDir "macos-bundle.json"
    $evidence | ConvertTo-Json -Depth 5 | Set-Content -Path $evidencePath
    Write-Host "Wrote evidence to $evidencePath"
    Write-Host "Bundle complete (DRY-RUN). No uploads performed."
}
finally {
    Pop-Location
}

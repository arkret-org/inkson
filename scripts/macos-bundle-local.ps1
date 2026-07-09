param(
    [string]$BinaryPath = "target/release/inkson",
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

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $isMacHost = ($PSVersionTable.Platform -eq "Unix") -and ((uname -s) -eq "Darwin")
    if (-not $isMacHost) {
        Write-Host "macOS bundle creation skipped on non-Darwin runner."
        exit 0
    }

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        throw "inkson binary not found at $BinaryPath — run `cargo build --release` first"
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $cargoBundle = Get-Command cargo-bundle -ErrorAction SilentlyContinue
    $dxBundle = Get-Command dx -ErrorAction SilentlyContinue

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
        & cargo bundle --release --target-dir $DistDir 2>&1 | Tee-Object -Variable bundleOutput
        $evidence.bundler = "cargo-bundle"
        $candidate = Get-ChildItem -Path $DistDir -Recurse -Filter "inkson.app" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) {
            $evidence.bundle_path = $candidate.FullName
        }
    }
    elseif ($dxBundle) {
        Write-Host "Using dx bundle ($($dxBundle.Source))"
        & dx bundle --release --platform macos --out-dir $DistDir 2>&1 | Tee-Object -Variable bundleOutput
        $evidence.bundler = "dx"
        $candidate = Get-ChildItem -Path $DistDir -Recurse -Filter "*.app" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) {
            $evidence.bundle_path = $candidate.FullName
        }
    }
    else {
        Write-Host "Neither cargo-bundle nor dx found — falling back to hand-rolled .app layout."
        $appRoot = Join-Path $DistDir "inkson.app"
        $contents = Join-Path $appRoot "Contents"
        $macos = Join-Path $contents "MacOS"
        New-Item -ItemType Directory -Force -Path $macos | Out-Null
        Copy-Item -Force -LiteralPath $BinaryPath -Destination (Join-Path $macos "inkson")
        chmod 0755 (Join-Path $macos "inkson")

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
</dict>
</plist>
"@
        Set-Content -Path (Join-Path $contents "Info.plist") -Value $infoPlist
        $evidence.bundler = "hand-rolled"
        $evidence.bundle_path = $appRoot
    }

    $evidencePath = Join-Path $DistDir "macos-bundle.json"
    $evidence | ConvertTo-Json -Depth 5 | Set-Content -Path $evidencePath
    Write-Host "Wrote evidence to $evidencePath"
    Write-Host "Bundle complete (DRY-RUN). No uploads performed."
}
finally {
    Pop-Location
}

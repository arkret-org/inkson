param(
    [string]$BinaryPath,
    [string]$DistDir = "dist/linux-packages",
    [string]$Version = "0.9.0-local"
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib/cargo.ps1")

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $isWindowsHost = ($PSVersionTable.PSEdition -eq "Desktop") -or ($PSVersionTable.Platform -eq "Win32NT") -or ($env:OS -eq "Windows_NT")
    $isMacHost = ($PSVersionTable.Platform -eq "Unix") -and ((uname -s) -eq "Darwin")

    if ($isWindowsHost -or $isMacHost) {
        Write-Host "Linux package creation skipped on non-Linux runner."
        exit 0
    }

    if (-not $BinaryPath) {
        # `cargo build --release --features desktop` writes into the target directory configured
        # by the workspace-level `../.cargo/config.toml`, which is shared by
        # every sibling repository and is not `<repo>/target`. Ask cargo.
        $BinaryPath = Get-InksonBinaryPath -RepositoryRoot $repoRoot
    }

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        throw "binary not found at $BinaryPath"
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $dpkgDeb = Get-Command dpkg-deb -ErrorAction SilentlyContinue
    $evidence = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        binary = $BinaryPath
        formats = @()
    }

    if ($dpkgDeb) {
        $pkgRoot = Join-Path $DistDir "deb-root"
        $installDir = Join-Path $pkgRoot "usr/bin"
        $controlDir = Join-Path $pkgRoot "DEBIAN"
        New-Item -ItemType Directory -Force -Path $installDir, $controlDir | Out-Null
        Copy-Item -Force -LiteralPath $BinaryPath -Destination (Join-Path $installDir "inkson")
        chmod 0755 (Join-Path $installDir "inkson")

        @"
Package: inkson
Version: $Version
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Arkret Local Release <local-release@example.invalid>
Description: Arkret cross-platform client local package
"@ | Set-Content -Encoding ASCII -Path (Join-Path $controlDir "control")

        $debPath = Join-Path $DistDir "inkson_${Version}_amd64.deb"
        & dpkg-deb --build $pkgRoot $debPath
        $hashPath = "$debPath.sha256"
        Get-FileHash -Algorithm SHA256 -LiteralPath $debPath |
            ForEach-Object { "$($_.Hash.ToLowerInvariant())  $(Split-Path -Leaf $debPath)" } |
            Set-Content -Encoding ASCII -Path $hashPath
        $evidence.formats += [ordered]@{ format = "deb"; path = $debPath; sha256 = $hashPath }
    }

    $rpmBuild = Get-Command rpmbuild -ErrorAction SilentlyContinue
    $evidence.formats += [ordered]@{ format = "rpm"; available = [bool]$rpmBuild; note = "Use docs/RELEASING.md local-only rpmbuild strand when rpmbuild is installed." }

    $appImageTool = Get-Command appimagetool -ErrorAction SilentlyContinue
    $evidence.formats += [ordered]@{ format = "AppImage"; available = [bool]$appImageTool; note = "Use docs/RELEASING.md local-only AppDir strand when appimagetool is installed." }

    $flatpakBuilder = Get-Command flatpak-builder -ErrorAction SilentlyContinue
    $evidence.formats += [ordered]@{ format = "Flatpak"; available = [bool]$flatpakBuilder; note = "Use docs/RELEASING.md local-only flatpak-builder strand when installed; do not publish to Flathub." }

    $evidencePath = Join-Path $DistDir "linux-package-evidence.json"
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $evidencePath
    Write-Host "Wrote Linux package evidence to $evidencePath"
}
finally {
    Pop-Location
}

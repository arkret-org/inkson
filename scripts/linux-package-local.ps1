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

        # Derive runtime ABI dependencies from the actual ELF, rather than
        # retaining a manually maintained GTK/WebKit version list.
        if (-not (Get-Command dpkg-shlibdeps -ErrorAction SilentlyContinue)) {
            throw "dpkg-shlibdeps is required to describe native package dependencies"
        }
        $resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
        $dependencyRoot = Join-Path $DistDir "dependency-metadata"
        New-Item -ItemType Directory -Force -Path (Join-Path $dependencyRoot "debian") | Out-Null
        @"
Source: inkson
Section: utils
Priority: optional
Maintainer: Arkret Local Release <local-release@example.invalid>
Standards-Version: 4.6.2

Package: inkson
Architecture: any
Description: Arkret cross-platform client local package
"@ | Set-Content -Encoding ASCII -Path (Join-Path $dependencyRoot "debian/control")
        Push-Location $dependencyRoot
        try {
            $dependencyOutput = @(& dpkg-shlibdeps -O -e $resolvedBinary)
            if ($LASTEXITCODE -ne 0) {
                throw "dpkg-shlibdeps failed with exit code $LASTEXITCODE"
            }
        }
        finally {
            Pop-Location
        }
        $dependsLine = @($dependencyOutput | Where-Object { $_ -like "shlibs:Depends=*" })
        if ($dependsLine.Count -ne 1) {
            throw "dpkg-shlibdeps did not emit exactly one runtime dependency list"
        }
        $packageDepends = $dependsLine[0] -replace '^shlibs:Depends=', ''
        if (-not $packageDepends) {
            throw "dynamic desktop binary has no identified package dependencies"
        }
        $evidence.runtime_dependencies = $packageDepends

        @"
Package: inkson
Version: $Version
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Arkret Local Release <local-release@example.invalid>
Depends: $packageDepends
Description: Arkret cross-platform client local package
"@ | Set-Content -Encoding ASCII -Path (Join-Path $controlDir "control")

        $debPath = Join-Path $DistDir "inkson_${Version}_amd64.deb"
        & dpkg-deb --build $pkgRoot $debPath
        if ($LASTEXITCODE -ne 0) {
            throw "dpkg-deb failed with exit code $LASTEXITCODE"
        }
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

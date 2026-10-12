param(
    [string]$ArtifactPath,
    [string]$DistDir = "dist/signing",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib/cargo.ps1")

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $isWindowsHost = ($PSVersionTable.PSEdition -eq "Desktop") -or ($PSVersionTable.Platform -eq "Win32NT") -or ($env:OS -eq "Windows_NT")
    $isMacHost = ($PSVersionTable.Platform -eq "Unix") -and ((uname -s) -eq "Darwin")

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    if (-not $ArtifactPath) {
        # `cargo build --release --features desktop` writes into the target directory configured
        # by the workspace-level `../.cargo/config.toml`, which is shared by
        # every sibling repository and is not `<repo>/target`. Ask cargo.
        $ArtifactPath = Get-InksonBinaryPath -RepositoryRoot $repoRoot -WindowsBinary:$isWindowsHost
    }

    if (-not $NoBuild -and -not (Test-Path -LiteralPath $ArtifactPath)) {
        cargo build --locked --release --features desktop
        if ($LASTEXITCODE -ne 0) { throw "Desktop build failed: $LASTEXITCODE" }
    }

    $artifactExists = Test-Path -LiteralPath $ArtifactPath
    $evidence = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        artifact = $ArtifactPath
        artifact_exists = $artifactExists
        remote_submit = $false
        timestamp_server = $false
        transparency_log = $false
        platforms = @()
    }

    if ($isMacHost) {
        $codesign = Get-Command codesign -ErrorAction SilentlyContinue
        $xcrun = Get-Command xcrun -ErrorAction SilentlyContinue
        $identity = $env:INKSON_MACOS_SIGN_IDENTITY
        $mac = [ordered]@{
            platform = "macos"
            codesign_available = [bool]$codesign
            signing_identity_present = [bool]$identity
            signed = $false
            verified = $false
            notarytool_available = [bool]$xcrun
            notary_input_present = [bool]($env:APPLE_ID -and $env:APPLE_TEAM_ID -and ($env:APPLE_APP_SPECIFIC_PASSWORD -or $env:APPLE_KEYCHAIN_PROFILE))
            notary_submitted = $false
            stapled = $false
            notes = @("Local plan validates codesign/notarytool inputs only; it never runs notarytool submit or stapler.")
        }

        if ($artifactExists -and $codesign -and $identity) {
            & codesign --force --sign $identity --timestamp=none $ArtifactPath
            if ($LASTEXITCODE -ne 0) { throw "codesign signing failed: $LASTEXITCODE" }
            & codesign --verify --strict --verbose=2 $ArtifactPath
            if ($LASTEXITCODE -ne 0) { throw "codesign verification failed: $LASTEXITCODE" }
            $mac.signed = $true
            $mac.verified = $true
        }
        $evidence.platforms += $mac
    }
    elseif ($isWindowsHost) {
        $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        $certPath = $env:INKSON_WINDOWS_CERT_PATH
        $win = [ordered]@{
            platform = "windows"
            signtool_available = [bool]$signtool
            certificate_path_present = [bool]$certPath
            certificate_path_exists = [bool]($certPath -and (Test-Path -LiteralPath $certPath))
            signed = $false
            verified = $false
            timestamp_server = $false
            notes = @("Local signing omits /tr and /t so no timestamp authority is contacted.")
        }

        if ($artifactExists -and $signtool -and $certPath -and (Test-Path -LiteralPath $certPath)) {
            $args = @("sign", "/fd", "SHA256", "/f", $certPath)
            if ($env:INKSON_WINDOWS_CERT_PASSWORD) {
                $args += @("/p", $env:INKSON_WINDOWS_CERT_PASSWORD)
            }
            $args += $ArtifactPath
            & signtool.exe @args
            if ($LASTEXITCODE -ne 0) { throw "signtool signing failed: $LASTEXITCODE" }
            & signtool.exe verify /pa $ArtifactPath
            if ($LASTEXITCODE -ne 0) { throw "signtool verification failed: $LASTEXITCODE" }
            $win.signed = $true
            $win.verified = $true
        }
        $evidence.platforms += $win
    }
    else {
        $gpg = Get-Command gpg -ErrorAction SilentlyContinue
        $tarball = Join-Path $DistDir "inkson-linux-x64.tar.gz"
        $linux = [ordered]@{
            platform = "linux"
            gpg_available = [bool]$gpg
            signing_key_present = $false
            tarball = $tarball
            tarball_created = $false
            detached_signature = "$tarball.asc"
            detached_signature_created = $false
            detached_signature_verified = $false
            package_formats = @("tar.gz", "deb", "rpm", "AppImage", "Flatpak")
            notes = @("This script creates the tarball locally and signs only when a local secret key is present; docs/RELEASING.md lists local-only package commands for deb/rpm/AppImage/Flatpak.")
        }

        if ($artifactExists) {
            tar -czf $tarball -C (Split-Path -Parent $ArtifactPath) (Split-Path -Leaf $ArtifactPath)
            if ($LASTEXITCODE -ne 0) { throw "Tarball creation failed: $LASTEXITCODE" }
            $linux.tarball_created = $true
            if ($gpg) {
                $keyListing = @(& gpg --batch --with-colons --list-secret-keys)
                if ($LASTEXITCODE -ne 0) { throw "Local signing key discovery failed: $LASTEXITCODE" }
                $linux.signing_key_present = [bool]($keyListing | Where-Object { $_ -match '^sec:' })
                if ($linux.signing_key_present) {
                    & gpg --batch --yes --armor --detach-sign --output "$tarball.asc" $tarball
                    if ($LASTEXITCODE -ne 0) { throw "Detached signing failed: $LASTEXITCODE" }
                    $linux.detached_signature_created = $true
                    & gpg --batch --verify "$tarball.asc" $tarball
                    if ($LASTEXITCODE -ne 0) { throw "Detached signature verification failed: $LASTEXITCODE" }
                    $linux.detached_signature_verified = $true
                }
            }
        }
        $evidence.platforms += $linux
    }

    $evidencePath = Join-Path $DistDir "signing-dry-run.json"
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $evidencePath
    Write-Host "Wrote signing dry-run evidence to $evidencePath"
}
finally {
    Pop-Location
}

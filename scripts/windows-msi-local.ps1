param(
    [string]$BinaryPath,
    [string]$DistDir = "dist/windows-msi",
    [string]$Version = "0.1.0-local"
)

# P3B.7.2 — Windows .msi packaging, DRY-RUN.
#
# Generates a placeholder MSI via `cargo-wix` (if installed) or, when
# the WiX toolset is missing, writes a manifest .json stub that
# downstream signing-dry-run.ps1 can chew on. Nothing is signed with a
# real cert, nothing is uploaded.

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "lib/cargo.ps1")

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    $isWindowsHost = ($PSVersionTable.PSEdition -eq "Desktop") -or ($PSVersionTable.Platform -eq "Win32NT") -or ($env:OS -eq "Windows_NT")
    if (-not $isWindowsHost) {
        Write-Host "Windows MSI creation skipped on non-Windows runner."
        exit 0
    }

    if (-not $BinaryPath) {
        # `cargo build --release --features desktop` writes into the target directory configured
        # by the workspace-level `../.cargo/config.toml`, which is shared by
        # every sibling repository and is not `<repo>/target`. Ask cargo.
        $BinaryPath = Get-InksonBinaryPath -RepositoryRoot $repoRoot -WindowsBinary
    }

    if (-not (Test-Path -LiteralPath $BinaryPath)) {
        throw "inkson.exe not found at $BinaryPath — run `cargo build --release --features desktop` first"
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $cargoWix = Get-Command cargo-wix -ErrorAction SilentlyContinue
    $candle = Get-Command candle.exe -ErrorAction SilentlyContinue

    $evidence = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        binary = $BinaryPath
        version = $Version
        msi_path = $null
        signing_invoked = $false
        notes = @("DRY-RUN: no real cert used, nothing uploaded. cargo-wix produces a placeholder MSI for the signing-dry-run.ps1 hand-off.")
    }

    if ($cargoWix) {
        Write-Host "Using cargo-wix ($($cargoWix.Source))"
        & cargo wix init --force 2>&1 | Out-Host
        & cargo wix --no-build --nocapture --output (Join-Path $DistDir "inkson-$Version.msi") 2>&1 | Out-Host
        $msi = Get-ChildItem -Path $DistDir -Filter "*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($msi) {
            $evidence.msi_path = $msi.FullName
        }
    }
    elseif ($candle) {
        Write-Host "Falling back to raw WiX (candle.exe) — minimal wix harness only."
        $wxs = Join-Path $DistDir "inkson.wxs"
        @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="inkson" Language="1033" Version="$Version" Manufacturer="Arkret" UpgradeCode="00000000-0000-0000-0000-000000000000">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perUser" />
    <MediaTemplate />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="inkson" />
      </Directory>
    </Directory>
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="MainExecutable">
        <File Source="$BinaryPath" />
      </Component>
    </ComponentGroup>
    <Feature Id="MainFeature" Title="inkson" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
  </Product>
</Wix>
"@ | Set-Content -Path $wxs
        & candle.exe -out (Join-Path $DistDir "inkson.wixobj") $wxs
        $evidence.msi_path = (Join-Path $DistDir "inkson.wixobj")
    }
    else {
        Write-Host "Neither cargo-wix nor candle.exe found — writing stub manifest only."
        $stub = Join-Path $DistDir "inkson-$Version.msi.stub.json"
        @{
            warning = "Stub only — no real MSI generated"
            binary = $BinaryPath
            version = $Version
            host_missing = @("cargo-wix", "candle.exe")
        } | ConvertTo-Json -Depth 4 | Set-Content -Path $stub
        $evidence.msi_path = $stub
    }

    $evidencePath = Join-Path $DistDir "windows-msi.json"
    $evidence | ConvertTo-Json -Depth 5 | Set-Content -Path $evidencePath
    Write-Host "Wrote evidence to $evidencePath"
    Write-Host "MSI generation complete (DRY-RUN). No uploads, no real cert."
}
finally {
    Pop-Location
}

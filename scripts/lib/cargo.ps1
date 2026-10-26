# Shared helpers for locating cargo build output.
#
# Dot-source from a script in `scripts/`:
#   . (Join-Path $PSScriptRoot "lib/cargo.ps1")

function Get-CargoTargetDirectory {
    <#
    .SYNOPSIS
        Absolute path of the cargo target directory for a repository.

    .DESCRIPTION
        The workspace-level `../.cargo/config.toml` points `build.target-dir`
        at one directory shared by every sibling repository, so the artifacts
        `cargo build --release --features desktop` produces no longer land in `<repo>/target/`.
        Cargo knows where it writes; ask it instead of assuming a layout.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    if ($env:OS -eq "Windows_NT") {
        $cache = "D:/BuildCache/inkson-glory"
        if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = "$cache/target" }
        if (-not $env:CARGO_HOME) { $env:CARGO_HOME = "D:/BuildCache/cargo" }
        foreach ($value in @($env:CARGO_TARGET_DIR,$env:CARGO_HOME)) {
            if (-not [IO.Path]::GetFullPath($value).StartsWith("D:",[StringComparison]::OrdinalIgnoreCase)) { throw "Cargo cache and output must be on D:" }
        }
        New-Item -ItemType Directory -Force -Path "$cache/tmp" | Out-Null
        $env:TEMP = "$cache/tmp"; $env:TMP = "$cache/tmp"
        $env:PYTHONPYCACHEPREFIX = "$cache/pycache"
        $env:npm_config_cache = "D:/BuildCache/npm"
    }
    $manifest = Join-Path $RepositoryRoot "Cargo.toml"
    $metadata = & cargo metadata --locked --format-version 1 --no-deps --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE for $manifest"
    }

    $targetDirectory = ($metadata | ConvertFrom-Json).target_directory
    if ([string]::IsNullOrWhiteSpace($targetDirectory)) {
        throw "cargo metadata reported no target directory for $manifest"
    }

    if ($env:OS -eq "Windows_NT" -and -not [IO.Path]::GetFullPath($targetDirectory).StartsWith("D:",[StringComparison]::OrdinalIgnoreCase)) { throw "Cargo resolved an output directory outside D:" }
    return $targetDirectory
}

function Get-InksonBinaryPath {
    <#
    .SYNOPSIS
        Path `cargo build` writes the inkson binary to for the given profile.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [ValidateSet("debug", "release")]
        [string]$CargoProfile = "release",

        [switch]$WindowsBinary
    )

    $name = if ($WindowsBinary) { "inkson.exe" } else { "inkson" }
    return Join-Path (Get-CargoTargetDirectory -RepositoryRoot $RepositoryRoot) (Join-Path $CargoProfile $name)
}

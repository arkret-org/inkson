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

    $manifest = Join-Path $RepositoryRoot "Cargo.toml"
    $metadata = & cargo metadata --format-version 1 --no-deps --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE for $manifest"
    }

    $targetDirectory = ($metadata | ConvertFrom-Json).target_directory
    if ([string]::IsNullOrWhiteSpace($targetDirectory)) {
        throw "cargo metadata reported no target directory for $manifest"
    }

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

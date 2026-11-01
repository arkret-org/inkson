# Shared helpers for locating cargo build output.
#
# Dot-source from a script in `scripts/`:
#   . (Join-Path $PSScriptRoot "lib/cargo.ps1")

function Get-CargoTargetDirectory {
    <#
    .SYNOPSIS
        Absolute path of the cargo target directory for a repository.

    .DESCRIPTION
        Honor Cargo configuration and the inherited environment.
        Ask Cargo from the owning repository instead of assuming a layout.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
    $manifest = Join-Path $RepositoryRoot "Cargo.toml"
    Push-Location -LiteralPath $RepositoryRoot
    try {
        $metadata = & cargo metadata --locked --format-version 1 --no-deps --manifest-path $manifest
        if ($LASTEXITCODE -ne 0) {
            throw "cargo metadata failed with exit code $LASTEXITCODE for $manifest"
        }
    } finally { Pop-Location }

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

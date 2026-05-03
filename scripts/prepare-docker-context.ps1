$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$parent = Resolve-Path (Join-Path $repoRoot "..")
$context = Join-Path $repoRoot "docker-context"

if (Test-Path -LiteralPath $context) {
    Remove-Item -LiteralPath $context -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $context | Out-Null

function Copy-CleanDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $excludeNames = @(".git", "target", "node_modules", "test-results", "playwright-report", "docker-context")
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | Where-Object {
        $excludeNames -notcontains $_.Name
    } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $Destination -Recurse -Force
    }
}

Copy-CleanDirectory -Source (Join-Path $parent "yougen") -Destination (Join-Path $context "yougen")
Copy-CleanDirectory -Source (Join-Path $parent "contrix-rust-sdk") -Destination (Join-Path $context "contrix-rust-sdk")
Copy-CleanDirectory -Source (Join-Path $parent "chime") -Destination (Join-Path $context "chime")

Write-Host "Prepared Docker context at $context"

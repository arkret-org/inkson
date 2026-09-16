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

Copy-CleanDirectory -Source (Join-Path $parent "inkson") -Destination (Join-Path $context "inkson")
Copy-CleanDirectory -Source (Join-Path $parent "arkret-rust-sdk") -Destination (Join-Path $context "arkret-rust-sdk")
Copy-CleanDirectory -Source (Join-Path $parent "garth") -Destination (Join-Path $context "garth")
Copy-CleanDirectory -Source (Join-Path $parent "chime") -Destination (Join-Path $context "chime")
# `yoface` is deliberately absent: it is a private cargo git dependency, not a
# sibling path dependency, so the image build fetches it from GitHub with the
# `github_token` build secret instead of copying a local checkout.

Write-Host "Prepared Docker context at $context"

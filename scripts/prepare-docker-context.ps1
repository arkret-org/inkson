$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$parent = (Resolve-Path (Join-Path $repoRoot "..")).Path
$context = [IO.Path]::GetFullPath((Join-Path $repoRoot "docker-context"))
$expected = [IO.Path]::GetFullPath((Join-Path $repoRoot "docker-context"))
if (-not $context.Equals($expected,[StringComparison]::OrdinalIgnoreCase) -or -not $context.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw "Docker context is outside the repository" }
if (Test-Path -LiteralPath $context) {
    $resolvedContext = (Resolve-Path -LiteralPath $context).Path
    $item = Get-Item -LiteralPath $context -Force
    if (-not $resolvedContext.Equals($expected,[StringComparison]::OrdinalIgnoreCase) -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Refusing to replace a redirected Docker context" }
    Remove-Item -LiteralPath $resolvedContext -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $context | Out-Null
function Copy-CleanDirectory {
    param([string]$Source,[string]$Destination,[bool]$TopLevel=$true)
    $excluded = @(".git","target","node_modules","test-results","playwright-report","docker-context","release-assets",".local")
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        if ($excluded -contains $item.Name -or ($TopLevel -and $item.Name -eq "artifacts")) { continue }
        if ($item.PSIsContainer) {
            Copy-CleanDirectory -Source $item.FullName -Destination (Join-Path $Destination $item.Name) -TopLevel $false
        } else { Copy-Item -LiteralPath $item.FullName -Destination $Destination -Force }
    }
}
foreach ($name in @("inkson","arkret-rust-sdk","arkret-spec","garth","chime")) {
    $source = Join-Path $parent $name
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing sibling dependency: $source" }
    Copy-CleanDirectory -Source $source -Destination (Join-Path $context $name)
}
Write-Host "Prepared Docker context at $context; Cargo fetches Glory/Sapid at their locked Git revisions"

param(
    [Parameter(Mandatory = $true)]
    [string]$Url,
    [string]$DistDir = "dist/lighthouse",
    [string]$BudgetPath = "docs/lighthouse-budget.json"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $report = Join-Path $DistDir "lighthouse.json"
    npx --yes lighthouse@12 $Url `
        --output=json `
        --output-path=$report `
        --budget-path=$BudgetPath `
        --chrome-flags="--headless=new --no-sandbox"
    Write-Host "Wrote Lighthouse report to $report"
}
finally {
    Pop-Location
}

param(
    [string]$ImageTag = "yougen-web:local",
    [string]$DistDir = "dist/web-image",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        throw "docker is required for web image evidence"
    }

    if (-not $SkipBuild) {
        $ps = Get-Command pwsh -ErrorAction SilentlyContinue
        if (-not $ps) {
            $ps = Get-Command powershell -ErrorAction SilentlyContinue
        }
        if (-not $ps) {
            throw "pwsh or powershell is required to prepare the Docker context"
        }
        & $ps.Path -ExecutionPolicy Bypass -File "scripts/prepare-docker-context.ps1"
        & docker build -f "docker-context/yougen/Dockerfile" -t $ImageTag "docker-context"
    }

    $imageId = (& docker image inspect $ImageTag --format "{{.Id}}").Trim()
    $imageTar = Join-Path $DistDir "yougen-web-image.tar"
    & docker save $ImageTag -o $imageTar

    $shaFile = Join-Path $DistDir "yougen-web-image.tar.sha256"
    Get-FileHash -Algorithm SHA256 -LiteralPath $imageTar |
        ForEach-Object { "$($_.Hash.ToLowerInvariant())  $(Split-Path -Leaf $imageTar)" } |
        Set-Content -Encoding ASCII -Path $shaFile

    $trivy = Get-Command trivy -ErrorAction SilentlyContinue
    $syft = Get-Command syft -ErrorAction SilentlyContinue
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue

    $trivyReport = Join-Path $DistDir "trivy-image.json"
    $sbomPath = Join-Path $DistDir "sbom.spdx.json"
    $cosignBundle = Join-Path $DistDir "cosign-image-tar.sig"

    $evidence = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        image_tag = $ImageTag
        image_id = $imageId
        image_tar = $imageTar
        image_tar_sha256 = $shaFile
        registry_push = $false
        transparency_log = $false
        trivy = [ordered]@{ available = [bool]$trivy; report = $null; exit_code = $null }
        sbom = [ordered]@{ tool = $null; path = $null }
        cosign = [ordered]@{ available = [bool]$cosign; signature = $null; signed = $false; mode = "sign-blob"; tlog_upload = $false }
    }

    if (Test-Path -LiteralPath $trivyReport) {
        $evidence.trivy.report = $trivyReport
        $evidence.trivy.exit_code = 0
    }
    elseif ($trivy) {
        & trivy image --format json --output $trivyReport $ImageTag
        $evidence.trivy.report = $trivyReport
        $evidence.trivy.exit_code = $LASTEXITCODE
    }

    if ($syft) {
        & syft packages $ImageTag -o spdx-json=$sbomPath
        $evidence.sbom.tool = "syft"
        $evidence.sbom.path = $sbomPath
    }
    elseif ($trivy) {
        $sbomPath = Join-Path $DistDir "sbom.cyclonedx.json"
        & trivy image --format cyclonedx --output $sbomPath $ImageTag
        $evidence.sbom.tool = "trivy"
        $evidence.sbom.path = $sbomPath
    }

    if ($cosign -and $env:COSIGN_KEY) {
        & cosign sign-blob --key $env:COSIGN_KEY --tlog-upload=false --output-signature $cosignBundle $imageTar
        $evidence.cosign.signature = $cosignBundle
        $evidence.cosign.signed = $true
    }

    $evidencePath = Join-Path $DistDir "web-image-evidence.json"
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $evidencePath
    Write-Host "Wrote web image evidence to $evidencePath"
}
finally {
    Pop-Location
}

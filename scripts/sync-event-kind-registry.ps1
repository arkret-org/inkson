# Refresh tests/fixtures/event-kind-registry.snapshot.txt from contrix-spec.
#
# Usage:
#   pwsh ./scripts/sync-event-kind-registry.ps1
#   pwsh ./scripts/sync-event-kind-registry.ps1 -SpecRoot D:/Works/contrix-dev/contrix-spec
#
# After running this, reconcile `known_event_kinds()` in src/conformance.rs to
# match. The diff test in conformance.rs is the tripwire — it fails until both
# files agree.

[CmdletBinding()]
param(
    [string]$SpecRoot = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")) "../contrix-spec")
)

$ErrorActionPreference = "Stop"

$registry = Join-Path $SpecRoot "spec/v1/artifacts/registry/event-kind-registry.json"
if (-not (Test-Path $registry)) {
    throw "event-kind registry not found at $registry — pass -SpecRoot pointing at the contrix-spec checkout."
}

$snapshot = Resolve-Path (Join-Path $PSScriptRoot "../tests/fixtures/event-kind-registry.snapshot.txt")
$scopeSnapshot = Resolve-Path (Join-Path $PSScriptRoot "../tests/fixtures/event-kind-wire-scopes.snapshot.tsv")

$json = Get-Content -Raw -LiteralPath $registry | ConvertFrom-Json
$active = @($json.event_kinds | Where-Object { $_.status -eq "active" })

$kinds = @($active | ForEach-Object { $_.event_kind } | Sort-Object -Unique)

$header = @(
    "# yougen event-kind registry snapshot",
    "#",
    "# Pinned mirror of ``contrix-spec/spec/v1/artifacts/registry/event-kind-registry.json``",
    "# (status == ""active""). One kind per line, sorted, lowercase. Lines starting",
    "# with ``#`` are comments. Blank lines are ignored.",
    "#",
    "# Refresh with ``scripts/sync-event-kind-registry.ps1`` after a contrix-spec",
    "# bump and update ``known_event_kinds()`` in ``src/conformance.rs`` in the same",
    "# commit; the diff test in conformance.rs ties the two together."
)

$lines = $header + $kinds
[System.IO.File]::WriteAllText(
    $snapshot,
    ($lines -join [Environment]::NewLine) + [Environment]::NewLine
)

Write-Host "Wrote $($kinds.Count) active event kinds to $snapshot"

$scopeRows = @(
    $active
    | Sort-Object event_kind
    | ForEach-Object { "$($_.event_kind)`t$($_.wire_scope)" }
)

$scopeHeader = @(
    "# yougen event-kind wire_scope snapshot",
    "#",
    "# Pinned mirror of ``wire_scope`` from",
    "# ``contrix-spec/spec/v1/artifacts/registry/event-kind-registry.json``",
    "# (status == ""active""). One row per kind, sorted by kind. Format is",
    "# tab-separated: ``<event_kind>\t<wire_scope>``.",
    "#",
    "# wire_scope values come from the registry's ``wire_scope_definitions``:",
    "#   actor_private_event - actor-private; reducer input but not Space-shared",
    "#   durable_event       - written into Space history; reducer input",
    "#   ephemeral_event     - short-TTL signaling; reducer MUST NOT use",
    "#",
    "# Refresh with ``scripts/sync-event-kind-registry.ps1``. The diff test in",
    "# ``src/conformance.rs`` ties this snapshot to the typed",
    "# ``event_kind_wire_scope()`` classifier."
)

$scopeLines = $scopeHeader + $scopeRows
[System.IO.File]::WriteAllText(
    $scopeSnapshot,
    ($scopeLines -join [Environment]::NewLine) + [Environment]::NewLine
)

Write-Host "Wrote $($scopeRows.Count) kind/scope pairs to $scopeSnapshot"

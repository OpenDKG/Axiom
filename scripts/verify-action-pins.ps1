<#
.SYNOPSIS
    Fails when a workflow uses an action that is not pinned to a full commit SHA.

.DESCRIPTION
    Scans every *.yml and *.yaml file in the workflow directory; GitHub runs both. Each "uses:"
    reference must end in a 40-character commit SHA. Local "./" references are allowed.

.PARAMETER WorkflowDirectory
    Directory to scan. Defaults to .github/workflows in the repository root.
#>
[CmdletBinding()]
param(
    [string]$WorkflowDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) '.github/workflows')
)

$ErrorActionPreference = 'Stop'

$unpinned = Get-ChildItem -LiteralPath $WorkflowDirectory -File |
    Where-Object { $_.Extension -in '.yml', '.yaml' } |
    Select-String -Pattern '^\s*-?\s*uses:\s*(\S+)' |
    Where-Object { $_.Matches[0].Groups[1].Value -notmatch '^(\./|[^@\s]+@[0-9a-f]{40}$)' }

if ($unpinned) {
    $unpinned | ForEach-Object { Write-Host "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
    throw "Workflow actions must be pinned to a full commit SHA."
}

Write-Host "Every workflow action is pinned to a commit SHA."

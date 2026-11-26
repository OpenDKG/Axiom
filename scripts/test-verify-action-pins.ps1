<#
.SYNOPSIS
    Self-test for verify-action-pins.ps1, run by Windows CI before the guard itself.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$guard = Join-Path $PSScriptRoot 'verify-action-pins.ps1'
$sha = '0123456789abcdef0123456789abcdef01234567'
$pinned = "      - uses: actions/checkout@$sha # v4"
$local = '    uses: ./.github/workflows/windows-ci.yml'
$tagged = '      - uses: actions/checkout@v4'

$cases = @(
    @{ Name = 'pinned and local references in .yml and .yaml pass'; ShouldFail = $false; Files = @{ 'a.yml' = @($pinned, $local); 'b.yaml' = @($pinned, $local) } },
    @{ Name = 'a tag reference in .yml fails'; ShouldFail = $true; Files = @{ 'a.yml' = @($tagged); 'b.yaml' = @($pinned) } },
    @{ Name = 'a tag reference in .yaml fails'; ShouldFail = $true; Files = @{ 'a.yml' = @($pinned); 'b.yaml' = @($tagged) } }
)

$failures = 0
foreach ($case in $cases) {
    $directory = Join-Path ([System.IO.Path]::GetTempPath()) ("action-pins-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $directory | Out-Null
    try {
        foreach ($file in $case.Files.GetEnumerator()) {
            Set-Content -LiteralPath (Join-Path $directory $file.Key) -Value $file.Value
        }

        $failed = $false
        try {
            & $guard -WorkflowDirectory $directory
        }
        catch {
            if ($_.Exception.Message -notlike '*pinned to a full commit SHA*') { throw }
            $failed = $true
        }

        if ($failed -eq $case.ShouldFail) {
            Write-Host "PASS: $($case.Name)"
        }
        else {
            Write-Host "FAIL: $($case.Name)"
            $failures++
        }
    }
    finally {
        Remove-Item -LiteralPath $directory -Recurse -Force
    }
}

if ($failures -gt 0) {
    throw "$failures of $($cases.Count) action pin guard cases failed."
}

Write-Host "All $($cases.Count) action pin guard cases passed."

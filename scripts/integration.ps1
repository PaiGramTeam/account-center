param(
    [ValidateSet("doctor", "test", "deps-up", "deps-down")]
    [string]$Command = "test"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $RepoRoot "docker-compose.integration.yml"

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')")
        exit $LASTEXITCODE
    }
}

function Assert-DockerComposeAvailable {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker is required for $Command"
    }

    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose is required for $Command"
    }
}

Push-Location $RepoRoot
try {
    switch ($Command) {
        "doctor" {
            Invoke-NativeCommand -FilePath "go" -Arguments @("run", "./cmd/integration-doctor")
        }
		"test" {
			$hadGoWork = Test-Path Env:GOWORK
			$previousGoWork = $env:GOWORK
			try {
				$env:GOWORK = "off"
				Invoke-NativeCommand -FilePath "go" -Arguments @("run", "./cmd/integration-doctor")
				Invoke-NativeCommand -FilePath "go" -Arguments @("test", "-tags=integration", "./integration/...")
			}
            finally {
                if ($hadGoWork) {
                    $env:GOWORK = $previousGoWork
                }
                else {
                    Remove-Item Env:GOWORK -ErrorAction SilentlyContinue
                }
            }
        }
        "deps-up" {
            Assert-DockerComposeAvailable
            Invoke-NativeCommand -FilePath "docker" -Arguments @("compose", "-f", $ComposeFile, "up", "-d")
        }
        "deps-down" {
            Assert-DockerComposeAvailable
            Invoke-NativeCommand -FilePath "docker" -Arguments @("compose", "-f", $ComposeFile, "down")
        }
    }
}
finally {
    Pop-Location
}

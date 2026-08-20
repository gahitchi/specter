param(
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

$PackageSpec = "osint-recon @ git+https://github.com/gahitchi/osint-recon.git@gpt-branch"

function Find-Uv {
    $Command = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -ne $Command) {
        return $Command.Source
    }

    Write-Host "Installing the uv package manager..."
    $Installer = Invoke-RestMethod "https://astral.sh/uv/install.ps1"
    & ([scriptblock]::Create($Installer))

    $Candidates = @(
        (Join-Path $HOME ".local\bin\uv.exe"),
        (Join-Path $env:USERPROFILE ".local\bin\uv.exe")
    )
    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate) {
            return $Candidate
        }
    }
    throw "uv was installed but could not be found. Open a new PowerShell window and retry."
}

$Uv = Find-Uv
Write-Host "Installing Specter in an isolated user environment..."
& $Uv tool install --force --refresh-package osint-recon $PackageSpec
if ($LASTEXITCODE -ne 0) {
    throw "Specter installation failed."
}

$BinDirectory = (& $Uv tool dir --bin).Trim()
$Specter = Join-Path $BinDirectory "specter.exe"
Write-Host "Specter installed successfully. While running, it checks for updates every 5 minutes."
Write-Host "Launch at any time with: specter"
Write-Host "Apply a downloaded update with: specter --update"
Write-Host "Uninstall with: uv tool uninstall osint-recon"

if (-not $NoLaunch) {
    & $Specter --no-update
}

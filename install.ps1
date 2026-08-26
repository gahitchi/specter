param(
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

$PackageSpec = "osint-recon[desktop] @ git+https://github.com/gahitchi/osint-recon.git@gpt-branch"

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
$SpecterApp = Join-Path $BinDirectory "specter-app.exe"
$IconPath = (& $Specter --icon-path).Trim()
if (-not (Test-Path -LiteralPath $IconPath)) {
    throw "Specter was installed but its application icon is missing."
}

function New-SpecterShortcut {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $Parent)) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    $Shell = New-Object -ComObject WScript.Shell
    $Shortcut = $Shell.CreateShortcut($Path)
    $Shortcut.TargetPath = $SpecterApp
    $Shortcut.WorkingDirectory = $HOME
    $Shortcut.Description = "Specter research and evidence workspace"
    $Shortcut.IconLocation = "$IconPath,0"
    $Shortcut.Save()
}

$Programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
$Desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
New-SpecterShortcut (Join-Path $Programs "Specter.lnk")
New-SpecterShortcut (Join-Path $Desktop "Specter.lnk")

Write-Host "Specter installed successfully. While running, it checks for updates every 5 minutes."
Write-Host "Open Specter from the desktop, Start menu, or launch it with: specter"
Write-Host "Apply a downloaded update with: specter --update"
Write-Host "Uninstall with: irm https://raw.githubusercontent.com/gahitchi/osint-recon/gpt-branch/uninstall.ps1 | iex"

if (-not $NoLaunch) {
    Start-Process -FilePath $SpecterApp -ArgumentList "--no-update"
}

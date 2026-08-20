$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$UvCommand = Get-Command uv -ErrorAction SilentlyContinue
if ($null -eq $UvCommand) {
    $UvPath = Join-Path $HOME ".local\bin\uv.exe"
    if (-not (Test-Path -LiteralPath $UvPath)) {
        throw "uv could not be found. Install uv or remove the osint-recon tool environment manually."
    }
} else {
    $UvPath = $UvCommand.Source
}

& $UvPath tool uninstall osint-recon
$ShortcutPath = Join-Path ([Environment]::GetFolderPath("Programs")) "Specter.lnk"
Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction SilentlyContinue

Write-Host "Specter was removed. Investigation data and settings were left in place."

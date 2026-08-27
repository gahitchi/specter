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
$ShortcutPaths = @(
    (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)) "Specter.lnk"),
    (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)) "Specter.lnk")
)
foreach ($ShortcutPath in $ShortcutPaths) {
    Remove-Item -LiteralPath $ShortcutPath -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath (Join-Path $env:LOCALAPPDATA "Specter\assets") `
    -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Specter and its shortcuts were removed. Investigation data and settings were left in place."

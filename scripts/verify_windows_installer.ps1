$ErrorActionPreference = 'Stop'
$installer = Get-ChildItem "$PSScriptRoot/../dist/installers/*windows-x64-setup.exe" | Select-Object -First 1
$destination = Join-Path $env:TEMP ('MultiVPN-package-test-' + [guid]::NewGuid().ToString('N'))
function Run-Checked($File, $Arguments) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "$File failed with exit code $($process.ExitCode)" }
}
Run-Checked $installer.FullName "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=`"$destination`""
try {
    if (-not (Test-Path "$destination/MultiVPN.exe")) { throw 'Installed executable missing' }
    $desktopLink = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Multi VPN.lnk'
    if (-not (Test-Path $desktopLink)) { throw 'Desktop shortcut missing' }
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($desktopLink)
    python -c 'import os,sys; sys.exit(not os.path.samefile(sys.argv[1],sys.argv[2]))' $shortcut.TargetPath "$destination\MultiVPN.exe"
    if ($LASTEXITCODE -ne 0) { throw 'Shortcut target incorrect' }
    Run-Checked "$destination/MultiVPN.exe" '--self-test'
} finally {
    Run-Checked "$destination/unins000.exe" '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
}
if (Test-Path "$destination/MultiVPN.exe") { throw 'Uninstall left the executable behind' }
if (Test-Path $desktopLink) { throw 'Uninstall left the desktop shortcut behind' }
Write-Output 'Installer, shortcut, frozen imports and uninstall verified. No VPN login.'

# Builds the BreachHound Windows installer (dist\breachhound-setup-<ver>.exe).
# Requires Go, a CGO C compiler (mingw-w64), rsrc, and Inno Setup (ISCC).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $env:CGO_ENABLED = '1'

    Write-Host '1/4  generating icon...'
    go run ./tools/mkicon

    Write-Host '2/4  embedding exe icon...'
    rsrc -ico cmd\breachhound-gui\assets\icon.ico -o cmd\breachhound-gui\rsrc_windows.syso

    Write-Host '3/4  building release exe...'
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    go build -ldflags '-H windowsgui -s -w' -o dist\breachhound-gui.exe ./cmd/breachhound-gui

    Write-Host '4/4  compiling installer...'
    $iscc = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    if (-not (Test-Path $iscc)) { $iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" }
    & $iscc installer\breachhound.iss

    Write-Host 'done -> dist\breachhound-setup-0.1.0.exe'
}
finally {
    Pop-Location
}

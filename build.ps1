# Build a standalone Windows executable: dist\IPSWatch.exe
# Requires: Python 3.11+ with Tkinter, and PyInstaller (pip install pyinstaller)
# Native tools write progress to stderr; check $LASTEXITCODE instead of using "Stop".
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

python -m unittest discover -s tests
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

python deploy\make_icon.py deploy\ipswatch.ico
if ($LASTEXITCODE -ne 0) { throw "icon generation failed" }

python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name IPSWatch `
    --icon deploy\ipswatch.ico `
    IPSWatch.pyw
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Write-Host "Built $(Resolve-Path dist\IPSWatch.exe)"

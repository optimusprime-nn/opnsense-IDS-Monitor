# Build release executables into dist\ :
#   dist\IPSWatch.exe      desktop app (tray, settings, toasts)
#   dist\ipswatch-cli.exe  command line / service
# Requires the Rust toolchain (https://rustup.rs) with the MSVC target.
# Native tools write progress to stderr; check $LASTEXITCODE instead of using "Stop".
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

# Keep local folder names (project path, user profile) out of the executables, and build with
# Control Flow Guard (an exploit can't jump into the middle of a function).
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE ".cargo" }
$env:RUSTFLAGS = "--remap-path-prefix=$PSScriptRoot=ipswatch --remap-path-prefix=$cargoHome=cargo --remap-path-prefix=$env:USERPROFILE=~ -C control-flow-guard=yes"

cargo test --release --locked
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

cargo build --release --locked
if ($LASTEXITCODE -ne 0) { throw "build failed" }

New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item target\release\IPSWatch.exe, target\release\ipswatch-cli.exe dist\ -Force

# Installer (dist\IPSWatch-Setup-<version>.exe) when Inno Setup 6 is installed.
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    $version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value
    & $iscc /Q "/DAppVersion=$version" installer\ipswatch.iss
    if ($LASTEXITCODE -ne 0) { throw "installer build failed" }
} else {
    "Inno Setup 6 not found - skipping the installer (winget install JRSoftware.InnoSetup)"
}
# SHA-256 beside each file of this version, so a download can be checked against the release.
$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value
Get-ChildItem dist\IPSWatch.exe, dist\ipswatch-cli.exe, "dist\IPSWatch-Setup-$version.exe" -ErrorAction SilentlyContinue | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$h  $($_.Name)" | Out-File -Encoding ascii "$($_.FullName).sha256"
    if ($env:GITHUB_STEP_SUMMARY) { "SHA-256 of $($_.Name): ``$h``" >> $env:GITHUB_STEP_SUMMARY }
}
Get-ChildItem dist\*.exe | ForEach-Object { "{0,-18} {1,6:N1} MB" -f $_.Name, ($_.Length / 1MB) }

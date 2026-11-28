# Regenerate the documentation's screenshots (docs\assets\img\*.png) from the demo data in
# samples\demo, so they always show the current version and never real addresses. The demo data
# (demo.db, demo-log.txt; not committed) is rebuilt first by `cargo run --example make_demo`.
#
#   .\scripts\screenshots.ps1            # uses target\release\IPSWatch.exe (run build.ps1 first)
#   .\scripts\screenshots.ps1 -Exe dist\IPSWatch.exe
#
# Each picture starts IPS Watch on a scratch copy of the demo data with its own settings file, so
# it runs beside your normal IPS Watch without touching its settings, database or tray icon lock.
# The window opens, settles for a few seconds, saves itself (--screenshot) and closes.
# Run it from your own desktop session (not over a remote shell): the window has to be drawn.
param(
    [string]$Exe = "target\release\IPSWatch.exe",
    [string]$Out = "docs\assets\img"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path $Exe)) { throw "$Exe not found - run .\build.ps1 first" }
$Exe = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path

# name -> arguments. In the demo, 192.168.1.50 is the infected PC and 198.51.100.44 the attacker.
$shots = [ordered]@{
    "findings"               = "--tab findings"
    "findings-select"        = "--tab findings --select-first 4"
    "host"                   = "--tab findings --host 192.168.1.50"
    "health"                 = "--tab health"
    "dns"                    = "--tab dns"
    "events"                 = "--tab events"
    "log"                    = "--tab log"
    "settings-firewall"      = "--tab settings:firewall"
    "settings-collection"    = "--tab settings:collection"
    "settings-detection"     = "--tab settings:detection"
    "settings-rules"         = "--tab settings:rules"
    "settings-notifications" = "--tab settings:notifications"
    "settings-autoblock"     = "--tab settings:autoblock"
    "settings-health"        = "--tab settings:health"
    "settings-dns"           = "--tab settings:dns"
    "settings-application"   = "--tab settings:application"
    "settings-data"          = "--tab settings:data"
}

# A neutral folder: its path shows in the Activity log and Data & storage pictures, so it must
# not contain your user name.
$work = Join-Path $env:SystemDrive "IPSWatch-demo"

# Fresh demo data, dated from now.
cargo run --quiet --release --example make_demo
if ($LASTEXITCODE -ne 0) { throw "making the demo data failed" }
foreach ($name in $shots.Keys) {
    # A fresh copy each time: nothing one picture does shows up in the next.
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $work | Out-Null
    Copy-Item samples\demo\config.toml, samples\demo\demo.db $work
    Copy-Item samples\demo\demo-log.txt (Join-Path $work "ipswatch.log")
    $png = Join-Path $Out "$name.png"
    Remove-Item $png -ErrorAction SilentlyContinue
    $argList = "--config `"$work\config.toml`" $($shots[$name]) --screenshot `"$png`""
    $p = Start-Process -FilePath $Exe -ArgumentList $argList -PassThru
    if (-not $p.WaitForExit(30000)) { $p.Kill(); throw "${name}: IPS Watch did not finish within 30 s" }
    if (-not (Test-Path $png)) { throw "${name}: no picture saved (see $work\ipswatch.log)" }
    "{0,-24} {1}" -f $name, $png
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
"Done. settings-dns-unbound.png is not regenerated (it needs an Unbound server selected); update it by hand if needed."

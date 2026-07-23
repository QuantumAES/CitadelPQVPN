<#
  build-windows.ps1 - build the CitadelPQVPN Windows installer (model W2).

  RUN ON WINDOWS (not from Linux): needs Visual Studio 2022 (Desktop C++),
  Flutter (windows-desktop), rustup + target x86_64-pc-windows-msvc, Inno Setup 6.
  See README.md in this folder for the full prerequisites checklist.

  NOTE: this script is intentionally ASCII-only. PowerShell without a BOM decodes
  a non-ASCII .ps1 with the OEM/ANSI code page, which mangles UTF-8 and produces
  "unexpected token" parser errors. Keeping it ASCII removes the BOM requirement.

  Does: cargo build service (MSVC) -> flutter build windows (also builds the Rust
  core citadel_client.dll) -> assemble payload\ -> (opt.) sign binaries -> ISCC (Inno)
  -> (opt.) sign the installer.

  Example:
    ./build-windows.ps1 -Version 1.0.0 -WintunDll C:\dl\wintun\bin\amd64\wintun.dll
    ./build-windows.ps1 -Version 1.0.0 -SignSha1 <thumbprint>   # + Authenticode
#>
param(
  [string]$Version   = "1.0.0",
  [string]$WintunDll = "",              # path to wintun.dll (amd64) from wireguard.com; else looked up next to this script
  [string]$SignSha1  = "",              # SHA1 thumbprint of the Authenticode cert in the store (opt.)
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
$here   = $PSScriptRoot
$root   = Split-Path -Parent (Split-Path -Parent $here)   # repository root
$target = "x86_64-pc-windows-msvc"

function Sign([string]$file) {
  if ($SignSha1) {
    Write-Host "  signing: $file"
    signtool sign /fd SHA256 /sha1 $SignSha1 /tr $TimestampUrl /td SHA256 $file
    if ($LASTEXITCODE -ne 0) { throw "signtool failed (exit $LASTEXITCODE) for $file" }
  }
}

Write-Host "== [1/5] Rust: service citadel-svc ($target) ==" -ForegroundColor Cyan
Push-Location $root
cargo build --release --target $target -p citadel-winsvc
Pop-Location
$svc = Join-Path $root "target\$target\release\citadel-svc.exe"
if (-not (Test-Path $svc)) { throw "not built: $svc" }

Write-Host "== [2/5] Flutter: Windows bundle (+ Rust core citadel_client.dll) ==" -ForegroundColor Cyan
Push-Location (Join-Path $root "app")
flutter build windows --release --dart-define=CITADEL_VERSION=$Version
Pop-Location
$bundle = Join-Path $root "app\build\windows\x64\runner\Release"
if (-not (Test-Path (Join-Path $bundle "app.exe"))) { throw "Flutter bundle not built: $bundle\app.exe" }

Write-Host "== [3/5] Assemble payload ==" -ForegroundColor Cyan
$payload = Join-Path $here "payload"
if (Test-Path $payload) { Remove-Item -Recurse -Force $payload }
New-Item -ItemType Directory -Force (Join-Path $payload "app") | Out-Null
Copy-Item -Recurse (Join-Path $bundle "*") (Join-Path $payload "app")
Copy-Item $svc (Join-Path $payload "citadel-svc.exe")

if (-not $WintunDll) { $WintunDll = Join-Path $here "wintun.dll" }
if (-not (Test-Path $WintunDll)) {
  throw "wintun.dll not found ($WintunDll). Download from https://www.wintun.net/ (amd64) and pass -WintunDll."
}
Copy-Item $WintunDll (Join-Path $payload "wintun.dll")

Write-Host "== [4/5] Sign binaries (if cert provided) ==" -ForegroundColor Cyan
Sign (Join-Path $payload "citadel-svc.exe")
Sign (Join-Path $payload "app\app.exe")

Write-Host "== [5/5] Inno Setup ==" -ForegroundColor Cyan
$iscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { throw "ISCC.exe not found: $iscc (install Inno Setup 6)" }

$issFile = Join-Path $here "citadel.iss"
& $iscc "/DAppVersion=$Version" "$issFile"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)" }

$setup = Join-Path $here "Output\CitadelPQVPN-Setup-$Version.exe"
Sign $setup
Write-Host "Done: $setup" -ForegroundColor Green

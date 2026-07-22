<#
  build-windows.ps1 — сборка Windows-инсталлятора CitadelPQVPN (модель W2).

  ЗАПУСКАТЬ НА WINDOWS (не с Linux): нужны Visual Studio 2022 (Desktop C++),
  Flutter (windows-desktop), rustup + target x86_64-pc-windows-msvc, Inno Setup 6.
  См. README.md в этой папке для полного чеклиста пререквизитов.

  Делает: cargo build службы (MSVC) -> flutter build windows (собирает и Rust-ядро
  citadel_client.dll) -> сборка payload\ -> (опц.) подпись бинарей -> ISCC (Inno)
  -> (опц.) подпись установщика.

  Пример:
    ./build-windows.ps1 -Version 1.0.0 -WintunDll C:\dl\wintun\bin\amd64\wintun.dll
    ./build-windows.ps1 -Version 1.0.0 -SignSha1 <thumbprint>   # + Authenticode
#>
param(
  [string]$Version   = "1.0.0",
  [string]$WintunDll = "",              # путь к wintun.dll (amd64) от wireguard.com; иначе ищется рядом
  [string]$SignSha1  = "",              # SHA1-отпечаток Authenticode-сертификата в хранилище (опц.)
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
$here   = $PSScriptRoot
$root   = Split-Path -Parent (Split-Path -Parent $here)   # корень репозитория
$target = "x86_64-pc-windows-msvc"

function Sign([string]$file) {
  if ($SignSha1) {
    Write-Host "  подпись: $file"
    signtool sign /fd SHA256 /sha1 $SignSha1 /tr $TimestampUrl /td SHA256 $file
  }
}

Write-Host "== [1/5] Rust: служба citadel-svc ($target) ==" -ForegroundColor Cyan
Push-Location $root
cargo build --release --target $target -p citadel-winsvc
Pop-Location
$svc = Join-Path $root "target\$target\release\citadel-svc.exe"
if (-not (Test-Path $svc)) { throw "не собран: $svc" }

Write-Host "== [2/5] Flutter: Windows-бандл (+ Rust-ядро citadel_client.dll) ==" -ForegroundColor Cyan
Push-Location (Join-Path $root "app")
flutter build windows --release --dart-define=CITADEL_VERSION=$Version
Pop-Location
$bundle = Join-Path $root "app\build\windows\x64\runner\Release"
if (-not (Test-Path (Join-Path $bundle "app.exe"))) { throw "не собран Flutter-бандл: $bundle\app.exe" }

Write-Host "== [3/5] Сборка payload ==" -ForegroundColor Cyan
$payload = Join-Path $here "payload"
if (Test-Path $payload) { Remove-Item -Recurse -Force $payload }
New-Item -ItemType Directory -Force (Join-Path $payload "app") | Out-Null
Copy-Item -Recurse (Join-Path $bundle "*") (Join-Path $payload "app")
Copy-Item $svc (Join-Path $payload "citadel-svc.exe")

if (-not $WintunDll) { $WintunDll = Join-Path $here "wintun.dll" }
if (-not (Test-Path $WintunDll)) {
  throw "wintun.dll не найден ($WintunDll). Скачай с https://www.wintun.net/ (amd64) и укажи -WintunDll."
}
Copy-Item $WintunDll (Join-Path $payload "wintun.dll")

Write-Host "== [4/5] Подпись бинарей (если задан сертификат) ==" -ForegroundColor Cyan
Sign (Join-Path $payload "citadel-svc.exe")
Sign (Join-Path $payload "app\app.exe")

Write-Host "== [5/5] Inno Setup ==" -ForegroundColor Cyan
$iscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { throw "ISCC.exe не найден: $iscc (поставь Inno Setup 6)" }
& $iscc "/DAppVersion=$Version" (Join-Path $here "citadel.iss")

$setup = Join-Path $here "Output\CitadelPQVPN-Setup-$Version.exe"
Sign $setup
Write-Host "Готово: $setup" -ForegroundColor Green

# CitadelPQVPN — упаковка под Windows (модель W2)

Инсталлятор (Inno Setup) кладёт Flutter-бандл + привилегированную службу `citadel-svc.exe` + `wintun.dll`,
регистрирует службу в SCM (AutoStart) и стартует её. Приложение (`app.exe`) общается со службой по
named pipe `\\.\pipe\citadel-svc`; движок (QUIC/obfs) — в приложении, служба владеет WinTUN+WFP+маршрутами.

> **Сборка полного бандла — ТОЛЬКО на Windows** (Flutter Windows требует Visual Studio/MSVC; собрать с
> Linux нельзя). Rust-ядро кроссится под `x86_64-pc-windows-gnu` с Linux лишь для compile-check.

## 1. Пререквизиты на Windows-хосте

| Что | Зачем | Ссылка/команда |
|-----|-------|----------------|
| **Visual Studio 2022** + workload **«Desktop development with C++»** | `flutter build windows` + MSVC-таргет Rust | Visual Studio Installer |
| **Flutter (stable)** + `flutter config --enable-windows-desktop` | сборка бандла + Rust-ядра (cargokit) | flutter.dev |
| **rustup** + `rustup target add x86_64-pc-windows-msvc` | служба `citadel-svc` под MSVC | rustup.rs |
| **Inno Setup 6** (ISCC.exe) | сборка установщика | jrsoftware.org |
| **`wintun.dll`** (amd64) | WinTUN-адаптер (грузится службой рантаймом) | https://www.wintun.net/ |
| **Authenticode-сертификат** (опц., но нужен для доверия) | подпись `signtool` | CA / self-signed для теста |

`flutter doctor -v` должен быть зелёным по Windows-тулчейну. `.NET`/JetBrains Rider **не нужны** (служба на Rust).

## 2. Сборка

```powershell
# из этой папки (packaging\windows)
./build-windows.ps1 -Version 1.0.0 -WintunDll C:\path\to\wintun\bin\amd64\wintun.dll
# с подписью:
./build-windows.ps1 -Version 1.0.0 -WintunDll ...\wintun.dll -SignSha1 <thumbprint-сертификата>
```

Скрипт: `cargo build` службы (MSVC) → `flutter build windows` (собирает и `citadel_client.dll`) →
собирает `payload\` → (опц.) подпись → `ISCC` → (опц.) подпись установщика.
Результат: `packaging\windows\Output\CitadelPQVPN-Setup-<version>.exe`.

### Что во что кладётся (payload → `C:\Program Files\CitadelPQVPN\`)
- `app\*` — Flutter-бандл: `app.exe`, `flutter_windows.dll`, **`citadel_client.dll`** (Rust-ядро), `data\`.
- `citadel-svc.exe` — привилегированная служба (WinTUN + WFP + маршруты + packet-pump + SCM).
- `wintun.dll` — рядом со службой (крейт `wintun` грузит из своей директории).

## 3. Установка / удаление (что делает инсталлятор)
- **Install (elevated/UAC):** копирует файлы → `citadel-svc install` (создаёт службу в SCM, AutoStart,
  авто-рестарт при краше) → `net start CitadelPQVPN` → ярлыки. Приложение стартует **под пользователем**
  (`runasoriginaluser` — де-эскалация из elevated-установщика).
- **Uninstall:** `net stop CitadelPQVPN` → `citadel-svc uninstall` → удаление файлов.

Ручные команды службы (для отладки, из elevated-консоли):
```
citadel-svc install      # зарегистрировать в SCM
citadel-svc uninstall    # снять
citadel-svc --console    # dev-режим (слушать пайп в консоли, без SCM)
```

## 4. Device E2E-чеклист (за пользователем, на Windows-боксе)
Проверить вживую (Rust кроссится начисто, но рантайм WinTUN/WFP/SCM — только здесь):
1. **Установка**: `Setup.exe` → служба `CitadelPQVPN` в `services.msc` = Running (AutoStart).
2. **Connect**: импорт ссылки → Connect → появляется WinTUN-адаптер «Citadel», интернет через туннель.
3. **DNS/маршруты**: `route print` показывает /1-половины на адаптере + bypass /32 к exit; резолв через туннель.
4. **Split-tunnel + kill-switch ОДНОВРЕМЕННО** (проверка Q5): Exclude-назначение идёт мимо туннеля,
   остальное заблокировано при KS (WFP). Раньше приходилось гасить KS — теперь работает вместе.
5. **Kill-switch fail-closed**: убить `app.exe` (не clean) при активном туннеле → не-туннельный трафик
   заблокирован (WFP держится службой). Clean disconnect → WFP снят, интернет вернулся.
6. **Reconnect**: toggle сети (WiFi off/on) → сессия переустанавливается, reader не течёт (CancelIoEx).
7. **Пайп-ACL**: сторонний процесс НЕ interactive-user (напр. из-под другой сессии) не подключается к пайпу.

## 5. Известные ограничения / follow-up
- **persistent-WFP** (fail-closed через краш САМОЙ службы) — не реализован: сейчас app-crash → WFP держится
  (служба жива); service-crash → BFE чистит фильтры, SCM рестартит службу (5с) и переармирует на реконнекте
  (краткое окно). Полный вариант (FWP_FILTER_FLAG_PERSISTENT + очистка осиротевших + escape-hatch `--disarm`) —
  валидировать на устройстве.
- **Branding**: exe называется `app.exe` (Flutter `BINARY_NAME`). Опц. переименовать в `app/windows/CMakeLists.txt`
  (`set(BINARY_NAME "CitadelPQVPN")`) + иконка в `runner/Runner.rc` — тогда обновить `#define AppExe` в citadel.iss.
- **ARM64**: сборка та же, таргеты `aarch64-pc-windows-msvc` + wintun arm64 + `ArchitecturesAllowed=arm64`.
- **Альтернатива WiX**: MSI c нативными `<ServiceInstall>/<ServiceControl>` вместо `citadel-svc install` —
  лучше для GPO/enterprise-развёртывания; Inno выбран как быстрый путь, переиспользующий код службы.

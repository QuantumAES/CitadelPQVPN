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
  авто-рестарт при краше, SDDL-грант `SERVICE_START` интерактивному пользователю — см. §3.1) →
  `net start CitadelPQVPN` → ярлыки. Приложение стартует **под пользователем**
  (`runasoriginaluser` — де-эскалация из elevated-установщика). `install` **идемпотентен**: при апгрейде
  служба уже есть — конфиг/SDDL обновляются на существующей (иначе новые настройки не доехали бы до тех,
  кто обновляется, а не ставит с нуля).
- **Uninstall:** `net stop CitadelPQVPN` → `citadel-svc uninstall` → удаление файлов.

### 3.1 Жизненный цикл службы (п.2, 2026-07-25): не висеть без приложения
Раньше `citadel-svc.exe` (LocalSystem) работал всегда — даже когда приложение закрыто, т.е. elevated-процесс
со слушающим пайпом висел без клиента. Теперь:
- **Выход из приложения** (крестик «Отключить и выйти» или «Выход» из трея) → Dart `desktopServiceQuit()` →
  кадр **`TAG_QUIT`** по пайпу → служба выходит из serve-цикла и останавливается (процесс уходит из задач).
  Шлётся ПОСЛЕ `vpn_disconnect` (пока идёт сессия, serve занят pump'ом); открытие пайпа коротко ретраится
  (~2.5 с), пока служба доделывает teardown. Best-effort: не дошло — служба просто продолжит работать.
- **Следующее подключение** → `WindowsTunProvider` поднимает службу через SCM (`StartService`) и ждёт `Running`.
- **Почему `TAG_QUIT`, а не `ControlService(STOP)`:** остановку принимает только аутентифицированный (W3:
  образ клиента из install-dir) клиент и только когда сессии НЕТ (serve-цикл обслуживает по одному) ⇒
  посторонний локальный пользователь не снимет службу с активным туннелем вместе с WFP-kill-switch
  (fail-open = деанон). Поэтому в SDDL даётся **только `RP` (SERVICE_START)**, без `WP` (SERVICE_STOP):
  старт поднимает лишь слушателя пайпа, который сам аутентифицирует клиента.
- **AutoStart сохранён** — если `sc sdset` не отработал (политики домена и т.п.), служба вернётся после
  перезагрузки, а до тех пор приложение покажет ошибку старта службы.

### 3.2 Одна копия приложения (п.2)
`app/windows/runner/main.cpp`: мьютекс `Local\CitadelPQVPN.SingleInstance` (per-сеанс — RDP/несколько
пользователей независимы). Вторая копия не стартует, а показывает окно первой (`FindWindowW` по заголовку
+ `ShowWindow`/`SetForegroundWindow`; окно могло быть скрыто в трей). Иначе две копии делили бы vault
и боролись за пайп службы = второй туннель поверх первого.

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
8. **Одна копия (п.2)**: запустить ярлык дважды → второй процесс не появляется, окно первого выходит вперёд
   (в т.ч. когда оно свёрнуто в трей).
9. **Жизненный цикл службы (п.2)**: выйти из приложения → `citadel-svc.exe` исчезает из «Диспетчера задач»,
   служба в `services.msc` = Stopped; запустить приложение и подключиться → служба сама стартует (без UAC),
   туннель поднимается. Проверить и путь «выход при активном туннеле» (сначала disconnect, потом остановка).

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

## 6. CI и раннеры

Workflow **`.github/workflows/windows.yml`** (триггеры: push в `main`/`dev` по путям, PR, ручной):

| Job | Что делает | Раннер |
|-----|-----------|--------|
| `rust` (обязательный) | `cargo test -p citadel-winnet -p citadel-winsvc` + `cargo build -p citadel-winsvc --release` + `cargo clippy` (winnet/winsvc/client) `-D warnings` под **MSVC** | `windows-latest` |
| `installer` (push/dispatch) | Flutter-бандл + служба + WinTUN + Inno → артефакт `CitadelPQVPN-Setup-unsigned` | `windows-latest` |

**Что CI ЛОВИТ:** компиляция и линковка под MSVC (WFP/FWPM, named-pipe, SCM, CancelIoEx — то, что
Linux `windows-gnu` не покрывает полностью) + пуре-юнит-тесты winnet/winsvc на Windows.

**Чего CI НЕ ловит (нужна настоящая машина):** создание WinTUN-адаптера, WFP-фильтры, регистрация/старт
службы, packet-pump, reconnect — GitHub-hosted раннер это не запускает (нет админ-сессии, драйвера, интерактива).
Полный **device-E2E** (§4) — только на реальном Windows с админом.

### GitHub-hosted `windows-latest` (что уже есть / что доставляет workflow)
- **Предустановлено:** VS2022 Build Tools (MSVC + Windows SDK), CMake, rustup, choco, git.
- **Доставляет workflow:** `nasm` (для aws-lc-rs), Flutter (`subosito/flutter-action`), Inno Setup (`choco`),
  `wintun.dll` (скачивается с wintun.net). MSVC-таргет — дефолт на Windows-раннере.

### Self-hosted раннер (нужен для реального E2E)
Если хотите гонять **рантайм-тесты WinTUN/WFP/службы** в CI — только self-hosted на реальной/VM Windows:
1. **ОС:** Windows 10/11 x64 (или Server 2022), **не** Core (нужен GUI-стек для WinTUN/интерактива).
2. **Поставить** всё из §1 (VS2022 C++, Flutter, rustup+msvc-target, Inno6, nasm) + положить `wintun.dll`.
3. **Runner-агент:** GitHub → repo Settings → Actions → Runners → New self-hosted runner (Windows x64),
   распаковать, `./config.cmd`, зарегистрировать с меткой (напр. `windows-e2e`).
4. **Права:** для установки службы/создания адаптера раннер должен работать **с админ-правами** —
   запускать агент **интерактивно от админа** (`./run.cmd`), НЕ как ограниченную службу (LocalService).
   Драйвер WinTUN ставится при первом создании адаптера — нужен админ и подписанный `wintun.dll` (он подписан WireGuard).
5. **Изоляция:** такой раннер меняет системную сеть (адаптер/маршруты/WFP) — держите на выделенной VM,
   с snapshot-откатом; НЕ на shared-хосте.
6. В workflow-job для E2E: `runs-on: [self-hosted, windows-e2e]` + шаги установки/старта службы и smoke-теста.

> Рекомендация: обязательный гейт (`rust`) — на GitHub-hosted (дёшево, ловит компиляцию/линт); реальный
> E2E — вручную по §4 ЛИБО на выделенном self-hosted admin-раннере (по желанию).

## 7. Быстрая ручная итерация (без полного бандла)
- Только служба (быстро, без Flutter): `cargo build -p citadel-winsvc --release --target x86_64-pc-windows-msvc`
  → `target\x86_64-pc-windows-msvc\release\citadel-svc.exe`. Отладка: `citadel-svc --console` (elevated) —
  слушает пайп в консоли без SCM; можно ткнуть тестовым клиентом.
- Ядро-провайдер под MSVC-артефакт с Linux (для CI/compile-check без Windows): `cargo xwin build --target
  x86_64-pc-windows-msvc -p citadel-client` (нужен `cargo-xwin`). Полный app-бандл — всё равно только на Windows.

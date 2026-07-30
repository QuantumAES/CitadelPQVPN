; ═══════════════════════════════════════════════════════════════════════════
;  CitadelPQVPN — Inno Setup инсталлятор (Windows, модель W2).
;
;  Ставит: Flutter-бандл (app.exe + citadel_client.dll ядро + data/) +
;  привилегированную службу citadel-svc.exe + wintun.dll. Регистрирует службу
;  через `citadel-svc install` (SCM, AutoStart) и стартует её.
;
;  Собирается скриптом build-windows.ps1 (готовит payload\ рядом с этим .iss),
;  затем: ISCC.exe /DAppVersion=X.Y.Z citadel.iss
;  Компилятор — Inno Setup 6 (ISCC.exe). Подпись — signtool (см. build-windows.ps1).
; ═══════════════════════════════════════════════════════════════════════════

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define AppName "CitadelPQVPN"
#define Publisher "CitadelPQVPN"
#define SvcExe "citadel-svc.exe"
#define FlutterExe "app.exe"      ; Flutter BINARY_NAME (app/windows/CMakeLists: set(BINARY_NAME "app"))
#define AppExe "CitadelPQVPN.exe" ; п.1: инсталлятор переименовывает app.exe → CitadelPQVPN.exe
#define SvcName "CitadelPQVPN"    ; = SERVICE_NAME в citadel-svc

[Setup]
; AppId — СТАБИЛЬНЫЙ GUID (не менять между версиями: по нему находится прошлая установка для апгрейда).
AppId={{7E2C1A94-1D6B-4C8E-9B2A-CITADELPQVPN01}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
; Служба ставится в SCM → нужен админ (UAC).
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
OutputBaseFilename=CitadelPQVPN-Setup-{#AppVersion}
WizardStyle=modern
; Закрыть app перед апгрейдом/сносом (файлы заняты, иначе reboot-required).
CloseApplications=yes

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Flutter-бандл целиком (flutter_windows.dll + citadel_client.dll + data\ + прочие DLL), КРОМЕ
; главного exe — его ставим следующей строкой под брендовым именем (п.1).
Source: "payload\app\*"; DestDir: "{app}"; Excludes: "{#FlutterExe}"; Flags: recursesubdirs ignoreversion
; Главный exe приложения: app.exe → CitadelPQVPN.exe (п.1). Flutter грузит data\/DLL относительно
; своего КАТАЛОГА, не имени — переименование безопасно (и W3 сверяет каталог клиента, не имя).
Source: "payload\app\{#FlutterExe}"; DestDir: "{app}"; DestName: "{#AppExe}"; Flags: ignoreversion
; Привилегированная служба + WinTUN (грузится службой рантаймом из своей папки).
Source: "payload\{#SvcExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Зарегистрировать службу (установщик уже elevated → citadel-svc install создаёт службу в SCM).
; Он же выдаёт интерактивному пользователю право SERVICE_START (sc sdset) — без него приложение без
; прав администратора не поднимет туннель («OpenService: Отказано в доступе»).
Filename: "{app}\{#SvcExe}"; Parameters: "install"; StatusMsg: "Регистрация службы {#SvcName}…"; Flags: runhidden waituntilterminated
; Запустить службу сейчас — ВСЕГДА, в т.ч. при обновлении: PrepareToInstall её остановил, чтобы
; заменить занятые файлы, и без этого шага компьютер остался бы с погашенной службой.
Filename: "{sys}\net.exe"; Parameters: "start {#SvcName}"; Flags: runhidden waituntilterminated
; Запустить приложение ПОД ПОЛЬЗОВАТЕЛЕМ (runasoriginaluser — де-эскалация из elevated-установщика).
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Остановить + снять службу ДО удаления файлов (иначе citadel-svc.exe/wintun.dll заняты).
Filename: "{sys}\net.exe"; Parameters: "stop {#SvcName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopSvc"
Filename: "{app}\{#SvcExe}"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "DelSvc"

[Code]
{ Обновление поверх работающей установки: citadel-svc.exe и wintun.dll держит ЗАПУЩЕННАЯ служба, и
  без остановки Inno не может их заменить — файлы уезжают в «замену при перезагрузке», а до неё в
  памяти продолжает работать СТАРАЯ служба (ровно тот класс «фикс на диске есть, а в памяти нет»,
  который уже стоил разбирательства на Linux-демоне). Поэтому гасим службу до копирования файлов;
  обратно её поднимает шаг `net start` в [Run]. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\net.exe'), 'stop {#SvcName}', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

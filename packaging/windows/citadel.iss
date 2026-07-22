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
#define AppExe "app.exe"          ; Flutter BINARY_NAME (app/windows/CMakeLists: set(BINARY_NAME "app"))
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
; Flutter-бандл целиком (app.exe + flutter_windows.dll + citadel_client.dll + data\ + прочие DLL).
Source: "payload\app\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
; Привилегированная служба + WinTUN (грузится службой рантаймом из своей папки).
Source: "payload\{#SvcExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Зарегистрировать службу (установщик уже elevated → citadel-svc install создаёт службу в SCM).
Filename: "{app}\{#SvcExe}"; Parameters: "install"; StatusMsg: "Регистрация службы {#SvcName}…"; Flags: runhidden waituntilterminated
; Запустить службу сейчас (AutoStart подхватит и на следующих загрузках).
Filename: "{sys}\net.exe"; Parameters: "start {#SvcName}"; Flags: runhidden waituntilterminated; Check: not IsUpgrade
; Запустить приложение ПОД ПОЛЬЗОВАТЕЛЕМ (runasoriginaluser — де-эскалация из elevated-установщика).
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Остановить + снять службу ДО удаления файлов (иначе citadel-svc.exe/wintun.dll заняты).
Filename: "{sys}\net.exe"; Parameters: "stop {#SvcName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopSvc"
Filename: "{app}\{#SvcExe}"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "DelSvc"

[Code]
{ Апгрейд: пропустить `net start` (служба уже есть/запущена; install переустановит конфиг). }
function IsUpgrade(): Boolean;
var prev: String;
begin
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1', 'UninstallString', prev)
         or RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1', 'UninstallString', prev);
end;

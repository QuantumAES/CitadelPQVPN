#include "flutter_window.h"

#include <flutter/standard_method_codec.h>

#include <optional>

#include "flutter/generated_plugin_registrant.h"
#include "resource.h"

namespace {
// #5.5 системный трей: сообщение-колбэк иконки, её UID и команды контекст-меню.
constexpr UINT WM_CITADEL_TRAY = WM_APP + 1;
constexpr UINT kTrayIconId = 1;
constexpr UINT kCmdOpen = 40001;
constexpr UINT kCmdDisconnect = 40002;
constexpr UINT kCmdExit = 40003;

// UTF-8 (из Dart) → UTF-16 wide (Win32 *W-API). Пустая строка → пустая.
std::wstring Utf8ToWide(const std::string& s) {
  if (s.empty()) return std::wstring();
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                              nullptr, 0);
  if (n <= 0) return std::wstring();
  std::wstring w(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
  return w;
}
}  // namespace

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  RegisterPlugins(flutter_controller_->engine());
  SetupTrayChannel();  // #5.5: method-channel citadel/tray
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  flutter_controller_->engine()->SetNextFrameCallback([&]() {
    this->Show();
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::OnDestroy() {
  RemoveTrayIcon();     // #5.5: убрать иконку трея до сноса окна/движка
  tray_channel_ = nullptr;
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

// ── #5.5 системный трей (Windows-native) ──

void FlutterWindow::SetupTrayChannel() {
  tray_channel_ =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          flutter_controller_->engine()->messenger(), "citadel/tray",
          &flutter::StandardMethodCodec::GetInstance());
  tray_channel_->SetMethodCallHandler(
      [this](const flutter::MethodCall<flutter::EncodableValue>& call,
             std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>
                 result) {
        const std::string& method = call.method_name();
        if (method == "init") {
          if (const auto* args =
                  std::get_if<flutter::EncodableMap>(call.arguments())) {
            auto get = [&](const char* key) -> std::string {
              auto it = args->find(flutter::EncodableValue(std::string(key)));
              if (it != args->end()) {
                if (const auto* s = std::get_if<std::string>(&it->second)) {
                  return *s;
                }
              }
              return std::string();
            };
            std::string tip = get("tooltip");
            if (!tip.empty()) tray_tip_ = Utf8ToWide(tip);
            label_open_ = Utf8ToWide(get("open"));
            label_disconnect_ = Utf8ToWide(get("disconnect"));
            label_exit_ = Utf8ToWide(get("exit"));
          }
          AddTrayIcon();
          result->Success();
        } else if (method == "setConnected") {
          if (const auto* b = std::get_if<bool>(call.arguments())) {
            tray_connected_ = *b;
          }
          result->Success();
        } else if (method == "dispose") {
          RemoveTrayIcon();
          result->Success();
        } else {
          result->NotImplemented();
        }
      });
}

void FlutterWindow::AddTrayIcon() {
  if (tray_added_) return;
  ZeroMemory(&tray_nid_, sizeof(tray_nid_));
  tray_nid_.cbSize = sizeof(tray_nid_);
  tray_nid_.hWnd = GetHandle();
  tray_nid_.uID = kTrayIconId;
  tray_nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  tray_nid_.uCallbackMessage = WM_CITADEL_TRAY;
  tray_nid_.hIcon =
      LoadIconW(GetModuleHandle(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON));
  wcsncpy_s(tray_nid_.szTip, tray_tip_.c_str(), _TRUNCATE);
  Shell_NotifyIconW(NIM_ADD, &tray_nid_);
  tray_added_ = true;
}

void FlutterWindow::RemoveTrayIcon() {
  if (!tray_added_) return;
  Shell_NotifyIconW(NIM_DELETE, &tray_nid_);
  tray_added_ = false;
}

void FlutterWindow::ShowTrayMenu() {
  HMENU menu = CreatePopupMenu();
  if (!menu) return;
  AppendMenuW(menu, MF_STRING, kCmdOpen,
              label_open_.empty() ? L"Open" : label_open_.c_str());
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  if (tray_connected_ && !label_disconnect_.empty()) {
    AppendMenuW(menu, MF_STRING, kCmdDisconnect, label_disconnect_.c_str());
  }
  AppendMenuW(menu, MF_STRING, kCmdExit,
              label_exit_.empty() ? L"Exit" : label_exit_.c_str());

  HWND hwnd = GetHandle();
  // Требование Win32: без SetForegroundWindow меню не закрывается по клику мимо него.
  SetForegroundWindow(hwnd);
  POINT pt;
  GetCursorPos(&pt);
  UINT cmd = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                            pt.x, pt.y, 0, hwnd, nullptr);
  DestroyMenu(menu);
  if (cmd == kCmdOpen) {
    InvokeTray("onOpen");
  } else if (cmd == kCmdDisconnect) {
    InvokeTray("onDisconnect");
  } else if (cmd == kCmdExit) {
    InvokeTray("onExit");
  }
}

void FlutterWindow::InvokeTray(const std::string& method) {
  if (tray_channel_) {
    tray_channel_->InvokeMethod(method, nullptr);
  }
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  // #5.5: сообщение-колбэк иконки трея (наше WM_APP+1; Flutter его не обрабатывает).
  if (message == WM_CITADEL_TRAY) {
    switch (LOWORD(lparam)) {
      case WM_LBUTTONUP:
      case WM_LBUTTONDBLCLK:
        InvokeTray("onOpen");  // левый клик → показать окно
        break;
      case WM_RBUTTONUP:
      case WM_CONTEXTMENU:
        ShowTrayMenu();  // правый клик → контекст-меню
        break;
      default:
        break;
    }
    return 0;
  }

  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_FONTCHANGE:
      flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}

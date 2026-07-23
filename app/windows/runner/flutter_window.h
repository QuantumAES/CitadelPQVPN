#ifndef RUNNER_FLUTTER_WINDOW_H_
#define RUNNER_FLUTTER_WINDOW_H_

#include <flutter/dart_project.h>
#include <flutter/encodable_value.h>
#include <flutter/flutter_view_controller.h>
#include <flutter/method_channel.h>

#include <windows.h>
#include <shellapi.h>

#include <memory>
#include <string>

#include "win32_window.h"

// A window that does nothing but host a Flutter view.
class FlutterWindow : public Win32Window {
 public:
  // Creates a new FlutterWindow hosting a Flutter view running |project|.
  explicit FlutterWindow(const flutter::DartProject& project);
  virtual ~FlutterWindow();

 protected:
  // Win32Window:
  bool OnCreate() override;
  void OnDestroy() override;
  LRESULT MessageHandler(HWND window, UINT const message, WPARAM const wparam,
                         LPARAM const lparam) noexcept override;

 private:
  // The project to run.
  flutter::DartProject project_;

  // The Flutter instance hosted by this window.
  std::unique_ptr<flutter::FlutterViewController> flutter_controller_;

  // ── #5.5 системный трей (Windows-native, Shell_NotifyIcon) ──
  // Method-channel `citadel/tray` для связи с Dart (lib/windows_tray.dart):
  // Dart → C++: init / setConnected / dispose; C++ → Dart: onOpen / onDisconnect / onExit.
  void SetupTrayChannel();
  void AddTrayIcon();
  void RemoveTrayIcon();
  void ShowTrayMenu();
  void InvokeTray(const std::string& method);

  std::unique_ptr<flutter::MethodChannel<flutter::EncodableValue>> tray_channel_;
  NOTIFYICONDATAW tray_nid_{};
  bool tray_added_ = false;
  bool tray_connected_ = false;
  // Подписи меню приходят из Dart (UTF-8 → wide) — без кириллических литералов в .cpp.
  std::wstring tray_tip_ = L"CitadelPQVPN";
  std::wstring label_open_;
  std::wstring label_disconnect_;
  std::wstring label_exit_;
};

#endif  // RUNNER_FLUTTER_WINDOW_H_

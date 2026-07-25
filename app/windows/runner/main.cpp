#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <windows.h>

#include "flutter_window.h"
#include "utils.h"

// п.2: имя мьютекса единственного экземпляра. Local\ (не Global\) — предел «одна копия НА СЕАНС
// пользователя»: разные пользователи RDP/быстрого переключения работают независимо, у каждого свой
// профиль/vault. Заголовок окна ищем ровно тот, что ставит runner и window_manager (main.dart).
constexpr const wchar_t kSingleInstanceMutex[] = L"Local\\CitadelPQVPN.SingleInstance";
constexpr const wchar_t kWindowTitle[] = L"CitadelPQVPN";

// Показать окно уже работающей копии (в т.ч. свёрнутой в системный трей — тогда оно скрыто) и
// вынести его на передний план. `false` — окно не найдено (копия ещё стартует / зависла).
static bool ActivateRunningInstance() {
  HWND hwnd = ::FindWindowW(nullptr, kWindowTitle);
  if (!hwnd) {
    return false;
  }
  if (!::IsWindowVisible(hwnd)) {
    ::ShowWindow(hwnd, SW_SHOW);  // из трея (#5.5 скрывает окно, а не закрывает)
  }
  if (::IsIconic(hwnd)) {
    ::ShowWindow(hwnd, SW_RESTORE);
  }
  ::SetForegroundWindow(hwnd);
  return true;
}

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  // п.2: запрет второй копии. Две копии делили бы vault/профили и, главное, боролись бы за
  // named pipe службы (второй туннель поверх первого = сорванный kill-switch/маршруты).
  // Мьютекс держим до конца процесса (закроет ОС при выходе) — освобождать не нужно.
  HANDLE single_instance = ::CreateMutexW(nullptr, TRUE, kSingleInstanceMutex);
  if (single_instance == nullptr || ::GetLastError() == ERROR_ALREADY_EXISTS) {
    if (single_instance != nullptr) {
      ::CloseHandle(single_instance);
    }
    ActivateRunningInstance();  // показать уже запущенную копию вместо старта второй
    return EXIT_SUCCESS;
  }

  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  // Портретное окно в стиле OpenVPN Connect (узкое+высокое). window_manager в main.dart затем
  // фиксирует размер (400x680) и отключает ресайз; здесь стартовый размер, чтобы не мелькнул 1280x720.
  Win32Window::Size size(400, 680);
  if (!window.Create(L"CitadelPQVPN", origin, size)) {
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}

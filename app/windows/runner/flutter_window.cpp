#include "flutter_window.h"

#include <flutter/standard_method_codec.h>

#include <cstdint>
#include <optional>
#include <vector>

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
        } else if (method == "setPhase") {
          // Dart шлёт {phase: off|connecting|up|error, tooltip: "<текст состояния>"}.
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
            const std::string phase = get("phase");
            if (phase == "up") {
              tray_phase_ = TrayPhase::Up;
            } else if (phase == "connecting") {
              tray_phase_ = TrayPhase::Connecting;
            } else if (phase == "error") {
              tray_phase_ = TrayPhase::Error;
            } else {
              tray_phase_ = TrayPhase::Off;
            }
            // Пункт «Отключить туннель» в меню имеет смысл, пока сессия жива (up/connecting).
            tray_connected_ = (tray_phase_ == TrayPhase::Up ||
                               tray_phase_ == TrayPhase::Connecting);
            const std::string tip = get("tooltip");
            if (!tip.empty()) tray_tip_ = Utf8ToWide(tip);
            ApplyTrayPhase();
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

// Иконка трея под состояние: базовая IDI_APP_ICON нужного системного размера + цветная точка-бейдж
// в правом нижнем углу (Off — база ещё и обесцвечивается, чтобы «выключено» читалось боковым
// зрением, а не только по оттенку точки). Всё делается попиксельно в 32bpp DIB: GDI-примитивы
// (Ellipse и т.п.) не пишут альфу, и бейдж поверх иконки с альфа-каналом вышел бы прозрачным.
// При любой неудаче возвращаем nullptr — вызывающий оставит обычную иконку приложения.
HICON FlutterWindow::MakeTrayIcon(TrayPhase phase) {
  const int cx = GetSystemMetrics(SM_CXSMICON);
  const int cy = GetSystemMetrics(SM_CYSMICON);
  if (cx <= 0 || cy <= 0) return nullptr;

  HICON base = static_cast<HICON>(LoadImageW(GetModuleHandle(nullptr),
                                             MAKEINTRESOURCEW(IDI_APP_ICON),
                                             IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
  if (!base) return nullptr;

  BITMAPINFO bi{};
  bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bi.bmiHeader.biWidth = cx;
  bi.bmiHeader.biHeight = -cy;  // top-down: строка 0 — верхняя
  bi.bmiHeader.biPlanes = 1;
  bi.bmiHeader.biBitCount = 32;
  bi.bmiHeader.biCompression = BI_RGB;

  // Пиксели базовой иконки берём НЕ через DrawIconEx: рисование GDI на DIB не обязано сохранять
  // альфа-канал (классическая ловушка — иконка получается полностью прозрачной). Читаем битмап
  // иконки напрямую: GetIconInfo → GetDIBits(32bpp, top-down).
  ICONINFO base_info{};
  if (!GetIconInfo(base, &base_info)) {
    DestroyIcon(base);
    return nullptr;
  }
  // Размер битмапа обязан совпасть с запрошенным (иначе GetDIBits вернул бы не то) — иначе фолбэк.
  BITMAP base_bm{};
  if (!base_info.hbmColor ||
      !GetObject(base_info.hbmColor, sizeof(base_bm), &base_bm) ||
      base_bm.bmWidth != cx || base_bm.bmHeight != cy) {
    if (base_info.hbmColor) DeleteObject(base_info.hbmColor);
    if (base_info.hbmMask) DeleteObject(base_info.hbmMask);
    DestroyIcon(base);
    return nullptr;
  }
  HDC screen = GetDC(nullptr);
  void* bits = nullptr;
  HBITMAP color = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
  if (!color || !bits) {
    if (color) DeleteObject(color);
    if (base_info.hbmColor) DeleteObject(base_info.hbmColor);
    if (base_info.hbmMask) DeleteObject(base_info.hbmMask);
    ReleaseDC(nullptr, screen);
    DestroyIcon(base);
    return nullptr;
  }
  auto* px = static_cast<uint8_t*>(bits);  // BGRA, premultiplied
  const size_t stride = static_cast<size_t>(cx) * 4;
  const size_t pixels = static_cast<size_t>(cx) * static_cast<size_t>(cy);

  if (base_info.hbmColor) {
    GetDIBits(screen, base_info.hbmColor, 0, cy, px, &bi, DIB_RGB_COLORS);
  }
  // Иконка без альфа-канала (легаси 24/8bpp): альфа пришла нулевой ⇒ иконка была бы невидимой.
  // Восстанавливаем прозрачность по AND-маске (бит 1 = прозрачно).
  bool has_alpha = false;
  for (size_t i = 0; i < pixels && !has_alpha; ++i) has_alpha = px[i * 4 + 3] != 0;
  if (!has_alpha && base_info.hbmMask) {
    const size_t mask_stride = ((static_cast<size_t>(cx) + 31) / 32) * 4;  // 1bpp, выравн. на DWORD
    std::vector<uint8_t> mask(mask_stride * static_cast<size_t>(cy), 0);
    BITMAPINFO mbi{};
    mbi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    mbi.bmiHeader.biWidth = cx;
    mbi.bmiHeader.biHeight = -cy;
    mbi.bmiHeader.biPlanes = 1;
    mbi.bmiHeader.biBitCount = 1;
    mbi.bmiHeader.biCompression = BI_RGB;
    if (GetDIBits(screen, base_info.hbmMask, 0, cy, mask.data(), &mbi, DIB_RGB_COLORS)) {
      for (int y = 0; y < cy; ++y) {
        for (int x = 0; x < cx; ++x) {
          const uint8_t bit = (mask[y * mask_stride + (x >> 3)] >> (7 - (x & 7))) & 1;
          px[y * stride + static_cast<size_t>(x) * 4 + 3] = bit ? 0 : 0xFF;
        }
      }
    }
  }

  if (phase == TrayPhase::Off) {
    for (int y = 0; y < cy; ++y) {
      for (int x = 0; x < cx; ++x) {
        uint8_t* p = px + y * stride + static_cast<size_t>(x) * 4;
        // Яркость по premultiplied-компонентам: связь с альфой сохраняется (gray ≤ A).
        const uint8_t g = static_cast<uint8_t>((p[0] * 29 + p[1] * 150 + p[2] * 77) >> 8);
        p[0] = p[1] = p[2] = g;
      }
    }
  }

  // Цвет бейджа (BGRA, A=255 ⇒ premultiplied == прямой). Зелёный/янтарный/красный/серый.
  uint8_t br = 0, bg = 0, bb = 0;
  switch (phase) {
    case TrayPhase::Up:         br = 0x2E; bg = 0xC4; bb = 0x6A; break;  // зелёный
    case TrayPhase::Connecting: br = 0xF5; bg = 0xA6; bb = 0x23; break;  // янтарный
    case TrayPhase::Error:      br = 0xE0; bg = 0x3B; bb = 0x2F; break;  // красный
    case TrayPhase::Off:        br = 0x9E; bg = 0x9E; bb = 0x9E; break;  // серый
  }
  // Диаметр ~44% ширины иконки (на 16px ≈ 7px) — различимо и не съедает логотип.
  const int d = (cx * 7) / 16 < 6 ? 6 : (cx * 7) / 16;
  const int x0 = cx - d, y0 = cy - d;
  const double r = d / 2.0, cxf = x0 + r - 0.5, cyf = y0 + r - 0.5;
  for (int y = y0; y < cy; ++y) {
    if (y < 0) continue;
    for (int x = x0; x < cx; ++x) {
      if (x < 0) continue;
      const double dx = x - cxf, dy = y - cyf;
      const double dist = dx * dx + dy * dy;
      uint8_t* p = px + y * stride + static_cast<size_t>(x) * 4;
      if (dist <= (r - 1.0) * (r - 1.0)) {
        p[0] = bb; p[1] = bg; p[2] = br; p[3] = 0xFF;          // тело точки
      } else if (dist <= r * r) {
        p[0] = p[1] = p[2] = 0xFF; p[3] = 0xFF;                 // светлый кант — отделяет от логотипа
      }
    }
  }

  // Маска для CreateIconIndirect: у 32bpp-иконки прозрачность берётся из альфы, но поле обязательно
  // (берём маску оригинала — корректно и для легаси-иконок без альфы).
  HBITMAP mask = base_info.hbmMask ? base_info.hbmMask : CreateBitmap(cx, cy, 1, 1, nullptr);
  ICONINFO ii{};
  ii.fIcon = TRUE;
  ii.hbmMask = mask;
  ii.hbmColor = color;
  HICON icon = CreateIconIndirect(&ii);  // битмапы копируются — ниже их можно удалять

  if (mask && mask != base_info.hbmMask) DeleteObject(mask);
  if (base_info.hbmColor) DeleteObject(base_info.hbmColor);
  if (base_info.hbmMask) DeleteObject(base_info.hbmMask);
  DeleteObject(color);
  ReleaseDC(nullptr, screen);
  DestroyIcon(base);
  return icon;
}

void FlutterWindow::ApplyTrayPhase() {
  if (!tray_added_) return;
  HICON fresh = MakeTrayIcon(tray_phase_);
  if (fresh) {
    HICON prev = tray_icon_;
    tray_icon_ = fresh;
    tray_nid_.hIcon = fresh;
    if (prev) DestroyIcon(prev);  // после подмены — иначе утечка GDI-хэндлов на каждой смене фазы
  }
  // Tooltip дублирует состояние текстом: доступность (в т.ч. дальтонизм) и точность («ошибка»
  // vs «переподключение» по цвету различимы хуже, чем по подписи).
  tray_nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  wcsncpy_s(tray_nid_.szTip, tray_tip_.c_str(), _TRUNCATE);
  Shell_NotifyIconW(NIM_MODIFY, &tray_nid_);
}

void FlutterWindow::AddTrayIcon() {
  if (tray_added_) return;
  ZeroMemory(&tray_nid_, sizeof(tray_nid_));
  tray_nid_.cbSize = sizeof(tray_nid_);
  tray_nid_.hWnd = GetHandle();
  tray_nid_.uID = kTrayIconId;
  tray_nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
  tray_nid_.uCallbackMessage = WM_CITADEL_TRAY;
  tray_icon_ = MakeTrayIcon(tray_phase_);
  tray_nid_.hIcon =
      tray_icon_ ? tray_icon_
                 : LoadIconW(GetModuleHandle(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON));
  wcsncpy_s(tray_nid_.szTip, tray_tip_.c_str(), _TRUNCATE);
  Shell_NotifyIconW(NIM_ADD, &tray_nid_);
  tray_added_ = true;
}

void FlutterWindow::RemoveTrayIcon() {
  if (!tray_added_) return;
  Shell_NotifyIconW(NIM_DELETE, &tray_nid_);
  tray_added_ = false;
  if (tray_icon_) {
    DestroyIcon(tray_icon_);
    tray_icon_ = nullptr;
  }
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
      // Проверка на nullptr: сообщение может прийти уже после OnDestroy (движок снесён) — в
      // шаблоне Flutter здесь безусловное разыменование, то есть падение на выходе.
      if (flutter_controller_) {
        flutter_controller_->engine()->ReloadSystemFonts();
      }
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}

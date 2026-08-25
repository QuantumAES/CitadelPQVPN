import 'dart:io' show Platform;

import 'package:flutter/services.dart';

/// C8.5 для **Windows** — запрет захвата окна приложения, аналог Android `FLAG_SECURE`.
///
/// Реализовано НАТИВНО в C++-runner'е (`windows/runner/flutter_window.cpp`) через method-channel
/// `citadel/window`: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` убирает окно из
/// любого захвата экрана — скриншотов, записи, демонстрации в конференции.
///
/// Зачем отдельно от тумблера «Запрет скриншотов», который до сих пор был только для Android: на
/// Copilot+ ПК систему снимает экран САМА (Recall делает периодические снимки без участия
/// пользователя и складывает их в локальный индекс). То есть на Windows содержимое окна VPN-клиента
/// — список профилей, узлы выхода, состояние туннеля — попадало в постоянное хранилище снимков,
/// которое живёт дольше сессии и переживает выход из приложения. `WDA_EXCLUDEFROMCAPTURE` закрывает
/// этот путь целиком, потому что Recall получает кадры тем же механизмом, что и запись экрана.
///
/// Защита ставится в C++ ещё в `OnCreate` (до первого показа окна), а Dart её только СНИМАЕТ, если
/// пользователь выключил настройку. Порядок именно такой: иначе между стартом процесса и чтением
/// настройки оставалось бы окно кадров, доступное для съёмки.
class WindowsSecure {
  static const _ch = MethodChannel('citadel/window');

  /// Запрет захвата поддержан только на Windows (на Android — своя реализация через FLAG_SECURE,
  /// см. `android_vpn.dart`; на Linux эквивалента у X11/Wayland нет).
  static bool get supported => Platform.isWindows;

  /// Включить/снять запрет захвата. Возвращает `true`, если система его применила.
  ///
  /// `false` при `on: true` означает, что окно РЕАЛЬНО снимается: Win32 отказал и в
  /// `WDA_EXCLUDEFROMCAPTURE`, и в фолбэке `WDA_MONITOR` (тот есть со времён Vista, поэтому на
  /// поддерживаемых версиях Windows такого не бывает — отдельного состояния «тумблер включён, но
  /// не работает» в интерфейсе нет). Отдаём наружу, чтобы отказ было видно вызывающему, а не
  /// только Win32; исключения не бросаем — отсутствие защиты не повод не запустить приложение.
  static Future<bool> setSecure(bool on) async {
    if (!supported) return false;
    try {
      return await _ch.invokeMethod<bool>('setSecure', {'on': on}) ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false; // старый runner без канала citadel/window
    }
  }
}

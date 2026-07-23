import 'dart:io' show Platform;

import 'package:flutter/services.dart';

/// #5.5 — системный трей **только для Windows**, реализован НАТИВНО в C++-runner'е
/// (`windows/runner/flutter_window.cpp`, Shell_NotifyIcon) через method-channel `citadel/tray`.
///
/// Почему нативно, а не пакетом `tray_manager`: тот жёстко требует `appindicator` при сборке И в
/// рантайме Linux (его CMake падает FATAL_ERROR без библиотеки) — это ломало `flutter build linux`
/// и добавляло рантайм-зависимость VPN-клиенту. Плагин один на все desktop, только для Linux не
/// исключить. Нативный путь даёт трей там, где он нужен (Windows), не трогая Linux/Android.
///
/// Подписи меню передаются ИЗ Dart (UTF-8) — C++ конвертит UTF-8→wide, чтобы не зависеть от кодировки
/// исходника (никаких кириллических литералов в .cpp).
class WindowsTray {
  static const _ch = MethodChannel('citadel/tray');

  /// Трей поддержан только на Windows (нативная реализация в runner'е).
  static bool get supported => Platform.isWindows;

  /// Создать иконку в трее. Колбэки — на клик по иконке / пункты меню:
  ///   • [onOpen] — левый клик по иконке или «Открыть»;
  ///   • [onDisconnect] — «Отключить туннель» (пункт есть только при активном туннеле);
  ///   • [onExit] — «Выход».
  static Future<void> init({
    required void Function() onOpen,
    required void Function() onDisconnect,
    required void Function() onExit,
  }) async {
    if (!supported) return;
    _ch.setMethodCallHandler((call) async {
      switch (call.method) {
        case 'onOpen':
          onOpen();
        case 'onDisconnect':
          onDisconnect();
        case 'onExit':
          onExit();
      }
      return null;
    });
    await _ch.invokeMethod('init', <String, String>{
      'tooltip': 'CitadelPQVPN',
      'open': 'Открыть CitadelPQVPN',
      'disconnect': 'Отключить туннель',
      'exit': 'Выход',
    });
  }

  /// Обновить состояние (влияет на видимость пункта «Отключить туннель» в меню).
  static Future<void> setConnected(bool connected) async {
    if (!supported) return;
    await _ch.invokeMethod('setConnected', connected);
  }

  /// Убрать иконку из трея (перед выходом).
  static Future<void> dispose() async {
    if (!supported) return;
    await _ch.invokeMethod('dispose');
  }
}

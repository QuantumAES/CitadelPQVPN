import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'package:app/l10n/strings.dart';

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
    required Strings t,
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
    await setMenuLabels(t);
  }

  /// Подписи меню трея на языке приложения. Отдельным вызовом, потому что язык меняется на лету:
  /// нативное меню строится из этих строк и должно пережить смену без перезапуска приложения.
  static Future<void> setMenuLabels(Strings t) async {
    if (!supported) return;
    await _ch.invokeMethod('init', <String, String>{
      'tooltip': 'CitadelPQVPN',
      'open': t('tray_open'),
      'disconnect': t('tray_disconnect'),
      'exit': t('tray_exit'),
    });
  }

  /// Обновить состояние туннеля: значок в трее получает цветную точку-бейдж (правый нижний угол),
  /// а в состоянии «выключено» ещё и обесцвечивается — состояние видно у свёрнутого приложения без
  /// его открытия. Тем же вызовом обновляется tooltip (текстовая подпись состояния — доступность,
  /// в т.ч. дальтонизм) и видимость пункта «Отключить туннель» в меню.
  ///
  ///   • серый (обесцвеченная иконка) — туннель выключен;
  ///   • янтарный — подключение/переподключение;
  ///   • зелёный — туннель активен;
  ///   • красный — ошибка (сессия не поднята).
  /// `live` — жива ли сессия ядра. Отдельный признак, потому что при бесконечном реконнекте фаза
  /// показывает причину последнего отказа (`error`), но останавливать по-прежнему есть что: без
  /// него у свёрнутого в трей приложения не оставалось НИ ОДНОГО способа прервать цикл, кроме
  /// выхода из программы.
  static Future<void> setPhase(String phase, {String? tooltip, bool live = false}) async {
    if (!supported) return;
    await _ch.invokeMethod('setPhase', <String, String>{
      'phase': phase, // off | connecting | up | error
      'tooltip': tooltip ?? 'CitadelPQVPN',
      'live': live ? '1' : '0',
    });
  }

  /// Убрать иконку из трея (перед выходом).
  static Future<void> dispose() async {
    if (!supported) return;
    await _ch.invokeMethod('dispose');
  }
}

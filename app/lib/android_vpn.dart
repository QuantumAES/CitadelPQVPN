import 'dart:io';

import 'package:flutter/services.dart';

/// Мост к нативному Android `VpnService` (канал `dev.citadelpqvpn/vpn`, см. MainActivity.kt).
/// Используется только на Android; на остальных платформах путь идёт через polkit-helper.
class AndroidVpn {
  static const _ch = MethodChannel('dev.citadelpqvpn/vpn');

  static bool get isAndroid => Platform.isAndroid;

  // Смена underlying-сети больше не идёт через Dart: NetworkCallback живёт в CitadelVpnService и
  // сигналит нативному loop по JNI напрямую (S2) — переживает Activity, работает при закрытом окне.

  /// Системный консент VpnService (показывается один раз). `true` — разрешено.
  static Future<bool> prepare() async =>
      (await _ch.invokeMethod<bool>('prepare')) ?? false;

  /// Запустить foreground-сервис туннеля.
  static Future<void> startService() => _ch.invokeMethod('startService');

  static Future<void> stopService() => _ch.invokeMethod('stopService');

  /// Открыть системные настройки VPN (там включается always-on + «блокировать без VPN» —
  /// Android kill-switch, C6). Приложение не может форсить его само.
  static Future<void> openVpnSettings() => _ch.invokeMethod('openVpnSettings');

  /// C8.3: список запускаемых приложений для split-tunnel picker'а. Каждый элемент — `(package, label)`.
  static Future<List<({String package, String label})>> listInstalledApps() async {
    final raw = await _ch.invokeMethod<List<dynamic>>('listInstalledApps') ?? const [];
    return raw
        .map((e) => (
              package: (e['package'] ?? '').toString(),
              label: (e['label'] ?? '').toString(),
            ))
        .where((e) => e.package.isNotEmpty)
        .toList();
  }
}

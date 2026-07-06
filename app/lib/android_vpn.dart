import 'dart:io';

import 'package:flutter/services.dart';

import 'package:app/src/rust/api/citadel.dart';

/// Мост к нативному Android `VpnService` (канал `dev.citadelpqvpn/vpn`, см. MainActivity.kt).
/// Используется только на Android; на остальных платформах путь идёт через polkit-helper.
class AndroidVpn {
  static const _ch = MethodChannel('dev.citadelpqvpn/vpn');

  static bool get isAndroid => Platform.isAndroid;

  /// Колбэк из native при смене underlying-сети (WiFi↔LTE/toggle) — форсировать реконнект.
  static void Function()? onNetworkChanged;
  static bool _handlerSet = false;

  /// Подписать канал на вызовы native→Dart (`onNetworkChanged`). Идемпотентно; звать один раз.
  static void ensureHandler() {
    if (_handlerSet) return;
    _handlerSet = true;
    _ch.setMethodCallHandler((call) async {
      if (call.method == 'onNetworkChanged') onNetworkChanged?.call();
      return null;
    });
  }

  /// Системный консент VpnService (показывается один раз). `true` — разрешено.
  static Future<bool> prepare() async =>
      (await _ch.invokeMethod<bool>('prepare')) ?? false;

  /// Запустить foreground-сервис туннеля.
  static Future<void> startService() => _ch.invokeMethod('startService');

  /// Построить TUN по параметрам движка (фаза 1) → fd (detached, владелец — Rust).
  static Future<int> establishTun(TunSetupDto p) async {
    final fd = await _ch.invokeMethod<int>('establishTun', {
      'addr': p.addr,
      'prefix': p.prefix,
      'routes': p.routes.split(' ').where((s) => s.isNotEmpty).toList(),
      'dns': p.dns.isEmpty
          ? <String>[]
          : p.dns.split(' ').where((s) => s.isNotEmpty).toList(),
      'mtu': int.tryParse(p.mtu) ?? 1280,
    });
    return fd ?? -1;
  }

  static Future<void> stopService() => _ch.invokeMethod('stopService');
}

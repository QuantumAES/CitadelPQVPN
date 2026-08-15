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

  /// C8.5: включить/снять FLAG_SECURE (запрет скриншотов/записи экрана). `true` — запрещено.
  static Future<void> setSecureFlag(bool on) =>
      _ch.invokeMethod('setSecureFlag', {'on': on});

  /// П8: включён ли на устройстве режим энергосбережения (`PowerManager.isPowerSaveMode`).
  /// Пока он включён, строгий профиль маскировки понижается ядром до экономного.
  static Future<bool> powerSaveMode() async =>
      (await _ch.invokeMethod<bool>('powerSaveMode')) ?? false;

  /// Тексты постоянной нотификации VPN на языке ПРИЛОЖЕНИЯ (нотификация — тот же интерфейс, а
  /// системная локаль устройства может быть другой). Зовётся на старте и при смене языка.
  static Future<void> setNotifStrings({
    required String up,
    required String connecting,
    required String reconnecting,
    required String down,
  }) =>
      _ch.invokeMethod('setNotifStrings', {
        'up': up,
        'connecting': connecting,
        'reconnecting': reconnecting,
        'down': down,
      });

  /// N-3: положить в буфер обмена ЧУВСТВИТЕЛЬНОЕ — с пометкой `EXTRA_IS_SENSITIVE` (Android 13+:
  /// системное превью показывает «•••» вместо содержимого) и автоочисткой через `ttlSeconds`.
  /// `false` — платформа не справилась, вызывающий кладёт обычным путём.
  static Future<bool> copySensitive(String text, int ttlSeconds) async =>
      (await _ch.invokeMethod<bool>(
          'copySensitive', {'text': text, 'ttlSeconds': ttlSeconds})) ??
      false;

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

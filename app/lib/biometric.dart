import 'dart:io' show Platform;

import 'package:flutter/services.dart';

/// Готовность устройства к разблокировке отпечатком (ответ канала `citadel/biometric`).
enum BiometricStatus {
  /// Датчик есть, отпечаток зарегистрирован, ключи Keystore доступны — настройку можно предлагать.
  ok,

  /// Датчика нет (или он не «сильный» класс) — настройки не существует для этого устройства.
  noHardware,

  /// Датчик есть, но в системе не зарегистрировано ни одного отпечатка: чинится в настройках ОС,
  /// поэтому формулировка для человека здесь другая, чем при отсутствии железа.
  noneEnrolled,

  /// Временно недоступна (датчик занят, слишком много попыток, политика администратора).
  unavailable,
}

/// Отказ платформенной части. Отмена пользователем — тоже «отказ», но молчаливый: интерфейс на неё
/// ничего не показывает, человек и так знает, что нажал «Отмена».
class BiometricFailure implements Exception {
  BiometricFailure(this.code, this.message);

  final String code;
  final String? message;

  /// Человек закрыл системный диалог сам.
  bool get cancelled => code == 'cancelled';

  /// Ключа в Keystore больше нет: сменилась биометрия устройства (`invalidated`) либо данные
  /// приложения очистили/переустановили (`no_key`). Слот в файле хранилища остался, но развернуть
  /// его нечем — единственное лечение — войти паролем и включить отпечаток заново.
  bool get keyGone => code == 'invalidated' || code == 'no_key';

  @override
  String toString() => 'BiometricFailure($code${message == null ? '' : ': $message'})';
}

/// C9: разблокировка хранилища отпечатком — тонкая обёртка канала `citadel/biometric`.
///
/// Всё содержательное живёт в Kotlin ([`BiometricVault`]): ключ Android Keystore, требующий
/// аутентификации на каждую операцию, и системный диалог поверх `CryptoObject`. Здесь — только
/// перенос байтов и разбор кодов ошибок.
///
/// **Секрет через этот слой проходит транзитом.** `wrap` получает мастер-ключ хранилища из ядра и
/// сразу отдаёт его в ОС; `unwrap` получает его обратно и сразу возвращает ядру. Вызывающий обязан
/// затирать свои копии — см. [zeroize] и его использование в `AppState`.
class BiometricUnlock {
  static const _ch = MethodChannel('citadel/biometric');

  /// Платформы, где разблокировка отпечатком реализована. Windows Hello и macOS Touch ID
  /// подключаются тем же слотом в формате хранилища, но своей платформенной половиной — сейчас её
  /// нет, и настройка там не показывается (обещать то, чего не делаем, нельзя).
  static bool get supported => Platform.isAndroid;

  static Future<BiometricStatus> status() async {
    if (!supported) return BiometricStatus.noHardware;
    try {
      final s = await _ch.invokeMethod<String>('status');
      return switch (s) {
        'ok' => BiometricStatus.ok,
        'none_enrolled' => BiometricStatus.noneEnrolled,
        'no_hardware' => BiometricStatus.noHardware,
        _ => BiometricStatus.unavailable,
      };
    } on PlatformException {
      return BiometricStatus.unavailable;
    } on MissingPluginException {
      return BiometricStatus.noHardware; // сборка без канала (старый runner)
    }
  }

  /// Включение: завернуть мастер-ключ хранилища ключом Keystore. Спрашивает отпечаток.
  static Future<Uint8List> wrap(Uint8List secret, BiometricTexts t) =>
      _call('wrap', {'secret': secret, ...t.args});

  /// Разблокировка: развернуть мастер-ключ из блоба. Спрашивает отпечаток.
  static Future<Uint8List> unwrap(Uint8List blob, BiometricTexts t) =>
      _call('unwrap', {'blob': blob, ...t.args});

  /// Выключение: удалить ключ из Keystore. Без диалога — отзывать доступ человек должен свободно.
  static Future<void> remove() async {
    if (!supported) return;
    try {
      await _ch.invokeMethod<bool>('remove');
    } on PlatformException {
      // ключа и так нет — цель достигнута
    } on MissingPluginException {
      // нечего удалять
    }
  }

  static Future<Uint8List> _call(String method, Map<String, Object?> args) async {
    try {
      final out = await _ch.invokeMethod<Uint8List>(method, args);
      if (out == null || out.isEmpty) {
        throw BiometricFailure('empty', 'платформа вернула пустой ответ');
      }
      return out;
    } on PlatformException catch (e) {
      throw BiometricFailure(e.code, e.message);
    } on MissingPluginException {
      throw BiometricFailure('no_hardware', null);
    }
  }

  /// Затереть копию секрета в памяти Dart. Гарантий у управляемой памяти нет (GC мог сделать копию
  /// при перемещении), но оставлять ключ хранилища лежать в куче до следующей сборки мусора — это
  /// на порядок хуже, чем не идеальное, но немедленное затирание.
  static void zeroize(Uint8List b) => b.fillRange(0, b.length, 0);
}

/// Тексты системного диалога. Приходят из l10n приложения, а не из системной локали: язык
/// интерфейса выбирает пользователь в самом клиенте (та же логика, что у строк нотификации VPN).
class BiometricTexts {
  const BiometricTexts({required this.title, required this.subtitle, required this.cancel});

  final String title;
  final String subtitle;
  final String cancel;

  Map<String, Object?> get args => {'title': title, 'subtitle': subtitle, 'cancel': cancel};
}

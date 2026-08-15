import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

import 'package:app/android_vpn.dart';

/// N-3: буфер обмена для чувствительного — ссылки абонента и `client_id`.
///
/// Обычное копирование оставляет секрет в системном буфере до перезагрузки, а на Android ещё и
/// показывает его в превью-плашке на весь экран. Риск ограничен тем, что абонентская ссылка
/// одноразовая и живёт 24 часа (M-9), но тем же механизмом копируется мастер-ссылка.
///
/// Что делает:
///   * **Android** — уходит в платформенный путь (`SensitiveClipboard.kt`): пометка
///     `EXTRA_IS_SENSITIVE` (Android 13+) + очистка Handler'ом процесса;
///   * **десктоп** — обычный буфер плюс таймер очистки в этом изоляте.
///
/// Чего НЕ делает и обещать не может: буфер — общий ресурс системы, его успевают прочитать
/// менеджеры буфера и (до Android 10) любое фоновое приложение. Это сокращение окна, а не запрет.
class SensitiveClipboard {
  /// Сколько живёт скопированное. 90 секунд — верхняя граница из роадмапа: успеть вставить в
  /// мессенджер, но не оставить ссылку в буфере на весь день.
  static const Duration ttl = Duration(seconds: 90);

  /// Что мы положили последним: чистим ТОЛЬКО это. Между копированием и очисткой человек мог
  /// скопировать своё, и затирать чужое — сломанное поведение (на Android так же, см. Kotlin).
  static String? _pending;
  static Timer? _timer;

  /// Скопировать [text] как чувствительное.
  static Future<void> copy(String text) async {
    if (Platform.isAndroid) {
      if (await AndroidVpn.copySensitive(text, ttl.inSeconds)) return;
      // Платформа не справилась (нет буфера/отказ) — кладём обычным путём, но без автоочистки
      // врать не будем: она ниже включается только для десктопного пути.
      await Clipboard.setData(ClipboardData(text: text));
      return;
    }
    await Clipboard.setData(ClipboardData(text: text));
    _pending = text;
    _timer?.cancel();
    _timer = Timer(ttl, _clearIfOurs);
  }

  static Future<void> _clearIfOurs() async {
    final want = _pending;
    _timer = null;
    if (want == null) return;
    final current = (await Clipboard.getData(Clipboard.kTextPlain))?.text;
    _pending = null;
    if (current != want) return; // в буфере уже чужое — не трогаем
    await Clipboard.setData(const ClipboardData(text: ''));
  }

  /// Только для тестов: снять отложенную очистку.
  static void cancelForTest() {
    _timer?.cancel();
    _timer = null;
    _pending = null;
  }
}

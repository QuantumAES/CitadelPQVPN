import 'package:flutter_rust_bridge/flutter_rust_bridge.dart'
    show AnyhowException, PanicException;
import 'package:flutter_test/flutter_test.dart';

import 'package:app/errors.dart';

/// Что именно приезжает из ядра. FRB кодирует ошибку как `format!("{:?}", anyhow::Error)`, а
/// `Debug` у anyhow к верхней (человеческой) строке дописывает служебные блоки. Ровно эти формы
/// и проверяем: их не должно быть на экране ни в одном виде.
void main() {
  group('humanError', () {
    test('оставляет только верхнюю строку, backtrace срезан', () {
      // Отказ БЕЗ причин (`anyhow!`/`bail!`) — тот самый случай, где блок кадров шёл сразу за
      // фразой и доезжал до пользователя: «Неверный мастер-пароль» + простыня адресов.
      final e = AnyhowException('Неверный мастер-пароль\n\n'
          'Stack backtrace:\n'
          '   0: rust_lib_app::api::citadel::vault_unlock\n'
          '   1: core::ops::function::FnOnce::call_once\n');
      expect(humanError(e), 'Неверный мастер-пароль');
    });

    test('срезает backtrace и у отказа валидации поля', () {
      final e = AnyhowException(
          'Имя профиля не может быть пустым\n\nStack backtrace:\n   0: foo\n');
      expect(humanError(e), 'Имя профиля не может быть пустым');
    });

    test('срезает нижний регистр «stack backtrace:»', () {
      final e = AnyhowException('Ссылка не распознана\n\nstack backtrace:\n   0: bar');
      expect(humanError(e), 'Ссылка не распознана');
    });

    test('срезает цепочку причин', () {
      final e = AnyhowException('Хранилище недоступно: не прочитать файл\n\n'
          'Caused by:\n    0: os error 13\n\n'
          'Stack backtrace:\n   0: baz');
      expect(humanError(e), 'Хранилище недоступно: не прочитать файл');
    });

    test('сохраняет намеренный перенос строки внутри фразы', () {
      // Ядро само переносит путь на вторую строку — склеивать его нельзя (обрежется в диалоге).
      final e = AnyhowException(
          'Нет доступа к папке хранилища:\nC:\\Program Files\\CitadelPQVPN\n\nStack backtrace:\n   0: q');
      expect(humanError(e),
          'Нет доступа к папке хранилища:\nC:\\Program Files\\CitadelPQVPN');
    });

    test('разворачивает обёртку FFI (не «AnyhowException(...)»)', () {
      expect(humanError(AnyhowException('Сервер недоступен')), 'Сервер недоступен');
      expect(humanError(AnyhowException('Сервер недоступен')), isNot(contains('AnyhowException')));
    });

    test('паника ядра: без хвоста Debug-backtrace', () {
      // FRB приклеивает `format!("{b:?}")` к тексту паники БЕЗ разделителя — и `Backtrace [ … ]`,
      // и `<disabled>` (когда захват выключён) оказываются прямо в сообщении.
      expect(
        humanError(PanicException('called `Option::unwrap()` on a `None` value<disabled>')),
        'called `Option::unwrap()` on a `None` value',
      );
      expect(
        humanError(PanicException('assertion failed: x > 0Backtrace [\n  { fn: "a" },\n]')),
        'assertion failed: x > 0',
      );
    });

    test('длинный текст подрезается, диалог остаётся читаемым', () {
      final out = humanError(AnyhowException('я' * 500));
      expect(out.length, 300);
      expect(out.endsWith('…'), isTrue);
    });

    test('пустой текст не превращается в пустой диалог', () {
      expect(humanError(AnyhowException('\n\nStack backtrace:\n   0: x')), 'Неизвестная ошибка');
    });

    test('обычное Dart-исключение проходит как есть', () {
      expect(humanError(const FormatException('кривой ввод')),
          'FormatException: кривой ввод');
    });
  });
}

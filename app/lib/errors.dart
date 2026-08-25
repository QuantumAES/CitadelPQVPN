import 'package:flutter/material.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart'
    show AnyhowException, PanicException;

import 'package:app/l10n/strings.dart';

/// Технические хвосты, которых человеку в сообщении об отказе видеть не нужно. Текст режется по
/// ПЕРВОМУ встреченному маркеру — всё, что дальше, уходит только в журнал отладки.
///
/// Порядок в списке не важен (ищем самый ранний индекс), важен состав:
///   * `Caused by:`      — цепочка причин `anyhow` (`Debug`-вид);
///   * `Stack backtrace:` — блок кадров, который `anyhow` дописывает при захваченном backtrace.
///     Он появлялся, потому что шаблонный `setup_default_user_utils()` ставил процессу
///     `RUST_BACKTRACE=1` (убрано в `api::simple::init_app`); маркер оставляем как страховку —
///     backtrace может включить и окружение, а UI обязан оставаться чистым в любом случае;
///   * `stack backtrace:` — тот же блок до капитализации (зависит от версии backtrace-rs);
///   * `Backtrace [` / `<disabled>` — `Debug` у `std::backtrace::Backtrace`: FRB приклеивает его
///     к тексту `PanicException` без разделителя.
const _cutMarkers = <String>[
  '\nCaused by:',
  '\nStack backtrace:',
  '\nstack backtrace:',
  'Backtrace [',
  '<disabled>',
];

/// Предел длины сообщения в диалоге: паника ядра или отказ ОС бывают длиной в абзац, а диалог
/// должен остаться читаемым.
const _limit = 300;

/// Ошибка ядра → фраза для человека.
///
/// Через FRB ошибка приезжает как `AnyhowException` (паника — как `PanicException`), внутри —
/// `Debug`-вид `anyhow`: верхняя строка (её ядро формулирует по-человечески), а следом служебные
/// блоки. Диалогу нужна ровно верхняя строка: остальное не помещается в поле, обрывается
/// многоточием и пугает пользователя — а его место в журнале отладки, куда ядро его и пишет.
///
/// Многострочность СОХРАНЯЕМ: ядро намеренно переносит на вторую строку путь к файлу («Нет доступа
/// к папке хранилища:\nC:\…»), и склеивать это в одну строку значит снова получить обрезанный текст.
///
/// Функция — ЕДИНСТВЕННЫЙ путь текста ошибки на экран: любой `catch (e)`, показывающий что-то
/// пользователю, обязан идти через неё, а не через `'$e'` (тот ещё и обернёт всё в
/// `AnyhowException(...)`).
/// `t` (строки текущего языка) нужен только для случая «текста нет вовсе»: сами сообщения приходят
/// из ядра и переводу здесь не подлежат — оно формулирует их само (пока по-русски).
String humanError(Object e, [Strings? t]) {
  var head = _rawMessage(e);
  for (final marker in _cutMarkers) {
    final i = head.indexOf(marker);
    if (i >= 0) head = head.substring(0, i);
  }
  head = head.trim();
  if (head.isEmpty) return t?.call('unknown_error') ?? 'Неизвестная ошибка';
  return head.length > _limit ? '${head.substring(0, _limit - 1)}…' : head;
}

/// Развернуть обёртку FFI: у `AnyhowException`/`PanicException` берём само сообщение, иначе —
/// `toString()`. Без этого `'$e'` дал бы человеку `AnyhowException(Неверный мастер-пароль)`.
String _rawMessage(Object e) => switch (e) {
      AnyhowException(:final message) => message,
      PanicException(:final message) => message,
      _ => e.toString(),
    };

/// Блок с сообщением об отказе (диалоги пароля, экран разблокировки).
///
/// Отдельным виджетом, а не через `errorText` поля ввода: тот однострочный и в окне шириной 400 px
/// обрезал сообщение на первых словах — то самое «не видно сообщение об ошибке полностью».
/// Здесь текст переносится, при длинном — скроллится, и его можно выделить/скопировать.
class ErrorNote extends StatelessWidget {
  const ErrorNote({super.key, required this.text});
  final String text;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: cs.errorContainer,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, size: 18, color: cs.onErrorContainer),
          const SizedBox(width: 8),
          Expanded(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxHeight: 120),
              child: SingleChildScrollView(
                child: SelectableText(
                  text,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: cs.onErrorContainer),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

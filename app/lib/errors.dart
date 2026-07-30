import 'package:flutter/material.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart' show AnyhowException;

/// Ошибка ядра → фраза для человека.
///
/// Через FRB ошибка приезжает как `AnyhowException`, внутри — `Debug`-вид `anyhow`: верхняя строка
/// (её ядро формулирует по-человечески), а следом «Caused by:» с технической цепочкой. Диалогу
/// нужна ровно верхняя строка: цепочка не помещается в поле, обрывается многоточием и пугает
/// пользователя — а её место в журнале отладки, куда ядро её и пишет.
///
/// Многострочность СОХРАНЯЕМ: ядро намеренно переносит на вторую строку путь к файлу («Нет доступа
/// к папке хранилища:\nC:\…»), и склеивать это в одну строку значит снова получить обрезанный текст.
String humanError(Object e) {
  final raw = e is AnyhowException ? e.message : e.toString();
  final head = raw.split('\nCaused by:').first.trim();
  if (head.isEmpty) return 'Неизвестная ошибка';
  // Страховка от совсем длинного текста (например, паника ядра): диалог должен остаться читаемым.
  const limit = 300;
  return head.length > limit ? '${head.substring(0, limit - 1)}…' : head;
}

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

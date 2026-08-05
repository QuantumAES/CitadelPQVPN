import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:app/l10n/lang_ru.dart';
import 'package:app/l10n/strings.dart';

/// Локализация без кодогенерации держится на двух инвариантах, и оба проверяются здесь, а не
/// глазами на девяти языках:
///   1. набор ключей во всех языках совпадает с русским эталоном (иначе на чужом языке молча
///      вылезет русская строка — или, хуже, сам ключ);
///   2. каждый ключ, который интерфейс СПРАШИВАЕТ (`t('…')`), в эталоне есть — опечатка в ключе
///      иначе доходит до экрана как `some_key` вместо текста.
void main() {
  test('во всех языках один и тот же набор ключей', () {
    final expected = langRu.keys.toSet();
    for (final entry in kLangs.entries) {
      final actual = entry.value.keys.toSet();
      expect(actual.difference(expected), isEmpty,
          reason: 'язык ${entry.key}: лишние ключи (нет в русском эталоне)');
      expect(expected.difference(actual), isEmpty,
          reason: 'язык ${entry.key}: не переведены ключи');
    }
  });

  test('плейсхолдеры {…} сохранены во всех переводах', () {
    final re = RegExp(r'\{(\w+)\}');
    for (final key in langRu.keys) {
      final want = re.allMatches(langRu[key]!).map((m) => m.group(1)!).toSet();
      for (final entry in kLangs.entries) {
        final got = re.allMatches(entry.value[key]!).map((m) => m.group(1)!).toSet();
        expect(got, want,
            reason: 'язык ${entry.key}, ключ $key: подстановки должны совпадать с эталоном');
      }
    }
  });

  test('каждый язык объявлен в списке локалей и имеет название', () {
    final codes = kSupportedLocales.map((l) => l.languageCode).toSet();
    expect(codes, kLangs.keys.toSet(), reason: 'supportedLocales должен совпадать с набором языков');
    for (final code in kLangs.keys) {
      expect(kLangNames[code], isNotNull, reason: 'нет названия языка для $code');
    }
    expect(kLangs.containsKey(kDefaultLang), isTrue);
  });

  test('все ключи, запрошенные интерфейсом, есть в эталоне', () {
    // Ищем обращения вида t('key') / Strings.of(ctx)('key') в исходниках приложения.
    final re = RegExp(r"""(?:\bt|\)\s*)\(\s*'([a-z0-9_]+)'""");
    final used = <String, String>{}; // ключ → где встретился
    for (final f in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart') || f.path.contains('/l10n/') || f.path.contains('/src/rust/')) {
        continue;
      }
      for (final m in re.allMatches(f.readAsStringSync())) {
        used[m.group(1)!] = f.path;
      }
    }
    expect(used, isNotEmpty, reason: 'парсер обращений к строкам ничего не нашёл — проверь regexp');
    final missing = {
      for (final e in used.entries)
        if (!langRu.containsKey(e.key)) e.key: e.value,
    };
    expect(missing, isEmpty, reason: 'нет таких ключей в русском эталоне: $missing');
  });

  test('неизвестный язык и пропущенный ключ откатываются к русскому', () {
    final t = Strings.forCode('xx');
    expect(t.code, kDefaultLang);
    expect(t('cancel'), langRu['cancel']);
    // ключа нет нигде — возвращаем сам ключ (заметно в интерфейсе, но экран не падает)
    expect(t('нет_такого_ключа'), 'нет_такого_ключа');
  });

  test('подстановка плейсхолдеров', () {
    final t = Strings.forCode('en');
    expect(t('password_min', {'n': '12'}), contains('12'));
    expect(t('switch_body', {'current': 'A', 'name': 'B'}), allOf(contains('A'), contains('B')));
  });
}

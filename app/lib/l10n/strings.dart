/// Локализация интерфейса CitadelPQVPN.
///
/// Устройство намеренно простое: язык = плоская карта `ключ → строка` (по файлу на язык), русский
/// — эталон набора ключей и запасной вариант для пропусков. Кодогенерации (ARB/gen_l10n) здесь нет
/// сознательно: сборка клиента и так проходит через FRB-codegen, добавлять второй генератор в
/// релизный конвейер ради 200 строк — плата больше выгоды, а полноту набора ключей дешевле
/// проверить тестом (`app/test/l10n_test.dart`), чем генератором.
///
/// Две двери к строкам:
///   * [Strings.of] — из виджетов (через `Localizations`, перестраивается при смене языка);
///   * [Strings.forCode] — из кода без `BuildContext` под `MaterialApp` (системный трей).
library;

import 'package:flutter/foundation.dart' show SynchronousFuture;
import 'package:flutter/widgets.dart';

import 'package:app/l10n/lang_cs.dart';
import 'package:app/l10n/lang_de.dart';
import 'package:app/l10n/lang_en.dart';
import 'package:app/l10n/lang_es.dart';
import 'package:app/l10n/lang_fr.dart';
import 'package:app/l10n/lang_hi.dart';
import 'package:app/l10n/lang_it.dart';
import 'package:app/l10n/lang_my.dart';
import 'package:app/l10n/lang_ru.dart';

/// Язык по умолчанию: русский (см. `language()` в ядре — оно хранит выбор пользователя).
const String kDefaultLang = 'ru';

/// Все языки интерфейса: код → карта строк.
const Map<String, Map<String, String>> kLangs = {
  'ru': langRu,
  'en': langEn,
  'de': langDe,
  'fr': langFr,
  'es': langEs,
  'it': langIt,
  'cs': langCs,
  'hi': langHi,
  'my': langMy,
};

/// Названия языков — на самих языках: список выбора должен читаться тем, кто ищет свой язык,
/// а не тем, кто уже понимает текущий.
const Map<String, String> kLangNames = {
  'ru': 'Русский',
  'en': 'English',
  'de': 'Deutsch',
  'fr': 'Français',
  'es': 'Español',
  'it': 'Italiano',
  'cs': 'Čeština',
  'hi': 'हिन्दी',
  'my': 'မြန်မာ',
};

/// Локали для `MaterialApp.supportedLocales` (порядок = порядок в списке выбора).
const List<Locale> kSupportedLocales = [
  Locale('ru'),
  Locale('en'),
  Locale('de'),
  Locale('fr'),
  Locale('es'),
  Locale('it'),
  Locale('cs'),
  Locale('hi'),
  Locale('my'),
];

/// Набор строк одного языка. Обращение — вызовом: `t('cancel')`, `t('password_min', {'n': '12'})`.
class Strings {
  const Strings(this.code, this._map);

  /// Код языка (`ru`, `en`, …) — например, чтобы отметить текущий пункт в списке выбора.
  final String code;
  final Map<String, String> _map;

  /// Строки указанного языка; неизвестный код — русский (а не пустой интерфейс).
  factory Strings.forCode(String code) =>
      Strings(kLangs.containsKey(code) ? code : kDefaultLang,
          kLangs[code] ?? langRu);

  /// Строки текущего языка приложения. Вне `MaterialApp` (нет `Localizations`) — русские.
  static Strings of(BuildContext context) =>
      Localizations.of<Strings>(context, Strings) ?? const Strings(kDefaultLang, langRu);

  /// Строка по ключу с подстановкой плейсхолдеров `{имя}`.
  ///
  /// Пропущенный в языке ключ берём из русского эталона, а если ключа нет и там — возвращаем сам
  /// ключ. Это заметно в интерфейсе и ловится тестами, но не роняет экран из-за одной строки.
  String call(String key, [Map<String, String>? args]) {
    var s = _map[key] ?? langRu[key] ?? key;
    if (args != null) {
      args.forEach((k, v) => s = s.replaceAll('{$k}', v));
    }
    return s;
  }
}

/// Делегат `Localizations` для [Strings]. Загрузка синхронная (карты — константы в бинаре),
/// поэтому смена языка перерисовывает интерфейс без кадра «пустого экрана».
class StringsDelegate extends LocalizationsDelegate<Strings> {
  const StringsDelegate();

  @override
  bool isSupported(Locale locale) => kLangs.containsKey(locale.languageCode);

  @override
  Future<Strings> load(Locale locale) =>
      SynchronousFuture<Strings>(Strings.forCode(locale.languageCode));

  @override
  bool shouldReload(StringsDelegate old) => false;
}

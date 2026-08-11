/// M-9: сверка кода ссылки — чистые правила сравнения (тестируются отдельно от UI).
///
/// Код администратор называет ГОЛОСОМ и по ДРУГОМУ каналу, а абонент записывает его как придётся:
/// строчными, с пробелом посередине, с дефисом. Значение имеют только сами символы, поэтому
/// сравниваем нормализованные формы. Алфавит — Crockford Base32 (см. `CredentialLink::verify_code`):
/// в нём нет ни `I`, ни `O`, ни `U`, поэтому классические ошибки распознавания на слух («ноль или
/// буква О») лечатся заменой, а не переспрашиванием.
String normalizeVerifyCode(String s) {
  final up = s.toUpperCase();
  final buf = StringBuffer();
  for (final ch in up.split('')) {
    switch (ch) {
      case 'O': // «о» на слух — это ноль (в алфавите буквы O нет)
        buf.write('0');
      case 'I':
      case 'L': // «и»/«эл» — это единица
        buf.write('1');
      default:
        if (RegExp(r'[0-9A-Z]').hasMatch(ch)) buf.write(ch);
    }
  }
  return buf.toString();
}

/// Совпал ли введённый человеком код с кодом самой ссылки. Пустой ввод — не совпадение
/// («ещё не ввели» отличается от «сошлось» на стороне вызывающего).
bool verifyCodeMatches(String entered, String expected) {
  final a = normalizeVerifyCode(entered);
  final b = normalizeVerifyCode(expected);
  return a.isNotEmpty && a == b;
}

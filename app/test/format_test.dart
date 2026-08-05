import 'package:flutter_test/flutter_test.dart';

import 'package:app/format.dart';
import 'package:app/l10n/strings.dart';

/// Индикация трафика показывает СКОРОСТЬ, и вся её читаемость держится на форматировании: строка
/// обновляется раз в секунду, поэтому не должна прыгать шириной, а разделитель дробной части
/// обязан быть тем, который принят в языке интерфейса.
void main() {
  final ru = Strings.forCode('ru');
  final en = Strings.forCode('en');

  test('масштаб единиц: байты → КБ → МБ', () {
    expect(fmtRate(0, ru), '0 Б/с');
    expect(fmtRate(512, ru), '512 Б/с');
    expect(fmtRate(1023, ru), '1023 Б/с');
    expect(fmtRate(1024, ru), '1,0 КБ/с');
    expect(fmtRate(18 * 1024, ru), '18 КБ/с');
    expect(fmtRate(1024 * 1024 * 1.5, ru), '1,5 МБ/с');
  });

  test('десятичный разделитель — из языка', () {
    expect(fmtRate(1024, en), '1.0 KB/s');
    expect(fmtRate(18 * 1024, en), '18 KB/s');
  });

  test('мусорные значения показываем нулём, а не «NaN»', () {
    expect(fmtRate(double.nan, ru), '0 Б/с');
    expect(fmtRate(double.infinity, ru), '0 Б/с');
    expect(fmtRate(-5, ru), '0 Б/с');
  });

  test('узел выхода показывается без порта', () {
    expect(hostOnly('203.0.113.10:4433'), '203.0.113.10');
    expect(hostOnly('[2001:db8::1]:4433'), '2001:db8::1');
    expect(hostsOnly('a.example:443, b.example:8443'), 'a.example, b.example');
  });
}

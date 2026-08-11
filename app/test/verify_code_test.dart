import 'package:flutter_test/flutter_test.dart';

import 'package:app/verify_code.dart';

/// M-9: код сверки абонент вводит СО СЛУХА — правила сравнения обязаны это учитывать, иначе
/// единственная проверка, которая ловит подмену ссылки при доставке, будет отвергать честных
/// людей за пробел или строчную букву, и её начнут пропускать.
void main() {
  test('регистр, пробелы и дефисы значения не имеют', () {
    expect(verifyCodeMatches('a1b2c3', 'A1B2C3'), isTrue);
    expect(verifyCodeMatches(' a1b2-c3 ', 'A1B2C3'), isTrue);
    expect(verifyCodeMatches('A1B2 C3', 'A1B2C3'), isTrue);
  });

  test('омоглифы алфавита Crockford: O→0, I/L→1', () {
    expect(verifyCodeMatches('O1B2C3', '01B2C3'), isTrue);
    expect(verifyCodeMatches('i1B2C3', '11B2C3'), isTrue);
    expect(verifyCodeMatches('L1B2C3', '11B2C3'), isTrue);
  });

  test('другой код не проходит (иначе проверка бессмысленна)', () {
    expect(verifyCodeMatches('A1B2C4', 'A1B2C3'), isFalse);
    expect(verifyCodeMatches('A1B2C', 'A1B2C3'), isFalse);
    expect(verifyCodeMatches('A1B2C33', 'A1B2C3'), isFalse);
  });

  test('пустой ввод — не совпадение (это «ещё не ввели», а не «сошлось»)', () {
    expect(verifyCodeMatches('', 'A1B2C3'), isFalse);
    expect(verifyCodeMatches('   ', 'A1B2C3'), isFalse);
    expect(verifyCodeMatches('', ''), isFalse);
    // и наоборот: непустой ввод против пустого ожидания не должен «совпасть»
    expect(verifyCodeMatches('A1B2C3', ''), isFalse);
  });
}

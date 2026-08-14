import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:app/biometric.dart';

/// C9: ответ канала `citadel/biometric` — НЕИЗМЕНЯЕМОЕ окно в буфер движка
/// (`platform_dispatcher.dart`, `_wrapUnmodifiableByteData`), а не обычный список. Затирание такого
/// буфера бросает `Unsupported operation: Cannot modify an unmodifiable list`, и падало это уже
/// после успешной разблокировки: ядро открывало хранилище, а человек видел на экране входа
/// системную ошибку и решал, что отпечаток не работает.
///
/// Мок повторяет транспорт дословно (`asUnmodifiableView` поверх закодированного конверта) — иначе
/// тест проверял бы не то, что происходит на устройстве: обычный `setMockMethodCallHandler` отдаёт
/// как раз изменяемый буфер и регрессию не ловит.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const ch = MethodChannel('citadel/biometric');
  const codec = StandardMethodCodec();
  const texts = BiometricTexts(title: 'CitadelPQVPN', subtitle: 'Отпечаток', cancel: 'Отмена');
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  /// Ключ, который «вернул Keystore»: важна не длина, а происхождение буфера.
  final secret = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

  /// Ответ канала ровно в том виде, в каком его отдаёт движок.
  void answerWith(Uint8List bytes, {required bool unmodifiable}) {
    messenger.setMockMessageHandler(ch.name, (ByteData? message) async {
      final envelope = codec.encodeSuccessEnvelope(bytes);
      return unmodifiable ? envelope.asUnmodifiableView() : envelope;
    });
  }

  tearDown(() => messenger.setMockMessageHandler(ch.name, null));

  test('ответ канала неизменяем — наверх уходит копия, которую можно затереть', () async {
    answerWith(secret, unmodifiable: true);

    final key = await BiometricUnlock.unwrap(Uint8List(44), texts);
    expect(key, secret, reason: 'байты обязаны доехать без искажений');

    BiometricUnlock.zeroize(key);
    expect(key.every((b) => b == 0), isTrue, reason: 'копия обязана затираться по-настоящему');
  });

  test('обёртка при включении отпечатка возвращает такую же затираемую копию', () async {
    answerWith(secret, unmodifiable: true);

    final wrapped = await BiometricUnlock.wrap(Uint8List(32), texts);
    BiometricUnlock.zeroize(wrapped);
    expect(wrapped.every((b) => b == 0), isTrue);
  });

  test('изменяемый ответ обрабатывается так же', () async {
    answerWith(secret, unmodifiable: false);

    final key = await BiometricUnlock.unwrap(Uint8List(44), texts);
    expect(key, secret);
    BiometricUnlock.zeroize(key);
    expect(key.every((b) => b == 0), isTrue);
  });

  test('пустой ответ платформы — отказ, а не пустой ключ', () async {
    answerWith(Uint8List(0), unmodifiable: true);

    await expectLater(
      BiometricUnlock.unwrap(Uint8List(44), texts),
      throwsA(isA<BiometricFailure>().having((e) => e.code, 'code', 'empty')),
    );
  });

  test('затирание неизменяемого буфера не роняет вызывающего', () {
    // Вторая линия обороны: даже если такой буфер когда-нибудь снова доедет до [zeroize],
    // разблокировка не должна падать из-за неудавшейся уборки.
    final frozen = ByteData(32).asUnmodifiableView().buffer.asUint8List(0, 32);
    expect(() => BiometricUnlock.zeroize(frozen), returnsNormally);
  });
}

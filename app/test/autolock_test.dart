import 'package:flutter/widgets.dart' show AppLifecycleState;
import 'package:flutter_test/flutter_test.dart';

import 'package:app/autolock.dart';

/// N-2: автозамок хранилища. Проверяется здесь, а не руками на телефоне, потому что ошибиться тут
/// можно в обе стороны, и обе дорогие: не сработает — открытое хранилище (а в нём мастер-ссылка,
/// то есть admin-плоскость) переживёт уход в фон; сработает лишний раз — человек получит замок
/// посреди работы и первым делом его выключит.
///
/// Время в тестах — управляемое: часы подменяются (`clock`), а таймауты берутся короткие
/// (десятки миллисекунд), поэтому ни один тест не ждёт настоящих минут.
void main() {
  /// Управляемые часы: тест сам решает, сколько «прошло».
  DateTime now = DateTime(2026, 8, 14, 12);
  DateTime clock() => now;

  setUp(() => now = DateTime(2026, 8, 14, 12));

  test('выключенный автозамок не запирает ничего и не держит таймер', () async {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(Duration.zero);

    expect(lock.running, isFalse, reason: 'выключенный автозамок не должен будить процесс');

    now = now.add(const Duration(hours: 3));
    lock.onLifecycle(AppLifecycleState.paused);
    lock.onLifecycle(AppLifecycleState.resumed);

    expect(locks, 0, reason: '0 минут = выключено, и это единственное значение, которое выключает');
    lock.dispose();
  });

  test('простой дольше таймаута запирает хранилище', () async {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(const Duration(milliseconds: 40));

    expect(lock.running, isTrue);
    await Future<void>.delayed(const Duration(milliseconds: 120));

    expect(locks, 1, reason: 'таймер простоя обязан сработать');
    expect(lock.running, isFalse, reason: 'после срабатывания таймер не перезаводится');
    lock.dispose();
  });

  test('касание сбрасывает отсчёт простоя', () async {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(const Duration(milliseconds: 60));

    for (var i = 0; i < 4; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
      lock.poke();
    }

    expect(locks, 0, reason: 'человек всё это время работал — замка быть не должно');
    await Future<void>.delayed(const Duration(milliseconds: 140));
    expect(locks, 1, reason: 'а вот когда перестал — замок');
    lock.dispose();
  });

  test('возврат из фона позже таймаута запирает сразу, раньше — нет', () {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(const Duration(minutes: 5));

    // Ушли в фон и вернулись через четыре минуты — это ещё «работаю».
    lock.onLifecycle(AppLifecycleState.paused);
    now = now.add(const Duration(minutes: 4));
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(locks, 0);

    // Ушли снова и вернулись через шесть — замок обязан быть уже на возврате, не по таймеру:
    // в замороженном системой процессе таймер мог не сработать вовсе.
    lock.onLifecycle(AppLifecycleState.paused);
    now = now.add(const Duration(minutes: 6));
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(locks, 1, reason: 'вернулись позже таймаута — хранилище должно быть уже заперто');
    lock.dispose();
  });

  test('погашенный экран считается уходом, потеря фокуса — нет', () {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(const Duration(minutes: 1));

    // `inactive` приходит на любой системный диалог поверх окна — включая наш же запрос
    // разрешения VPN и подсказку отпечатка. Считать это уходом нельзя.
    lock.onLifecycle(AppLifecycleState.inactive);
    now = now.add(const Duration(minutes: 10));
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(locks, 0, reason: 'системный диалог поверх окна — не уход из приложения');

    lock.onLifecycle(AppLifecycleState.hidden);
    now = now.add(const Duration(minutes: 10));
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(locks, 1, reason: 'погашенный экран/сворачивание — уход');
    lock.dispose();
  });

  test('на запертом хранилище автозамок молчит', () async {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(const Duration(milliseconds: 30));

    // Человек запер сам — таймер обязан сняться, иначе «замок поверх замка» дёргал бы UI.
    lock.setUnlocked(false);
    expect(lock.running, isFalse);
    await Future<void>.delayed(const Duration(milliseconds: 90));
    expect(locks, 0);

    // И повторный уход в фон на запертом хранилище тоже ничего не зовёт.
    lock.onLifecycle(AppLifecycleState.paused);
    now = now.add(const Duration(hours: 1));
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(locks, 0);
    lock.dispose();
  });

  test('смена настройки перезапускает отсчёт, а не продолжает старый', () async {
    var locks = 0;
    final lock = AutoLock(onLock: () => locks++, clock: clock)
      ..setUnlocked(true)
      ..configure(const Duration(milliseconds: 40));

    await Future<void>.delayed(const Duration(milliseconds: 25));
    lock.configure(const Duration(milliseconds: 60)); // человек только что был в настройках
    await Future<void>.delayed(const Duration(milliseconds: 40));
    expect(locks, 0, reason: 'новый таймаут отсчитывается с нуля');

    await Future<void>.delayed(const Duration(milliseconds: 60));
    expect(locks, 1);
    lock.dispose();
  });
}

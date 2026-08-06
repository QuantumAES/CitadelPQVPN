import 'package:flutter_test/flutter_test.dart';

import 'package:app/traffic.dart';

/// Расчёт скорости живёт отдельно от экранов (`lib/traffic.dart`), потому что плашка подключения
/// есть и на главном экране, и на экране разблокировки. Здесь проверяются ровно те случаи, из-за
/// которых индикация врала бы: отстающий таймер, разрыв ряда и перезапуск счётчиков.
void main() {
  final t0 = DateTime(2026, 1, 1, 12);

  test('до второго снимка скорости нет', () {
    final s = TrafficSampler();
    s.sample(1000, 2000, t0);
    expect(s.rxRate, 0);
    expect(s.txRate, 0);
  });

  test('скорость = дельта / фактически прошедшее время, а не «за секунду»', () {
    final s = TrafficSampler();
    s.sample(0, 0, t0);
    // Тик пришёл через 2 секунды (таймер отставал) — делить надо на 2, иначе скорость вдвое завышена.
    s.sample(2048, 1024, t0.add(const Duration(seconds: 2)));
    expect(s.rxRate, 1024);
    expect(s.txRate, 512);
  });

  test('перезапуск движка (счётчики с нуля) — ноль, а не отрицательная скорость', () {
    final s = TrafficSampler();
    s.sample(1000000, 1000000, t0);
    s.sample(0, 0, t0.add(const Duration(seconds: 1)));
    expect(s.rxRate, 0);
    expect(s.txRate, 0);
  });

  test('длинная пауза — новая точка отсчёта, а не «медленная секунда»', () {
    final s = TrafficSampler();
    s.sample(0, 0, t0);
    s.sample(1024, 1024, t0.add(const Duration(seconds: 1)));
    expect(s.rxRate, 1024);

    // Окно было свёрнуто на минуту: дельту за неё показывать как текущую скорость нельзя.
    s.sample(1024 * 1000, 1024 * 1000, t0.add(const Duration(seconds: 61)));
    expect(s.rxRate, 1024, reason: 'прежнее значение, пересчёта по разорванному ряду быть не должно');

    // Следующий обычный тик считается уже от новой точки.
    s.sample(1024 * 1000 + 512, 1024 * 1000 + 256, t0.add(const Duration(seconds: 62)));
    expect(s.rxRate, 512);
    expect(s.txRate, 256);
  });

  test('reset забывает историю — следующий снимок снова первый', () {
    final s = TrafficSampler();
    s.sample(0, 0, t0);
    s.sample(1024, 1024, t0.add(const Duration(seconds: 1)));
    expect(s.rxRate, 1024);

    s.reset();
    expect(s.rxRate, 0);
    expect(s.txRate, 0);
    s.sample(1024 * 100, 1024 * 100, t0.add(const Duration(seconds: 2)));
    expect(s.rxRate, 0, reason: 'после reset дельту считать не от чего');
  });
}

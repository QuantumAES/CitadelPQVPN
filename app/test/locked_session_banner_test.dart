import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:app/locked_session_banner.dart';

/// Экран разблокировки закрывает собой всё приложение, поэтому при живом туннеле он обязан
/// показать сессию и дать её отключить. Замок хранилища сессию НЕ рвёт (это проверяется в ядре,
/// `app/rust`: `vault_lock_does_not_touch_session`) — здесь проверяется вторая половина того же
/// требования: заблокированное хранилище не делает работающий VPN невидимым и неуправляемым.
void main() {
  Future<void> pump(WidgetTester t, Widget w) =>
      t.pumpWidget(MaterialApp(home: Scaffold(body: w)));

  testWidgets('поднятый туннель виден на экране разблокировки', (t) async {
    await pump(
      t,
      LockedSessionBanner(
        busy: true,
        up: true,
        exit: '203.0.113.10:4433',
        onDisconnect: () {},
      ),
    );

    expect(find.text('Туннель активен'), findsOneWidget);
    // Порт узла выхода в интерфейсе не показываем (как и на главном экране).
    expect(find.text('203.0.113.10'), findsOneWidget);
    expect(find.text('Отключить'), findsOneWidget);
  });

  testWidgets('состав плашки тот же, что на главном экране: узел · транспорт + скорость',
      (t) async {
    await pump(
      t,
      LockedSessionBanner(
        busy: true,
        up: true,
        exit: '203.0.113.10:4433',
        transport: 'QUIC/UDP',
        trafficMeter: true,
        rxRate: 1536, // 1,5 КБ/с
        txRate: 512,
        onDisconnect: () {},
      ),
    );

    // Узел и транспорт — одной строкой по центру (порт по-прежнему скрыт).
    final details = t.widget<Text>(find.text('203.0.113.10  ·  QUIC/UDP'));
    expect(details.textAlign, TextAlign.center);
    // Скорость приёма/передачи — как на главном экране.
    expect(find.text('1,5 КБ/с'), findsOneWidget);
    expect(find.text('512 Б/с'), findsOneWidget);
  });

  testWidgets('индикация трафика выключена — строки скорости нет', (t) async {
    await pump(
      t,
      LockedSessionBanner(
        busy: true,
        up: true,
        exit: '203.0.113.10:4433',
        transport: 'QUIC/UDP',
        rxRate: 1536,
        txRate: 512,
        onDisconnect: () {},
      ),
    );

    expect(find.text('1,5 КБ/с'), findsNothing);
    expect(find.text('203.0.113.10  ·  QUIC/UDP'), findsOneWidget);
  });

  testWidgets('на подключении скорости нет (цифры были бы нулями)', (t) async {
    await pump(
      t,
      LockedSessionBanner(
        busy: true,
        up: false,
        exit: '203.0.113.10:4433',
        transport: 'QUIC/UDP',
        trafficMeter: true,
        onDisconnect: () {},
      ),
    );

    expect(find.text('0 Б/с'), findsNothing);
  });

  testWidgets('идущее подключение показано как «Подключение…»', (t) async {
    await pump(
      t,
      LockedSessionBanner(busy: true, up: false, exit: '', onDisconnect: () {}),
    );

    expect(find.text('Подключение…'), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
  });

  testWidgets('без сессии плашки нет (обычная разблокировка)', (t) async {
    await pump(
      t,
      LockedSessionBanner(busy: false, up: false, exit: '', onDisconnect: () {}),
    );

    expect(find.text('Туннель активен'), findsNothing);
    expect(find.text('Отключить'), findsNothing);
  });

  testWidgets('«Отключить» — единственная кнопка, гасящая сессию с этого экрана', (t) async {
    var stopped = 0;
    await pump(
      t,
      LockedSessionBanner(
        busy: true,
        up: true,
        exit: '203.0.113.10:4433',
        onDisconnect: () => stopped++,
      ),
    );

    await t.tap(find.text('Отключить'));
    await t.pump();

    expect(stopped, 1);
  });
}

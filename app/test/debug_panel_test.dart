import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:app/debug_panel.dart';

/// Панель журнала висит на главном экране всё время, пока включён режим отладки, — то есть её
/// стоимость платится постоянно, независимо от того, поднят туннель или нет.
///
/// Автоскролл к последней строке когда-то планировался прямо из `build`: кадр → post-frame
/// `jumpTo` → `jumpTo` планирует следующий кадр → снова `build`. Приложение рисовало кадры без
/// остановки (на живой машине это давало десятки процентов CPU при ВЫКЛЮЧЕННОМ туннеле), и тем
/// дороже, чем длиннее журнал.
///
/// `pumpAndSettle` — точный детектор именно этого: он крутит кадры, пока их планируют, и падает
/// по таймауту, если поток кадров не прекращается. Поэтому тест ловит регрессию как таковую, а не
/// её косвенные следы. Таймаут задан явно и коротким: дефолтные 10 минут превратили бы упавший
/// тест в подвисший прогон.
void main() {
  Future<void> settle(WidgetTester t) => t.pumpAndSettle(
        const Duration(milliseconds: 100),
        EnginePhase.sendSemanticsUpdate,
        const Duration(seconds: 5),
      );

  Future<void> pump(WidgetTester t, List<String> lines) => t.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: MonoLogView(
              title: 'журнал',
              icon: Icons.terminal,
              lines: lines,
            ),
          ),
        ),
      );

  testWidgets('журнал не планирует кадры бесконечно', (t) async {
    await pump(t, List.generate(300, (i) => 'строка $i'));
    // Не зависает: поток кадров прекращается сам.
    await settle(t);
    expect(find.byType(MonoLogView), findsOneWidget);
  });

  testWidgets('новые строки успокаиваются, а не запускают вечную перерисовку', (t) async {
    final lines = <String>[for (var i = 0; i < 50; i++) 'строка $i'];
    await pump(t, lines);
    await settle(t);

    // Так журнал и растёт: список мутируется на месте, виджет пересобирается родителем.
    for (var i = 0; i < 20; i++) {
      lines.add('новая строка $i');
      await pump(t, lines);
    }
    await settle(t);
    expect(find.byType(MonoLogView), findsOneWidget);
  });

  testWidgets('пустой журнал показывает подсказку и тоже успокаивается', (t) async {
    await pump(t, const []);
    await settle(t);
    expect(find.byType(MonoLogView), findsOneWidget);
  });
}

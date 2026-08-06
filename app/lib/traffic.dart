/// Индикация трафика: расчёт текущей скорости по счётчикам ядра и строка «↓ … ↑ …» под ней.
///
/// Живёт отдельным файлом, потому что плашка подключения есть на ДВУХ экранах — на главном и на
/// экране разблокировки хранилища (замок туннель не рвёт, см. `AppState.lockVault`). Пока расчёт
/// дельт лежал внутри `home_page.dart`, второй экран показать скорость не мог, а копия той же
/// арифметики разъехалась бы с оригиналом на первой же правке.
library;

import 'package:flutter/material.dart';

import 'package:app/format.dart';
import 'package:app/l10n/strings.dart';

/// Скорость приёма/передачи по дельте монотонных счётчиков ядра между двумя снимками.
///
/// Класс намеренно НЕ ходит в ядро сам (счётчики передаются аргументами [sample]): арифметика
/// остаётся проверяемой обычным unit-тестом без нативной библиотеки, а кто и как часто снимает
/// счётчики — дело экрана.
class TrafficSampler {
  /// Текущая скорость, байт/с. До второго снимка — нули.
  double rxRate = 0, txRate = 0;

  int? _rxPrev, _txPrev;
  DateTime? _at;

  /// Пауза между снимками, после которой ряд считается разорванным (окно было свёрнуто, сессия
  /// падала и поднималась): такой интервал — не «медленная секунда», а новая точка отсчёта.
  static const double _maxGapSec = 5;

  /// Забыть историю (индикацию выключили / сессия закончилась) — иначе следующий снимок посчитал бы
  /// скорость по дельте через произвольный промежуток времени.
  void reset() {
    _rxPrev = _txPrev = null;
    _at = null;
    rxRate = txRate = 0;
  }

  /// Снимок счётчиков (байты, монотонные в пределах запуска движка) на момент [now].
  ///
  /// Дельта делится на ФАКТИЧЕСКИ прошедшее время, а не на «одну секунду»: таймер в фоне и под
  /// нагрузкой отстаёт, и деление на константу завышало бы скорость. Отрицательная дельта (движок
  /// перезапущен, счётчики с нуля) → ноль, а не мусор.
  void sample(int rx, int tx, DateTime now) {
    final prevAt = _at, prevRx = _rxPrev, prevTx = _txPrev;
    _rxPrev = rx;
    _txPrev = tx;
    _at = now;
    if (prevAt == null || prevRx == null || prevTx == null) return;
    final dt = now.difference(prevAt).inMicroseconds / 1e6;
    if (dt <= 0 || dt >= _maxGapSec) return; // разрыв ряда — только новая точка отсчёта
    rxRate = ((rx - prevRx) / dt).clamp(0, double.maxFinite);
    txRate = ((tx - prevTx) / dt).clamp(0, double.maxFinite);
  }
}

/// Строка скорости на плашке подключения: «↓ 1,4 МБ/с   ↑ 320 КБ/с». Моноширинные цифры
/// (`tabularFigures`) — иначе строка дёргается по ширине на каждом обновлении раз в секунду.
class TrafficRow extends StatelessWidget {
  const TrafficRow({
    super.key,
    required this.rxRate,
    required this.txRate,
    required this.fg,
    required this.t,
  });

  final double rxRate, txRate;
  final Color fg;
  final Strings t;

  @override
  Widget build(BuildContext context) {
    final style = Theme.of(context).textTheme.bodyMedium?.copyWith(
          color: fg.withValues(alpha: 0.9),
          fontFeatures: const [FontFeature.tabularFigures()],
        );
    Widget item(IconData icon, String label, String value) => Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 16, color: fg.withValues(alpha: 0.9)),
            const SizedBox(width: 4),
            // Подпись для доступности (скринридер прочитает «приём»/«отправка», а не стрелку).
            Semantics(label: label, child: Text(value, style: style)),
          ],
        );
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        item(Icons.arrow_downward, t('traffic_rx'), fmtRate(rxRate, t)),
        const SizedBox(width: 20),
        item(Icons.arrow_upward, t('traffic_tx'), fmtRate(txRate, t)),
      ],
    );
  }
}

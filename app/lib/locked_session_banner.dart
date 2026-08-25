import 'package:flutter/material.dart';

import 'package:app/format.dart';
import 'package:app/l10n/strings.dart';
import 'package:app/traffic.dart';

/// Плашка живой сессии на экране разблокировки хранилища.
///
/// Блокировка хранилища и закрытие окна туннель не останавливают: сессию держит движок, а на
/// Android — ещё и foreground-сервис, переживающий Activity. Но экран пароля закрывает собой всё
/// остальное, и без этой плашки работающий VPN оказывался невидимым и неуправляемым — со стороны
/// это выглядело ровно как «туннель отвалился». Показываем состояние и даём отключить, не требуя
/// сперва ввести мастер-пароль: отключение сессии секретов не касается.
///
/// Состав плашки — тот же, что у плашки на главном экране (`_StatusCard` в `home_page.dart`):
/// строка «узел · транспорт» по центру и, если индикация трафика включена, текущая скорость.
/// Замок хранилища прячет профили, а не состояние туннеля: два вида одной и той же сессии
/// расходиться не должны.
///
/// Виджет намеренно не знает про `AppState`: принимает снимок состояния значениями, поэтому
/// проверяется обычным widget-тестом без нативного ядра (см. `app/test/locked_session_banner_test.dart`).
class LockedSessionBanner extends StatelessWidget {
  const LockedSessionBanner({
    super.key,
    required this.busy,
    required this.up,
    required this.exit,
    required this.onDisconnect,
    this.transport = '',
    this.trafficMeter = false,
    this.rxRate = 0,
    this.txRate = 0,
  });

  /// Есть ли сессия, о которой стоит говорить (подключение или поднятый туннель).
  final bool busy;

  /// Туннель поднят (иначе — идёт подключение).
  final bool up;

  /// Узел выхода как его знает движок (`host:port`); пусто — ещё не выбран.
  final String exit;

  /// Транспорт сессии («QUIC/UDP» / «obfs-TCP»); пусто — ещё не установлена.
  final String transport;

  /// Показывать ли скорость (настройка «Индикация трафика», по умолчанию выключена).
  final bool trafficMeter;

  /// Текущая скорость приёма/передачи, байт/с (см. [TrafficSampler]).
  final double rxRate, txRate;

  /// Отключить сессию (замок хранилища этого НЕ делает — только явное действие человека).
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    if (!busy) return const SizedBox.shrink();
    final t = Strings.of(context);
    final dark = Theme.of(context).brightness == Brightness.dark;
    final bg = up
        ? (dark ? Colors.green.shade900 : Colors.green.shade50)
        : (dark ? Colors.amber.shade900 : Colors.amber.shade50);
    final fg = up
        ? (dark ? Colors.green.shade200 : Colors.green.shade800)
        : (dark ? Colors.amber.shade200 : Colors.amber.shade900);
    // Узел выхода — без порта, как и на главном экране (см. format.dart).
    final details = <String>[
      if (exit.isNotEmpty) hostOnly(exit),
      if (transport.isNotEmpty) transport,
    ].join('  ·  ');

    return Container(
      margin: const EdgeInsets.only(top: 20),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(16)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              if (up)
                Icon(Icons.shield, color: fg, size: 22)
              else
                SizedBox(
                  height: 20,
                  width: 20,
                  child: CircularProgressIndicator(strokeWidth: 2.2, color: fg),
                ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  up ? t('tunnel_active') : t('status_connecting'),
                  style: Theme.of(context)
                      .textTheme
                      .titleSmall
                      ?.copyWith(color: fg, fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
          if (details.isNotEmpty) ...[
            const SizedBox(height: 4),
            // По центру и тем же кеглем, что на главном экране: строка «узел · транспорт»
            // относится ко всей плашке, а не к иконке слева, и не должна оказаться мельче строки
            // скорости под ней.
            Text(details,
                textAlign: TextAlign.center,
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: fg.withValues(alpha: 0.9))),
          ],
          // Скорость — только на поднятом туннеле: на «подключении» цифры были бы нулями.
          if (trafficMeter && up) ...[
            const SizedBox(height: 8),
            TrafficRow(rxRate: rxRate, txRate: txRate, fg: fg, t: t),
          ],
          const SizedBox(height: 10),
          FilledButton.tonalIcon(
            onPressed: onDisconnect,
            icon: const Icon(Icons.power_settings_new, size: 18),
            label: Text(t('disconnect')),
          ),
        ],
      ),
    );
  }
}

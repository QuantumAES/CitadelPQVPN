import 'dart:async';

import 'package:flutter/widgets.dart' show AppLifecycleState;

/// Автозамок хранилища (находка N-2 сверки 2026-08-14).
///
/// В хранилище лежат не только профили: у администратора там **мастер-ссылка**, то есть вся
/// admin-плоскость сервера. До этого замок был только ручной — открытое хранилище жило в памяти
/// процесса до закрытия приложения, и короткий физический доступ к разблокированному телефону
/// давал полный доступ к управлению. Заход 10 (вход отпечатком) убрал главное возражение против
/// автозамка: возврат стоит одного касания, а не ввода длинного пароля.
///
/// Правила ровно два:
///   * **бездействие** — с последнего касания прошло больше таймаута → запереть;
///   * **фон** — уход в фон/погашение экрана засекает время; вернулись позже таймаута → запереть
///     сразу на возврате (не дожидаясь таймера, который в замороженном процессе мог не сработать).
///
/// Возврат в приложение раньше таймаута отсчёт сбрасывает — это обычная семантика «простоя», а не
/// «сессии»: человек, который только что работал в приложении, не должен получать замок в лицо.
///
/// Замок **не трогает туннель** — это инвариант всего клиента (`vault_lock` в ядре и
/// `AppState.lockVault`): автозамок обязан прятать секреты, а не рвать связь, иначе он превращается
/// из защиты в причину его выключить.
///
/// Класс намеренно ничего не знает ни про FFI, ни про виджеты: он получает время и события, отдаёт
/// один колбэк — поэтому проверяется юнит-тестом (`test/autolock_test.dart`), а не руками на
/// телефоне.
class AutoLock {
  AutoLock({required this.onLock, DateTime Function()? clock})
      : _clock = clock ?? DateTime.now;

  /// Что делать по срабатыванию (в приложении — `AppState.lockVault`). Зовётся только когда
  /// хранилище открыто (см. [setUnlocked]), поэтому повторных «замков поверх замка» не бывает.
  final void Function() onLock;
  final DateTime Function() _clock;

  /// Таймаут простоя; [Duration.zero] — автозамок выключен.
  Duration _timeout = Duration.zero;

  /// Есть ли что запирать: хранилище открыто.
  bool _unlocked = false;

  Timer? _timer;

  /// Момент ухода в фон (null — приложение на экране).
  DateTime? _awaySince;

  /// Текущий таймаут (для интерфейса/тестов).
  Duration get timeout => _timeout;

  /// Идёт ли отсчёт (для тестов: «таймер снят» — наблюдаемое свойство, а не деталь).
  bool get running => _timer != null;

  /// Настроить таймаут. Смена настройки перезапускает отсчёт с нуля: человек только что был в
  /// настройках, то есть в приложении.
  void configure(Duration timeout) {
    _timeout = timeout.isNegative ? Duration.zero : timeout;
    _awaySince = null;
    _restart();
  }

  /// Сообщить о состоянии хранилища. Открылось — начинаем отсчёт, закрылось — снимаем таймер
  /// (запирать нечего, а лишний таймер разбудил бы процесс впустую).
  void setUnlocked(bool unlocked) {
    if (_unlocked == unlocked) return;
    _unlocked = unlocked;
    _awaySince = null;
    _restart();
  }

  /// Человек взаимодействует с приложением — отсчёт простоя с начала.
  void poke() {
    if (_awaySince != null) return; // в фоне «касаний» не бывает; отсчёт держит уход в фон
    _restart();
  }

  /// События жизненного цикла приложения.
  ///
  /// `inactive` НЕ считается уходом: на десктопе он приходит на каждую потерю фокуса окна, а на
  /// Android — на любой системный диалог поверх (включая наш же запрос разрешения VPN и подсказку
  /// отпечатка). Ориентир — `paused`/`hidden`: экран погашен либо приложение свёрнуто.
  void onLifecycle(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
        _awaySince ??= _clock();
      case AppLifecycleState.resumed:
        final away = _awaySince;
        _awaySince = null;
        if (away != null && _armed && _clock().difference(away) >= _timeout) {
          _fire();
          return;
        }
        _restart();
      case AppLifecycleState.detached:
      case AppLifecycleState.inactive:
        break;
    }
  }

  /// Снять таймер (уход с экрана/закрытие приложения).
  void dispose() {
    _timer?.cancel();
    _timer = null;
  }

  bool get _armed => _unlocked && _timeout > Duration.zero;

  void _restart() {
    _timer?.cancel();
    _timer = null;
    if (!_armed) return;
    _timer = Timer(_timeout, _fire);
  }

  void _fire() {
    _timer?.cancel();
    _timer = null;
    if (!_armed) return;
    _unlocked = false; // повторного срабатывания на уже запертом хранилище быть не должно
    onLock();
  }
}

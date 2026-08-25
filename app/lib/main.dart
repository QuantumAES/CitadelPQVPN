import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:path_provider/path_provider.dart';
import 'package:window_manager/window_manager.dart';

import 'package:app/app_state.dart';
import 'package:app/biometric.dart';
import 'package:app/errors.dart';
import 'package:app/format.dart';
import 'package:app/home_page.dart';
import 'package:app/l10n/strings.dart';
import 'package:app/locked_session_banner.dart';
import 'package:app/traffic.dart';
import 'package:app/window_visibility.dart';
import 'package:app/windows_tray.dart';
import 'package:app/src/rust/api/citadel.dart';
import 'package:app/src/rust/api/diag.dart';
import 'package:app/src/rust/frb_generated.dart';

/// Desktop-платформы, где окно закрывается «красной кнопкой» (C8.2) и есть window_manager.
bool get _isDesktop => Platform.isLinux || Platform.isWindows || Platform.isMacOS;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  // C8.2: на desktop перехватываем закрытие окна — при активном туннеле спросим
  // «оставить в фоне / отключить и выйти», а не рвать сессию молча.
  if (_isDesktop) {
    await windowManager.ensureInitialized();
    // Портретное окно в стиле OpenVPN Connect (узкое+высокое) + брендовый заголовок окна: без него
    // OS-заголовок/панель задач показывают "app" (имя Flutter-проекта). #5.2/#5.3.
    // #п2: фикс-размер окна (не ресайзится) — узкое+высокое портретное как OpenVPN Connect.
    // min==max==size + setResizable(false) → рамку тянуть нельзя.
    const winSize = Size(400, 680);
    const opts = WindowOptions(
      size: winSize,
      minimumSize: winSize,
      maximumSize: winSize,
      center: true,
      title: 'CitadelPQVPN',
    );
    await windowManager.waitUntilReadyToShow(opts, () async {
      await windowManager.setTitle('CitadelPQVPN');
      await windowManager.setResizable(false); // #п2: фиксированное окно
      // Окно фиксированного размера разворачивать некуда: кнопка «развернуть» либо не работала
      // бы, либо растянула бы портретный макет. Убираем её из системной рамки.
      //
      // Но НЕ на Linux: там `setMaximizable(false)` в window_manager сделан через
      // `gtk_window_set_type_hint(GDK_WINDOW_TYPE_HINT_DIALOG)`, то есть окно объявляется
      // диалогом — а диалогу WM (GNOME/KWin/Xfwm) рисует только «закрыть», без «свернуть».
      // Так и пропала минимизация. Убрать одну кнопку, не задев другую, этим API нельзя:
      // `setMinimizable` дёргает ровно тот же type hint. На Linux «развернуть» и без того
      // недоступно — `setResizable(false)` уже запрещает менять размер.
      if (!Platform.isLinux) {
        await windowManager.setMaximizable(false);
      }
      await windowManager.show();
      await windowManager.focus();
    });
    await windowManager.setPreventClose(true);
    // #5.5: системный трей (Windows) инициализируется в _CitadelAppState (нативный, method-channel).
  }
  // На Android cwd=`/` (песочница не writable) и нет XDG/HOME — путь хранилища должна
  // задать платформа (приватный filesDir). На десктопе путь резолвится из XDG/HOME, и
  // трогать его нельзя: это сменило бы расположение уже существующих vault'ов.
  // Лог-файл задаём ДО startLogCapture, чтобы подхватить лог упавшей прошлой сессии.
  if (Platform.isAndroid) {
    final dir = await getApplicationSupportDirectory();
    setDataDir(dir: dir.path);
    setLogFile(path: '${dir.path}/citadel.log');
  }
  // Захват stderr движка → debug-панель приложения (иначе eprintln! ядра теряется, особенно
  // на Android). Идемпотентно; должно быть до первых vpn-операций.
  startLogCapture();
  runApp(const CitadelApp());
}

const _seed = Color(0xFF3B5BDB); // индиго-бренд CitadelPQVPN

ThemeData _theme(Brightness b) => ThemeData(
      brightness: b,
      colorScheme: ColorScheme.fromSeed(seedColor: _seed, brightness: b),
      useMaterial3: true,
      cardTheme: const CardThemeData(clipBehavior: Clip.antiAlias),
    );

class CitadelApp extends StatefulWidget {
  const CitadelApp({super.key});

  @override
  State<CitadelApp> createState() => _CitadelAppState();
}

class _CitadelAppState extends State<CitadelApp>
    with WindowListener, WidgetsBindingObserver {
  final AppState state = AppState();
  final GlobalKey<NavigatorState> _navKey = GlobalKey<NavigatorState>();

  /// Язык, на котором сейчас построено меню трея (нативное меню живёт вне дерева виджетов и само
  /// на смену языка не перестроится).
  String? _trayLang;

  @override
  void initState() {
    super.initState();
    // N-2: автозамку нужны переходы «свернули/погасили экран» — их даёт только наблюдатель
    // жизненного цикла. Ставим его выше всего дерева: экран разблокировки и главный экран
    // сменяют друг друга, а отсчёт простоя обязан пережить смену экрана.
    WidgetsBinding.instance.addObserver(this);
    if (_isDesktop) {
      windowManager.addListener(this);
      // #5.5: системный трей — только Windows (нативный). Пункт «Отключить» в меню зависит от
      // состояния → синхронизируем на смену AppState.
      if (WindowsTray.supported) {
        WindowsTray.init(
          onOpen: _showFromTray,
          onDisconnect: state.disconnect,
          onExit: _quitApp,
          t: Strings.forCode(state.lang),
        );
        state.addListener(_syncTray);
        _syncTray();
      }
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycle) {
    state.autoLock.onLifecycle(lifecycle);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    if (_isDesktop) {
      windowManager.removeListener(this);
      if (WindowsTray.supported) state.removeListener(_syncTray);
    }
    state.dispose();
    super.dispose();
  }

  // ─────────────────────────── #5.5 системный трей (Windows) ───────────────────────────

  /// Отразить состояние туннеля в трее: цвет точки-бейджа на значке + tooltip + видимость пункта
  /// «Отключить». Так состояние читается у свёрнутого приложения, без его открытия.
  void _syncTray() {
    // Строки трея берём без BuildContext: этот State живёт НАД MaterialApp, `Localizations` здесь
    // ещё нет — язык спрашиваем у состояния приложения напрямую.
    final t = Strings.forCode(state.lang);
    // Язык мог смениться — тогда пересобираем и подписи меню (тултип обновится ниже вместе с фазой).
    if (state.lang != _trayLang) {
      _trayLang = state.lang;
      WindowsTray.setMenuLabels(t);
    }
    final (phase, tip) = switch (state.phase) {
      // Узел выхода — без порта, как и на главном экране (см. format.dart).
      VpnPhase.up => (
          'up',
          state.exit.isEmpty
              ? t('tray_up')
              : t('tray_up_at', {'exit': hostOnly(state.exit)})
        ),
      VpnPhase.connecting => ('connecting', t('tray_connecting')),
      VpnPhase.error => (
          'error',
          [
            // errorTitle — КЛЮЧ строки (AppState._classify), а не готовый текст: переводим здесь.
            t('tray_error', {
              'reason': t(state.errorTitle.isEmpty
                      ? 'err_server_unreachable'
                      : state.errorTitle)
                  .toLowerCase(),
            }),
            if (state.activeProfileName.isNotEmpty) '(${state.activeProfileName})',
          ].join(' ')
        ),
      VpnPhase.off => ('off', t('tray_off')),
    };
    WindowsTray.setPhase(phase, tooltip: tip, live: state.isBusy);
  }

  void _showFromTray() {
    windowVisible.value = true;
    windowManager.show();
    windowManager.focus();
  }

  // ── видимость окна: гасим отрисовку, когда смотреть некому (см. window_visibility.dart) ──

  // Сворачивание/разворачивание окна на десктопе — это тот же «ушёл/вернулся», что фон на
  // телефоне, но приходит оно от оконного менеджера, а не жизненным циклом. Отдаём автозамку тем
  // же событием (N-2): свёрнутое в трей окно с открытым хранилищем — ровно тот случай, ради
  // которого автозамок и сделан.
  @override
  void onWindowMinimize() {
    windowVisible.value = false;
    state.autoLock.onLifecycle(AppLifecycleState.paused);
  }

  @override
  void onWindowRestore() {
    windowVisible.value = true;
    state.autoLock.onLifecycle(AppLifecycleState.resumed);
  }

  /// Страховка на случай, если окно показали/спрятали мимо наших вызовов (жест ОС, плагин):
  /// `window_manager` шлёт сюда имя события, и `hide`/`show` мы обязаны заметить.
  @override
  void onWindowEvent(String eventName) {
    switch (eventName) {
      case 'hide':
        windowVisible.value = false;
        state.autoLock.onLifecycle(AppLifecycleState.paused);
      case 'show':
      case 'restore':
      case 'focus':
        windowVisible.value = true;
        state.autoLock.onLifecycle(AppLifecycleState.resumed);
    }
  }

  /// Полный выход: чистый disconnect (снятие KS) → остановить службу → убрать трей → закрыть.
  Future<void> _quitApp() async {
    if (state.isBusy) {
      state.disconnect(); // vpnDisconnect → clean_shutdown ('Q'/disarm снимет kill-switch)
      await Future<void>.delayed(const Duration(milliseconds: 700));
    }
    // п.2 (Windows): погасить привилегированную citadel-svc.exe — она не должна висеть в задачах
    // без приложения. ПОСЛЕ disconnect: пока идёт сессия, служба занята pump'ом и запрос не примет.
    // На следующем подключении провайдер поднимет её обратно через SCM. На Linux/macOS — no-op.
    desktopServiceQuit();
    await WindowsTray.dispose(); // иконка должна исчезнуть до выхода, иначе останется «призрак»
    // Windows: выходим сразу (см. desktop_exit_now) — `destroy()` там разбирает движок и плагины
    // при живых нативных потоках уже после CoUninitialize, и это заканчивалось окном WER
    // «Программа прекратила работу» на штатном закрытии. Всё, что должно пережить выход, уже на
    // диске: vault пишется атомарно, kill-switch снят, служба уведомлена.
    if (Platform.isWindows) {
      desktopExitNow();
      return; // сюда управление не возвращается
    }
    await windowManager.destroy();
  }

  /// C8.2: пользователь нажал «крестик». Туннель неактивен → закрываемся сразу; активен →
  /// уходим в фон, не разрывая сессию.
  ///
  /// Где есть трей (Windows), диалога НЕТ: закрытие окна при активном туннеле — это «убрать с
  /// глаз», а не «отключить». Приложение сворачивается в трей, соединение продолжает работать;
  /// выйти по-настоящему — пункт «Выход» в меню трея (он делает чистый disconnect со снятием
  /// kill-switch). Где трея нет (Linux/macOS), скрытое окно вернуть было бы нечем, поэтому там
  /// по-прежнему спрашиваем.
  @override
  void onWindowClose() async {
    if (!state.isBusy) {
      await _quitApp(); // туннеля нет — просто выходим (убрав иконку трея)
      return;
    }
    if (WindowsTray.supported) {
      windowVisible.value = false; // окно ушло в трей — гасим анимации и фоновые перерисовки
      await windowManager.hide();
      return;
    }
    final ctx = _navKey.currentContext;
    if (ctx == null || !ctx.mounted) {
      await _quitApp();
      return;
    }
    // Сюда попадают только платформы без трея (Linux/macOS): «в фоне» = свернуть в панель задач.
    final t = Strings.of(ctx);
    final choice = await showDialog<String>(
      context: ctx,
      builder: (d) => AlertDialog(
        title: Text(t('tunnel_active')),
        content: Text(t('close_window_body')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(d, 'cancel'), child: Text(t('cancel'))),
          TextButton(
              onPressed: () => Navigator.pop(d, 'background'),
              child: Text(t('close_background'))),
          FilledButton(
              onPressed: () => Navigator.pop(d, 'quit'), child: Text(t('close_quit'))),
        ],
      ),
    );
    switch (choice) {
      case 'background':
        windowVisible.value = false;
        await windowManager.minimize();
      case 'quit':
        await _quitApp();
      default:
        break; // отмена — окно остаётся открытым
    }
  }

  @override
  Widget build(BuildContext context) {
    // AnimatedBuilder обнимает ВЕСЬ MaterialApp, а не только `home`: смена языка меняет `locale`
    // самого приложения (и переводы Material-виджетов), а не только наши строки.
    return AnimatedBuilder(
      animation: state,
      builder: (context, _) => MaterialApp(
        // Скрытое окно (трей/сворачивание) не должно стоить процессорного времени: TickerMode
        // над всем деревом останавливает анимации — прежде всего бесконечный индикатор
        // «Подключение…», который крутится столько же, сколько движок ретраит недоступный сервер.
        // Работу самого движка это не трогает, только отрисовку.
        // N-2: любое касание/клик — признак, что человек здесь, и отсчёт простоя начинается
        // заново. `translucent` + отсутствие обработчиков жестов: слушаем, но никому не мешаем.
        builder: (ctx, child) => Listener(
          behavior: HitTestBehavior.translucent,
          onPointerDown: (_) => state.autoLock.poke(),
          onPointerSignal: (_) => state.autoLock.poke(),
          child: ValueListenableBuilder<bool>(
            valueListenable: windowVisible,
            child: child ?? const SizedBox.shrink(),
            builder: (_, visible, inner) => TickerMode(enabled: visible, child: inner!),
          ),
        ),
        navigatorKey: _navKey,
        title: 'CitadelPQVPN',
        debugShowCheckedModeBanner: false,
        theme: _theme(Brightness.light),
        darkTheme: _theme(Brightness.dark),
        themeMode: ThemeMode.system,
        // Язык выбирает пользователь (настройка хранится ядром), а не система: VPN-клиент часто
        // ставят на чужом/рабочем устройстве с непонятной локалью, и «как в системе» там не помощь.
        locale: Locale(state.lang),
        supportedLocales: kSupportedLocales,
        localizationsDelegates: const [
          StringsDelegate(),
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        // Gate: если хранилище есть, но не разблокировано — экран ввода пароля.
        home: state.hasVault && !state.unlocked
            ? UnlockScreen(state: state)
            : HomePage(state: state),
      ),
    );
  }
}

/// Экран разблокировки хранилища мастер-паролем (показывается, если vault.bin существует).
class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key, required this.state});
  final AppState state;

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _pw = TextEditingController();
  bool _busy = false;
  String? _error;

  /// C9: идёт системный диалог отпечатка. Отдельно от [_busy] — там Argon2id на пароле, здесь
  /// ожидание пальца, и блокировать надо обе кнопки, но подписи у них разные.
  bool _bioBusy = false;

  /// Предлагать ли отпечаток: настроен для этого хранилища И устройство готово.
  bool get _bioReady => widget.state.biometricEnrolled && widget.state.biometricOffered;

  /// Индикация трафика на плашке живой сессии — тот же расчёт, что на главном экране
  /// (`lib/traffic.dart`). Счётчики ядра к хранилищу отношения не имеют, поэтому под замком
  /// доступны как обычно.
  final _traffic = TrafficSampler();
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted || !windowVisible.value) return; // спрятанное окно не перерисовываем
      final live = widget.state.phase == VpnPhase.up;
      if (!live || !widget.state.trafficMeter) {
        _traffic.reset();
        return;
      }
      final c = trafficCounters();
      _traffic.sample(c.rxBytes.toInt(), c.txBytes.toInt(), DateTime.now());
      setState(() {});
    });
    // C9: если вход по отпечатку включён — спрашиваем палец сразу, не дожидаясь нажатия. Ради
    // этого настройку и включают; отменивший диалог получает обычное поле пароля (и клавиатуру мы
    // ему заранее не открываем — см. autofocus ниже).
    WidgetsBinding.instance.addPostFrameCallback((_) => _biometricOnEntry());
  }

  Future<void> _biometricOnEntry() async {
    await widget.state.refreshBiometric();
    if (!mounted || !_bioReady) return;
    await _biometric(auto: true);
  }

  /// Разблокировать отпечатком. `auto` — вызов при входе на экран: там о неудаче молчим (человек
  /// диалога не просил), а по явному нажатию — говорим.
  Future<void> _biometric({bool auto = false}) async {
    if (_busy || _bioBusy) return;
    final t = Strings.of(context);
    setState(() {
      _bioBusy = true;
      _error = null;
    });
    try {
      await widget.state.unlockWithBiometric(BiometricTexts(
        title: 'CitadelPQVPN',
        subtitle: t('biometric_prompt_unlock'),
        cancel: t('cancel'),
      ));
    } on BiometricFailure catch (e) {
      // «Ключа больше нет» показываем ВСЕГДА, даже при автозапуске: иначе человек видит, что
      // отпечаток молча перестал работать, и не знает, что чинится это входом по паролю.
      if (!mounted) return;
      if (e.keyGone) {
        setState(() => _error = t('biometric_key_gone'));
      } else if (!e.cancelled && !auto) {
        // Причина отказа платформы (занят датчик, слишком много попыток) человеку ничего не
        // объясняет и не переведена — она уходит в журнал, а на экране остаётся суть.
        debugPrint('[biometric] $e');
        setState(() => _error = t('biometric_failed'));
      }
    } catch (e) {
      if (mounted) setState(() => _error = humanError(e));
    } finally {
      if (mounted) setState(() => _bioBusy = false);
    }
  }

  Future<void> _submit() async {
    if (_pw.text.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.state.unlock(_pw.text);
    } catch (e) {
      // Текст берём от ядра: оно отличает «неверный пароль» от «нет доступа к файлу хранилища»
      // (с путём) — раньше любая причина выглядела как неверный пароль, и человек перебирал его
      // там, где надо было чинить доступ.
      setState(() => _error = humanError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _tick?.cancel();
    _pw.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final t = Strings.of(context);
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 380),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Фирменный логотип (тот же, что иконка приложения) — экран пароля должен
                // опознаваться как CitadelPQVPN, а не как безымянный запрос пароля.
                Image.asset('assets/logo.png',
                    width: 96, height: 96, filterQuality: FilterQuality.medium),
                const SizedBox(height: 16),
                Text('CitadelPQVPN',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 4),
                Text(t('vault_locked'),
                    textAlign: TextAlign.center,
                    style: Theme.of(context)
                        .textTheme
                        .bodyMedium
                        ?.copyWith(color: cs.outline)),
                // Замок хранилища туннель не рвёт — значит, экран пароля обязан показать, что
                // сессия жива, и дать её отключить (иначе работающий VPN становится невидимым).
                LockedSessionBanner(
                  busy: widget.state.isBusy,
                  up: widget.state.phase == VpnPhase.up,
                  exit: widget.state.exit,
                  transport: widget.state.transport,
                  trafficMeter: widget.state.trafficMeter,
                  rxRate: _traffic.rxRate,
                  txRate: _traffic.txRate,
                  onDisconnect: widget.state.disconnect,
                ),
                const SizedBox(height: 28),
                TextField(
                  controller: _pw,
                  // Клавиатуру не поднимаем, если человек и так собирался войти отпечатком:
                  // системный диалог уже открыт поверх, и поле под ним ждать ввода не должно.
                  autofocus: !_bioReady,
                  obscureText: true,
                  onSubmitted: (_) => _submit(),
                  decoration: InputDecoration(
                    labelText: t('master_password'),
                    prefixIcon: const Icon(Icons.key_outlined),
                    border: const OutlineInputBorder(),
                  ),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  ErrorNote(text: _error!),
                ],
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: (_busy || _bioBusy) ? null : _submit,
                  child: _busy
                      ? const SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : Text(t('unlock')),
                ),
                // C9: повторный вызов отпечатка — на случай отменённого/промахнувшегося диалога.
                if (_bioReady) ...[
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: (_busy || _bioBusy) ? null : _biometric,
                    icon: const Icon(Icons.fingerprint),
                    label: Text(t('biometric_unlock')),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}

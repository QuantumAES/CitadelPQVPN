import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'package:window_manager/window_manager.dart';

import 'package:app/app_state.dart';
import 'package:app/home_page.dart';
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

class _CitadelAppState extends State<CitadelApp> with WindowListener {
  final AppState state = AppState();
  final GlobalKey<NavigatorState> _navKey = GlobalKey<NavigatorState>();

  @override
  void initState() {
    super.initState();
    if (_isDesktop) {
      windowManager.addListener(this);
      // #5.5: системный трей — только Windows (нативный). Пункт «Отключить» в меню зависит от
      // состояния → синхронизируем на смену AppState.
      if (WindowsTray.supported) {
        WindowsTray.init(
          onOpen: _showFromTray,
          onDisconnect: state.disconnect,
          onExit: _quitApp,
        );
        state.addListener(_syncTray);
        _syncTray();
      }
    }
  }

  @override
  void dispose() {
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
    final (phase, tip) = switch (state.phase) {
      VpnPhase.up => ('up', 'CitadelPQVPN — туннель активен${state.exit.isEmpty ? '' : ' (${state.exit})'}'),
      VpnPhase.connecting => ('connecting', 'CitadelPQVPN — подключение…'),
      VpnPhase.error => ('error', 'CitadelPQVPN — ошибка: ${state.errorMsg}'),
      VpnPhase.off => ('off', 'CitadelPQVPN — туннель выключен'),
    };
    WindowsTray.setPhase(phase, tooltip: tip);
  }

  void _showFromTray() {
    windowManager.show();
    windowManager.focus();
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
    await WindowsTray.dispose();
    await windowManager.destroy();
  }

  /// C8.2: пользователь нажал «крестик». Туннель неактивен → закрываемся сразу; активен → диалог
  /// «Оставить в фоне» (свернуть, сессия жива) / «Отключить и выйти» (чистый disconnect → снятие KS).
  @override
  void onWindowClose() async {
    if (!state.isBusy) {
      await _quitApp(); // туннеля нет — просто выходим (убрав иконку трея)
      return;
    }
    final ctx = _navKey.currentContext;
    if (ctx == null || !ctx.mounted) {
      await _quitApp();
      return;
    }
    // На Windows «в фоне» = сворачивание в системный трей; на Linux/macOS трея нет → обычный minimize.
    final bg = WindowsTray.supported ? 'в трей' : 'свернётся';
    final choice = await showDialog<String>(
      context: ctx,
      builder: (d) => AlertDialog(
        title: const Text('Туннель активен'),
        content: Text(
          'VPN подключён. Что сделать при закрытии окна?\n\n'
          '• Оставить в фоне — окно $bg, соединение продолжит работать.\n'
          '• Отключить и выйти — разорвать туннель и закрыть приложение.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(d, 'cancel'), child: const Text('Отмена')),
          TextButton(onPressed: () => Navigator.pop(d, 'background'), child: const Text('Оставить в фоне')),
          FilledButton(onPressed: () => Navigator.pop(d, 'quit'), child: const Text('Отключить и выйти')),
        ],
      ),
    );
    switch (choice) {
      case 'background':
        // Windows → скрыть в трей (иконка вернёт); Linux/macOS → minimize (в панель задач).
        if (WindowsTray.supported) {
          await windowManager.hide();
        } else {
          await windowManager.minimize();
        }
      case 'quit':
        await _quitApp();
      default:
        break; // отмена — окно остаётся открытым
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: _navKey,
      title: 'CitadelPQVPN',
      debugShowCheckedModeBanner: false,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: AnimatedBuilder(
        animation: state,
        builder: (context, _) {
          // Gate: если хранилище есть, но не разблокировано — экран ввода пароля.
          if (state.hasVault && !state.unlocked) {
            return UnlockScreen(state: state);
          }
          return HomePage(state: state);
        },
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

  Future<void> _submit() async {
    if (_pw.text.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.state.unlock(_pw.text);
    } catch (_) {
      setState(() => _error = 'Неверный мастер-пароль');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _pw.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
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
                Icon(Icons.shield_moon_outlined, size: 64, color: cs.primary),
                const SizedBox(height: 16),
                Text('CitadelPQVPN',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 4),
                Text('Хранилище профилей заблокировано',
                    textAlign: TextAlign.center,
                    style: Theme.of(context)
                        .textTheme
                        .bodyMedium
                        ?.copyWith(color: cs.outline)),
                const SizedBox(height: 28),
                TextField(
                  controller: _pw,
                  autofocus: true,
                  obscureText: true,
                  onSubmitted: (_) => _submit(),
                  decoration: InputDecoration(
                    labelText: 'Мастер-пароль',
                    prefixIcon: const Icon(Icons.key_outlined),
                    border: const OutlineInputBorder(),
                    errorText: _error,
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: _busy ? null : _submit,
                  child: _busy
                      ? const SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Разблокировать'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'package:window_manager/window_manager.dart';

import 'package:app/app_state.dart';
import 'package:app/home_page.dart';
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
    const opts = WindowOptions(
      size: Size(440, 820),
      minimumSize: Size(380, 640),
      center: true,
      title: 'CitadelPQVPN',
    );
    await windowManager.waitUntilReadyToShow(opts, () async {
      await windowManager.setTitle('CitadelPQVPN');
      await windowManager.show();
      await windowManager.focus();
    });
    await windowManager.setPreventClose(true);
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
    if (_isDesktop) windowManager.addListener(this);
  }

  @override
  void dispose() {
    if (_isDesktop) windowManager.removeListener(this);
    state.dispose();
    super.dispose();
  }

  /// C8.2: пользователь нажал «крестик». Туннель неактивен → закрываемся сразу; активен → диалог
  /// «Оставить в фоне» (свернуть, сессия жива) / «Отключить и выйти» (чистый disconnect → снятие KS).
  @override
  void onWindowClose() async {
    if (!state.isBusy) {
      await windowManager.destroy();
      return;
    }
    final ctx = _navKey.currentContext;
    if (ctx == null || !ctx.mounted) {
      await windowManager.destroy();
      return;
    }
    final choice = await showDialog<String>(
      context: ctx,
      builder: (d) => AlertDialog(
        title: const Text('Туннель активен'),
        content: const Text(
          'VPN подключён. Что сделать при закрытии окна?\n\n'
          '• Оставить в фоне — окно свернётся, соединение продолжит работать.\n'
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
        await windowManager.minimize();
      case 'quit':
        state.disconnect(); // vpnDisconnect → clean_shutdown ('Q' → helper снимет kill-switch)
        // дать движку/хелперу снять сеть до выхода процесса (иначе EOF без 'Q' оставит KS)
        await Future<void>.delayed(const Duration(milliseconds: 700));
        await windowManager.destroy();
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

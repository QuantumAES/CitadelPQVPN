import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'package:app/app_state.dart';
import 'package:app/home_page.dart';
import 'package:app/src/rust/api/citadel.dart';
import 'package:app/src/rust/frb_generated.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  // На Android cwd=`/` (песочница не writable) и нет XDG/HOME — путь хранилища должна
  // задать платформа (приватный filesDir). На десктопе путь резолвится из XDG/HOME, и
  // трогать его нельзя: это сменило бы расположение уже существующих vault'ов.
  if (Platform.isAndroid) {
    final dir = await getApplicationSupportDirectory();
    setDataDir(dir: dir.path);
  }
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

class _CitadelAppState extends State<CitadelApp> {
  final AppState state = AppState();

  @override
  void dispose() {
    state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
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

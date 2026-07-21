import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:app/android_vpn.dart';
import 'package:app/app_state.dart';
import 'package:app/debug_panel.dart';
import 'package:app/qr_scan_page.dart';
import 'package:app/src/rust/api/citadel.dart';
import 'package:app/split_tunnel_page.dart';
import 'package:app/subscribers_page.dart';

/// Версия сборки для экрана «О приложении». Задаётся `--dart-define=CITADEL_VERSION=<tag>` в
/// mk-client-release.sh (совпадает с тегом релиза, напр. v0.3.0-pre2); для локальных `flutter run`
/// — 'dev'. Заменяет прежний `ядро v${coreVersion()}` (тот всегда показывал версию крейта 0.1.0).
const String appVersion = String.fromEnvironment('CITADEL_VERSION', defaultValue: 'dev');

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.state});
  final AppState state;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    // обновляем счётчик времени сессии раз в секунду, пока подключены
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (widget.state.phase == VpnPhase.up && mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  AppState get s => widget.state;

  // ─────────────────────────── подключение ───────────────────────────

  Future<void> _tapProfile(ProfileDto p) async {
    if (s.isBusy && s.activeProfileId == p.id) return; // уже этот профиль
    if (s.isBusy && s.activeProfileId != p.id) {
      final cur = _activeName();
      final ok = await _confirm(
        'Переключить подключение?',
        'Сейчас активно подключение «$cur». Отключить его и подключиться к «${p.name}»?',
        confirmLabel: 'Переключить',
      );
      if (ok != true) return;
      s.disconnect();
      await Future.delayed(const Duration(milliseconds: 350)); // дать helper свернуть citadel0
    }
    s.connectProfile(p.id);
  }

  String _activeName() {
    final id = s.activeProfileId;
    if (id == null) return 'новый профиль';
    return s.profiles
        .firstWhere((x) => x.id == id, orElse: () => _ghost(id))
        .name;
  }

  ProfileDto _ghost(String id) => ProfileDto(
        id: id,
        name: 'профиль',
        servers: '',
        hasPin: false,
        hasPqAuth: false,
        hasObfs: false,
        isAdmin: false,
        lastExit: '',
      );

  // ─────────────────────────── добавление профиля ───────────────────────────

  Future<void> _addProfile() async {
    final res = await showModalBottomSheet<({String name, String uri})>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (_) => const AddProfileSheet(),
    );
    if (res == null || !mounted) return;
    if (!await _ensureVaultReady()) return;
    s.addAndConnect(res.name, res.uri);
  }

  /// Гарантировать, что vault создан и разблокирован (чтобы сохранить профиль на успехе).
  Future<bool> _ensureVaultReady() async {
    if (vaultExists()) {
      if (vaultIsUnlocked()) return true;
      return await _passwordDialog(
        title: 'Разблокировать хранилище',
        action: 'Разблокировать',
        onSubmit: (pw) => s.unlock(pw),
      );
    }
    return await _passwordDialog(
      title: 'Создать хранилище',
      hint: 'Профили шифруются этим мастер-паролем (AES-256-GCM). Без него их не восстановить.',
      action: 'Создать',
      confirm: true,
      onSubmit: (pw) => s.createVault(pw),
    );
  }

  // ─────────────────────────── UI ───────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('CitadelPQVPN'),
        actions: [
          // #0.3: «Добавить профиль» — в AppBar, а не FAB: плавающая кнопка перекрывала
          // popup-меню (три точки) нижних плиток профилей.
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: 'Добавить профиль',
            onPressed: _addProfile,
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Настройки',
            onPressed: _openSettings,
          ),
        ],
      ),
      body: AnimatedBuilder(
        animation: s,
        builder: (context, _) {
          return ListView(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
            children: [
              _StatusCard(state: s, onDisconnect: s.disconnect),
              if (s.debugEnabled) ...[
                const SizedBox(height: 16),
                _DebugSection(state: s),
              ],
              const SizedBox(height: 20),
              if (s.profiles.isEmpty)
                _EmptyProfiles(onAdd: _addProfile)
              else ...[
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 4),
                  child: Text('Профили',
                      style: Theme.of(context).textTheme.titleSmall),
                ),
                const SizedBox(height: 8),
                ...s.profiles.map((p) => _ProfileTile(
                      profile: p,
                      active: s.activeProfileId == p.id,
                      phase: s.phase,
                      onTap: () => _tapProfile(p),
                      onDelete: () => _deleteProfile(p),
                      onDisconnect: s.disconnect,
                      onSubscribers:
                          p.isAdmin ? () => _openSubscribers(p) : null,
                    )),
              ],
            ],
          );
        },
      ),
    );
  }

  /// C7.4: экран абонентов admin-профиля (управление реестром по туннелю).
  void _openSubscribers(ProfileDto p) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => SubscribersPage(state: s, profile: p)),
    );
  }

  Future<void> _deleteProfile(ProfileDto p) async {
    final ok = await _confirm(
      'Удалить профиль?',
      'Профиль «${p.name}» будет удалён из хранилища. Это действие необратимо.',
      confirmLabel: 'Удалить',
      destructive: true,
    );
    if (ok == true) s.removeProfile(p.id);
  }

  // ─────────────────────────── настройки ───────────────────────────

  void _openSettings() {
    showModalBottomSheet(
      context: context,
      showDragHandle: true,
      builder: (sheetCtx) => SafeArea(
        child: SingleChildScrollView( // #6: скролл — в компактном окне все пункты влезают
          child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (s.unlocked) ...[
              ListTile(
                leading: const Icon(Icons.password_outlined),
                title: const Text('Сменить мастер-пароль'),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  _changePassword();
                },
              ),
              ListTile(
                leading: const Icon(Icons.lock_outline),
                title: const Text('Заблокировать хранилище'),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  s.lockVault();
                },
              ),
            ],
            SwitchListTile(
              secondary: const Icon(Icons.bug_report_outlined),
              title: const Text('Режим отладки'),
              subtitle: const Text('Журнал ядра и диагностика подключения'),
              value: s.debugEnabled,
              onChanged: (_) {
                s.toggleDebug();
                Navigator.pop(sheetCtx);
              },
            ),
            // Kill-switch — на десктопе тумблер (Linux-хелпер через firewall); на Android это
            // СИСТЕМНЫЙ always-on+lockdown (приложение не может форсить), поэтому — гайд в настройки.
            if (!Platform.isAndroid && !Platform.isIOS)
              SwitchListTile(
                secondary: const Icon(Icons.shield_outlined),
                title: const Text('Kill-switch'),
                subtitle: const Text('Блокировать трафик вне туннеля (fail-closed); с новой сессии'),
                value: s.killswitch,
                onChanged: (_) {
                  s.toggleKillswitch();
                  Navigator.pop(sheetCtx);
                },
              ),
            if (Platform.isAndroid)
              ListTile(
                leading: const Icon(Icons.shield_outlined),
                title: const Text('Kill-switch (always-on)'),
                subtitle: const Text('Настроить в системных настройках VPN'),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  _showAlwaysOnGuide();
                },
              ),
            // C8.3 split-tunnel — Android (приложения+назначения) и Linux (только назначения).
            if (Platform.isAndroid || Platform.isLinux)
              ListTile(
                leading: const Icon(Icons.alt_route),
                title: const Text('Split-туннель'),
                subtitle: Text(Platform.isAndroid
                    ? 'По приложениям и адресам: через туннель / в обход'
                    : 'По адресам назначения: через туннель / в обход'),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const SplitTunnelPage()),
                  );
                },
              ),
            // Admin (C7.4): реестр абонентов живёт в меню admin-профиля («Абоненты»), не здесь —
            // операции идут по туннелю этого профиля, SSH-путь удалён.
            ListTile(
              leading: const Icon(Icons.info_outline),
              title: const Text('О приложении'),
              subtitle: Text('Постквантовый VPN · $appVersion · ядро v${coreVersion()}'),
            ),
          ],
        ),
        ),
      ),
    );
  }

  /// Android kill-switch = системный always-on+lockdown: объясняем и ведём в настройки VPN.
  Future<void> _showAlwaysOnGuide() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: const Text('Kill-switch (always-on)'),
        content: const Text(
          'На Android блокировку трафика мимо VPN включает система, не приложение.\n\n'
          'В системных настройках VPN включи для CitadelPQVPN:\n'
          '• Постоянный VPN (Always-on VPN)\n'
          '• Блокировать соединения без VPN',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(dctx, false), child: const Text('Закрыть')),
          FilledButton(
            onPressed: () => Navigator.pop(dctx, true),
            child: const Text('Открыть настройки'),
          ),
        ],
      ),
    );
    if (ok == true) await AndroidVpn.openVpnSettings();
  }

  Future<void> _changePassword() async {
    final oldC = TextEditingController();
    final newC = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: const Text('Сменить мастер-пароль'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: oldC,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Текущий пароль'),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: newC,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Новый пароль'),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: const Text('Отмена')),
          FilledButton(
              onPressed: () => Navigator.pop(dctx, true),
              child: const Text('Сменить')),
        ],
      ),
    );
    if (ok == true) {
      try {
        await s.changePassword(oldC.text, newC.text);
        _toast('Мастер-пароль изменён');
      } catch (_) {
        _toast('Не удалось: текущий пароль неверен');
      }
    }
    oldC.dispose();
    newC.dispose();
  }

  // ─────────────────────────── общие диалоги ───────────────────────────

  Future<bool?> _confirm(String title, String body,
      {String confirmLabel = 'OK', bool destructive = false}) {
    return showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: Text(title),
        content: Text(body),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: const Text('Отмена')),
          FilledButton(
            style: destructive
                ? FilledButton.styleFrom(
                    backgroundColor: Theme.of(dctx).colorScheme.error)
                : null,
            onPressed: () => Navigator.pop(dctx, true),
            child: Text(confirmLabel),
          ),
        ],
      ),
    );
  }

  /// Диалог ввода пароля (с опциональным подтверждением для создания). Возвращает true при успехе.
  Future<bool> _passwordDialog({
    required String title,
    required String action,
    required Future<void> Function(String) onSubmit,
    String? hint,
    bool confirm = false,
  }) async {
    final pw = TextEditingController();
    final pw2 = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) {
        String? err;
        return StatefulBuilder(builder: (dctx, setLocal) {
          Future<void> submit() async {
            if (pw.text.isEmpty) {
              setLocal(() => err = 'Пароль не может быть пустым');
              return;
            }
            if (confirm && pw.text != pw2.text) {
              setLocal(() => err = 'Пароли не совпадают');
              return;
            }
            try {
              await onSubmit(pw.text);
              if (dctx.mounted) Navigator.pop(dctx, true);
            } catch (e) {
              // При создании «неверного пароля» не бывает — показываем реальную ошибку
              // (например, недоступный каталог), иначе бы маскировали её под пароль.
              setLocal(() => err = confirm
                  ? 'Не удалось создать: ${_short(e)}'
                  : 'Неверный пароль');
            }
          }

          return AlertDialog(
            title: Text(title),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (hint != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Text(hint,
                        style: Theme.of(dctx).textTheme.bodySmall),
                  ),
                TextField(
                  controller: pw,
                  autofocus: true,
                  obscureText: true,
                  decoration:
                      InputDecoration(labelText: 'Пароль', errorText: err),
                  onSubmitted: confirm ? null : (_) => submit(),
                ),
                if (confirm) ...[
                  const SizedBox(height: 8),
                  TextField(
                    controller: pw2,
                    obscureText: true,
                    decoration:
                        const InputDecoration(labelText: 'Повторите пароль'),
                    onSubmitted: (_) => submit(),
                  ),
                ],
              ],
            ),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(dctx, false),
                  child: const Text('Отмена')),
              FilledButton(onPressed: submit, child: Text(action)),
            ],
          );
        });
      },
    );
    pw.dispose();
    pw2.dispose();
    return ok ?? false;
  }

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
  }

  /// Короткое читабельное представление FFI-ошибки для inline-показа в диалоге.
  static String _short(Object e) {
    final s = e.toString().replaceAll('\n', ' ').trim();
    return s.length > 120 ? '${s.substring(0, 117)}…' : s;
  }
}

// ═══════════════════════════ секция отладки ═══════════════════════════

class _DebugSection extends StatefulWidget {
  const _DebugSection({required this.state});
  final AppState state;

  @override
  State<_DebugSection> createState() => _DebugSectionState();
}

class _DebugSectionState extends State<_DebugSection> {
  final List<String> _diag = [];
  StreamSubscription<DiagLineDto>? _sub;
  bool _running = false;

  AppState get s => widget.state;

  /// Профиль для диагностики: активный, иначе первый в списке.
  String? get _targetId =>
      s.activeProfileId ?? (s.profiles.isNotEmpty ? s.profiles.first.id : null);

  void _run() {
    final id = _targetId;
    if (id == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Нет профиля для диагностики')),
      );
      return;
    }
    _sub?.cancel();
    setState(() {
      _diag
        ..clear()
        ..add('▶ Пробное подключение для диагностики (отдельная сессия, не основной туннель)…');
      _running = true;
    });
    _sub = runDiagnostics(profileId: id).listen(
      (l) {
        if (!mounted) return;
        setState(() => _diag.add('${l.ok ? '✔' : '✗'} ${l.step} — ${l.detail}'));
      },
      onDone: () {
        if (mounted) setState(() => _running = false);
      },
      onError: (Object e) {
        if (mounted) {
          setState(() {
            _running = false;
            _diag.add('✗ Диагностика прервана: $e');
          });
        }
      },
    );
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: _running ? null : _run,
                icon: _running
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.fact_check_outlined),
                label: Text(_running ? 'Проверка…' : 'Диагностика подключения'),
              ),
            ),
          ],
        ),
        if (_diag.isNotEmpty) ...[
          const SizedBox(height: 12),
          MonoLogView(
            title: 'Диагностика',
            icon: Icons.checklist_rtl,
            lines: _diag,
            height: 200,
            onClear: () => setState(() => _diag.clear()),
          ),
        ],
        const SizedBox(height: 12),
        const DebugLogPanel(),
      ],
    );
  }
}

// ═══════════════════════════ карточка статуса ═══════════════════════════

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.state, required this.onDisconnect});
  final AppState state;
  final VoidCallback onDisconnect;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final dark = Theme.of(context).brightness == Brightness.dark;

    late Color bg, fg;
    late IconData icon;
    late String label;
    Widget? lead;

    switch (state.phase) {
      case VpnPhase.up:
        bg = (dark ? Colors.green.shade900 : Colors.green.shade50);
        fg = (dark ? Colors.green.shade200 : Colors.green.shade800);
        icon = Icons.shield;
        label = 'Защищено';
      case VpnPhase.connecting:
        bg = (dark ? Colors.amber.shade900 : Colors.amber.shade50);
        fg = (dark ? Colors.amber.shade200 : Colors.amber.shade900);
        icon = Icons.shield_outlined;
        label = 'Подключение…';
        lead = SizedBox(
          height: 22,
          width: 22,
          child: CircularProgressIndicator(strokeWidth: 2.4, color: fg),
        );
      case VpnPhase.error:
        bg = cs.errorContainer;
        fg = cs.onErrorContainer;
        icon = Icons.gpp_bad_outlined;
        label = 'Ошибка';
      case VpnPhase.off:
        bg = cs.surfaceContainerHighest;
        fg = cs.onSurfaceVariant;
        icon = Icons.lock_open_outlined;
        label = 'Не защищено';
    }

    final details = <String>[
      if (state.exit.isNotEmpty) state.exit,
      if (state.transport.isNotEmpty) state.transport,
      if (state.cidr.isNotEmpty) state.cidr,
    ].join('  ·  ');

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        children: [
          Row(
            children: [
              lead ?? Icon(icon, color: fg, size: 26),
              const SizedBox(width: 12),
              Expanded(
                child: Text(label,
                    style: Theme.of(context)
                        .textTheme
                        .titleLarge
                        ?.copyWith(color: fg, fontWeight: FontWeight.w600)),
              ),
              if (state.phase == VpnPhase.up && state.since != null)
                Text(_fmtDur(DateTime.now().difference(state.since!)),
                    style: Theme.of(context)
                        .textTheme
                        .titleMedium
                        ?.copyWith(
                            color: fg, fontFeatures: const [
                      FontFeature.tabularFigures()
                    ])),
            ],
          ),
          if (details.isNotEmpty || state.errorMsg.isNotEmpty) ...[
            const SizedBox(height: 6),
            Align(
              alignment: Alignment.centerLeft,
              child: Text(
                state.phase == VpnPhase.error ? state.errorMsg : details,
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: fg.withValues(alpha: 0.9)),
              ),
            ),
          ],
          if (state.isBusy) ...[
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: onDisconnect,
                icon: const Icon(Icons.power_settings_new),
                label: const Text('Отключить'),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

// ═══════════════════════════ плитка профиля ═══════════════════════════

class _ProfileTile extends StatelessWidget {
  const _ProfileTile({
    required this.profile,
    required this.active,
    required this.phase,
    required this.onTap,
    required this.onDelete,
    required this.onDisconnect,
    this.onSubscribers,
  });
  final ProfileDto profile;
  final bool active;
  final VpnPhase phase;
  final VoidCallback onTap;
  final VoidCallback onDelete;
  final VoidCallback onDisconnect;
  /// C7.4: открыть экран абонентов (не null только у admin-профиля).
  final VoidCallback? onSubscribers;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Color dot;
    if (active && phase == VpnPhase.up) {
      dot = Colors.green;
    } else if (active && phase == VpnPhase.connecting) {
      dot = Colors.amber;
    } else {
      dot = cs.outlineVariant;
    }

    final chips = <Widget>[
      if (profile.isAdmin)
        _featChip(context, Icons.admin_panel_settings_outlined, 'admin'),
      if (profile.hasPqAuth)
        _featChip(context, Icons.verified_user_outlined, 'PQ-auth'),
      if (profile.hasObfs) _featChip(context, Icons.blur_on, 'obfs'),
      if (profile.hasPin) _featChip(context, Icons.push_pin_outlined, 'pin'),
    ];

    return Card(
      elevation: 0,
      color: active ? cs.primaryContainer.withValues(alpha: 0.5) : cs.surfaceContainerLow,
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        onTap: onTap,
        leading: Icon(Icons.circle, size: 14, color: dot),
        title: Text(profile.name,
            maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (profile.servers.isNotEmpty)
              Text(profile.servers,
                  maxLines: 1, overflow: TextOverflow.ellipsis),
            if (chips.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Wrap(spacing: 6, runSpacing: 4, children: chips),
              ),
          ],
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (v) {
            if (v == 'delete') onDelete();
            if (v == 'connect') onTap();
            if (v == 'disconnect') onDisconnect();
            if (v == 'subscribers') onSubscribers?.call();
          },
          itemBuilder: (_) => [
            if (active && (phase == VpnPhase.up || phase == VpnPhase.connecting))
              const PopupMenuItem(value: 'disconnect', child: Text('Отключить'))
            else
              const PopupMenuItem(value: 'connect', child: Text('Подключить')),
            if (onSubscribers != null)
              const PopupMenuItem(value: 'subscribers', child: Text('Абоненты')),
            const PopupMenuItem(value: 'delete', child: Text('Удалить')),
          ],
        ),
      ),
    );
  }

  Widget _featChip(BuildContext context, IconData icon, String label) {
    final cs = Theme.of(context).colorScheme;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: cs.primary),
        const SizedBox(width: 3),
        Text(label, style: Theme.of(context).textTheme.labelSmall),
      ],
    );
  }
}

// ═══════════════════════════ пустое состояние ═══════════════════════════

class _EmptyProfiles extends StatelessWidget {
  const _EmptyProfiles({required this.onAdd});
  final VoidCallback onAdd;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(top: 48),
      child: Column(
        children: [
          Icon(Icons.vpn_key_outlined, size: 56, color: cs.outline),
          const SizedBox(height: 16),
          Text('Нет профилей',
              style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 4),
          Text('Добавьте citadel://-ссылку,\nчтобы подключиться к серверу',
              textAlign: TextAlign.center,
              style: Theme.of(context)
                  .textTheme
                  .bodyMedium
                  ?.copyWith(color: cs.outline)),
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: onAdd,
            icon: const Icon(Icons.add),
            label: const Text('Добавить профиль'),
          ),
        ],
      ),
    );
  }
}

// ═══════════════════════════ лист добавления профиля ═══════════════════════════

class AddProfileSheet extends StatefulWidget {
  const AddProfileSheet({super.key});

  @override
  State<AddProfileSheet> createState() => _AddProfileSheetState();
}

class _AddProfileSheetState extends State<AddProfileSheet> {
  final _link = TextEditingController();
  final _name = TextEditingController();
  LinkSummaryDto? _summary;

  void _onLinkChanged(String v) {
    final t = v.trim();
    setState(() => _summary = t.isEmpty ? null : parseLinkSummary(uri: t));
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData('text/plain');
    final t = data?.text?.trim();
    if (t != null && t.isNotEmpty) {
      _link.text = t;
      _onLinkChanged(t);
    }
  }

  /// #0.2: платформы с камерой-сканером (mobile_scanner). На Linux/Windows плагина нет → только вставка.
  static bool get _canScan =>
      Platform.isAndroid || Platform.isIOS || Platform.isMacOS;

  Future<void> _scanQr() async {
    final uri = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const QrScanPage()),
    );
    final t = uri?.trim();
    if (t != null && t.isNotEmpty && mounted) {
      _link.text = t;
      _onLinkChanged(t);
    }
  }

  void _submit() {
    final uri = _link.text.trim();
    Navigator.pop<({String name, String uri})>(
        context, (name: _name.text.trim(), uri: uri));
  }

  @override
  void dispose() {
    _link.dispose();
    _name.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final valid = _summary?.valid ?? false;
    return Padding(
      padding: EdgeInsets.only(
        left: 20,
        right: 20,
        top: 4,
        bottom: MediaQuery.of(context).viewInsets.bottom + 20,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Новый профиль',
              style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 16),
          TextField(
            controller: _link,
            onChanged: _onLinkChanged,
            minLines: 1,
            maxLines: 3,
            decoration: InputDecoration(
              labelText: 'citadel://-ссылка',
              hintText: _canScan ? 'вставьте ссылку или отсканируйте QR' : 'вставьте ссылку или QR-данные',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: const Icon(Icons.content_paste),
                tooltip: 'Вставить из буфера',
                onPressed: _paste,
              ),
            ),
          ),
          // #0.2: сканирование QR камерой — на платформах с камерой (мобильные/macOS).
          if (_canScan) ...[
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _scanQr,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Сканировать QR камерой'),
            ),
          ],
          if (_summary != null) ...[
            const SizedBox(height: 12),
            _LinkPreview(summary: _summary!),
          ],
          if (valid) ...[
            const SizedBox(height: 12),
            TextField(
              controller: _name,
              decoration: const InputDecoration(
                labelText: 'Имя профиля (необязательно)',
                hintText: 'напр. exit-nl',
                border: OutlineInputBorder(),
              ),
            ),
          ],
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: valid ? _submit : null,
            icon: const Icon(Icons.shield_outlined),
            label: const Text('Подключить и сохранить'),
          ),
          const SizedBox(height: 4),
          Text(
            'Профиль сохранится в зашифрованное хранилище после первого успешного подключения.',
            style: Theme.of(context).textTheme.bodySmall,
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

class _LinkPreview extends StatelessWidget {
  const _LinkPreview({required this.summary});
  final LinkSummaryDto summary;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    if (!summary.valid) {
      return Row(
        children: [
          Icon(Icons.error_outline, size: 18, color: cs.error),
          const SizedBox(width: 8),
          Text('Ссылка не распознана',
              style: TextStyle(color: cs.error)),
        ],
      );
    }
    final feats = <String>[
      if (summary.isAdmin) 'admin (мастер)',
      if (summary.hasPqAuth) 'PQ-auth',
      if (summary.hasObfs) 'обфускация',
      if (summary.hasPin) 'cert-pin',
      if (summary.kxSuite.isNotEmpty) 'KX: ${summary.kxSuite}',
    ];
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.dns_outlined, size: 18, color: cs.primary),
              const SizedBox(width: 8),
              Expanded(
                  child: Text(summary.servers,
                      maxLines: 1, overflow: TextOverflow.ellipsis)),
            ],
          ),
          if (feats.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Wrap(
                spacing: 6,
                runSpacing: 6,
                children: feats
                    .map((f) => Chip(
                          label: Text(f),
                          visualDensity: VisualDensity.compact,
                          materialTapTargetSize:
                              MaterialTapTargetSize.shrinkWrap,
                        ))
                    .toList(),
              ),
            ),
          // C7.4: мастер-ссылка несёт admin_seed — предупредить, что раздавать её нельзя
          // (абонентам выдаются отдельные ссылки с экрана «Абоненты»).
          if (summary.isAdmin)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Row(
                children: [
                  Icon(Icons.warning_amber_rounded, size: 16, color: cs.error),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      'Мастер-ссылка: даёт управление абонентами. Не передавайте её никому.',
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: cs.error),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

String _fmtDur(Duration d) {
  final h = d.inHours;
  final m = (d.inMinutes % 60).toString().padLeft(2, '0');
  final s = (d.inSeconds % 60).toString().padLeft(2, '0');
  return h > 0 ? '$h:$m:$s' : '$m:$s';
}

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:app/app_state.dart';
import 'package:app/src/rust/api/admin.dart';
import 'package:app/src/rust/api/citadel.dart';

/// C7.4 — экран «Абоненты» admin-профиля: Layer-1 реестр сервера по туннелю (PQ-TLS admin-канал).
/// Требует АКТИВНОЙ сессии этого профиля (admin-VIP маршрутизируется только из-под туннеля) —
/// без неё показывает гейт с кнопкой подключения. Операции самодостаточны (connect→op→close в
/// ядре); параметры канала ядро выводит из мастер-ссылки профиля, Dart их не видит.
class SubscribersPage extends StatefulWidget {
  const SubscribersPage({super.key, required this.state, required this.profile});
  final AppState state;
  final ProfileDto profile;

  @override
  State<SubscribersPage> createState() => _SubscribersPageState();
}

class _SubscribersPageState extends State<SubscribersPage> {
  List<SubscriberDto>? _entries;
  bool _busy = false;
  String? _error;

  AppState get s => widget.state;

  /// Туннель этого профиля поднят (admin-канал достижим).
  bool get _sessionUp =>
      s.activeProfileId == widget.profile.id && s.phase == VpnPhase.up;

  @override
  void initState() {
    super.initState();
    s.addListener(_onStateChanged);
    if (_sessionUp) _refresh();
  }

  @override
  void dispose() {
    s.removeListener(_onStateChanged);
    super.dispose();
  }

  /// Сессия поднялась, пока экран открыт → подтянуть список сами (не заставлять жать «Обновить»).
  void _onStateChanged() {
    if (!mounted) return;
    setState(() {});
    if (_sessionUp && _entries == null && !_busy) _refresh();
  }

  /// Обёртка операции: занятость + ошибка в баннер.
  /// Обёртка операции: занятость + ошибка в баннер. `retries` — повторы при сбое (для авто-загрузки
  /// списка: #0.1 — сразу после подъёма туннеля admin-путь к ADMIN_VIP:порт, DNAT/маршрут, может
  /// быть ещё не проложен → connect/challenge падает; короткий ретрай устраняет ложную ошибку).
  Future<T?> _run<T>(
    Future<T> Function() op, {
    int retries = 0,
    Duration delay = const Duration(milliseconds: 1500),
  }) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      for (var attempt = 0;; attempt++) {
        try {
          return await op();
        } catch (e) {
          if (attempt >= retries || !mounted) {
            if (mounted) setState(() => _error = _short('$e'));
            return null;
          }
          await Future.delayed(delay); // admin-путь после туннеля мог ещё не подняться
        }
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _refresh() async {
    // #0.1: авто-загрузка после подъёма туннеля — до 3 повторов, пока admin-путь стабилизируется.
    final list = await _run(
      () => adminSubscribers(profileId: widget.profile.id),
      retries: 3,
    );
    if (list != null && mounted) {
      // активные сверху, внутри групп — по убыванию срока (свежевыданные видны сразу)
      list.sort((a, b) {
        if (a.active != b.active) return a.active ? -1 : 1;
        return b.validUntilUnix.compareTo(a.validUntilUnix);
      });
      setState(() => _entries = list);
    }
  }

  // ─────────────────────────── выдача доступа ───────────────────────────

  Future<void> _issueDialog() async {
    final labelC = TextEditingController();
    final vuC = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: const Text('Выдать доступ'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: labelC,
              autofocus: true,
              decoration: const InputDecoration(
                labelText: 'Метка (кому)',
                hintText: 'напр. «телефон Али»',
                helperText: 'хранится только на этом устройстве',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: vuC,
              decoration: const InputDecoration(
                labelText: 'Срок (необязательно)',
                hintText: '+30d · +12h · unix · пусто = +365d',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: const Text('Отмена')),
          FilledButton(
              onPressed: () => Navigator.pop(dctx, true),
              child: const Text('Выдать')),
        ],
      ),
    );
    if (ok != true) {
      labelC.dispose();
      vuC.dispose();
      return;
    }
    final issued = await _run(() => adminIssueSubscriber(
          profileId: widget.profile.id,
          label: labelC.text.trim(),
          validUntil: vuC.text.trim(),
        ));
    final label = labelC.text.trim();
    labelC.dispose();
    vuC.dispose();
    if (issued == null || !mounted) return;
    await _showIssuedLink(issued, label);
    await _refresh();
  }

  /// Показ выданной ссылки (QR + копирование). Единственный момент, когда её можно забрать:
  /// seed абонента у админа не хранится — повторно ссылку не восстановить.
  Future<void> _showIssuedLink(IssuedLinkDto issued, String label) async {
    QrDto? qr;
    try {
      qr = linkQr(uri: issued.uri);
    } catch (_) {
      // ссылка валидна (только что собрана ядром) — QR может не влезть лишь теоретически;
      // остаётся копирование текстом
    }
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (sheetCtx) => SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                label.isEmpty ? 'Доступ выдан' : 'Доступ выдан: $label',
                style: Theme.of(sheetCtx).textTheme.titleLarge,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 4),
              Text(
                'client_id ${_shortId(issued.clientIdHex)}',
                style: Theme.of(sheetCtx)
                    .textTheme
                    .bodySmall
                    ?.copyWith(fontFamily: 'monospace'),
                textAlign: TextAlign.center,
              ),
              if (qr != null) ...[
                const SizedBox(height: 16),
                Center(child: QrView(qr: qr, dimension: 260)),
              ],
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: issued.uri));
                  ScaffoldMessenger.of(sheetCtx).showSnackBar(
                      const SnackBar(content: Text('Ссылка скопирована')));
                },
                icon: const Icon(Icons.copy),
                label: const Text('Скопировать ссылку'),
              ),
              const SizedBox(height: 8),
              Text(
                'Передайте ссылку абоненту сейчас (QR или защищённый канал). '
                'Повторно получить её нельзя: секрет абонента на этом устройстве не хранится.',
                style: Theme.of(sheetCtx).textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ─────────────────────────── отзыв ───────────────────────────

  Future<void> _revoke(SubscriberDto e) async {
    final who = e.label.isEmpty ? _shortId(e.clientIdHex) : '«${e.label}»';
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: const Text('Отозвать доступ?'),
        content: Text('Доступ $who будет отозван (status=revoked). '
            'Действует со следующего подключения, ≤ длины эпохи.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: const Text('Отмена')),
          FilledButton(
            style: FilledButton.styleFrom(
                backgroundColor: Theme.of(dctx).colorScheme.error),
            onPressed: () => Navigator.pop(dctx, true),
            child: const Text('Отозвать'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await _run(() => adminRevokeSubscriber(
        profileId: widget.profile.id, clientIdHex: e.clientIdHex));
    await _refresh();
  }

  // ─────────────────────────── UI ───────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Абоненты · ${widget.profile.name}'),
        actions: [
          IconButton(
            tooltip: 'Обновить',
            onPressed: _busy || !_sessionUp ? null : _refresh,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      floatingActionButton: !_sessionUp
          ? null
          : FloatingActionButton.extended(
              onPressed: _busy ? null : _issueDialog,
              icon: const Icon(Icons.person_add_alt),
              label: const Text('Выдать доступ'),
            ),
      body: !_sessionUp
          ? _gate(context)
          : Column(
              children: [
                if (_busy) const LinearProgressIndicator(),
                if (_error != null)
                  Container(
                    width: double.infinity,
                    color: Theme.of(context).colorScheme.errorContainer,
                    padding: const EdgeInsets.all(12),
                    child: Text(
                      _error!,
                      style: TextStyle(
                          color:
                              Theme.of(context).colorScheme.onErrorContainer),
                    ),
                  ),
                Expanded(child: _list()),
              ],
            ),
    );
  }

  /// Гейт: admin-канал живёт за туннелем — без активной сессии профиля операций нет.
  Widget _gate(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final connecting =
        s.activeProfileId == widget.profile.id && s.phase == VpnPhase.connecting;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.vpn_lock, size: 56, color: cs.outline),
            const SizedBox(height: 16),
            Text('Нужна активная сессия',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              'Управление абонентами идёт по admin-каналу внутри туннеля. '
              'Подключитесь к «${widget.profile.name}», чтобы продолжить.',
              textAlign: TextAlign.center,
              style: Theme.of(context)
                  .textTheme
                  .bodyMedium
                  ?.copyWith(color: cs.outline),
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed:
                  connecting ? null : () => s.connectProfile(widget.profile.id),
              icon: connecting
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.shield_outlined),
              label: Text(connecting ? 'Подключение…' : 'Подключить'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _list() {
    if (_entries == null) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text('Загрузка реестра…', textAlign: TextAlign.center),
        ),
      );
    }
    if (_entries!.isEmpty) {
      return const Center(
          child: Text('Реестр пуст — выдайте первый доступ.'));
    }
    return ListView.separated(
      itemCount: _entries!.length,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (_, i) {
        final e = _entries![i];
        final expired = e.validUntilUnix.toInt() * 1000 <
            DateTime.now().millisecondsSinceEpoch;
        final alive = e.active && !expired;
        return ListTile(
          leading: Icon(
            alive ? Icons.verified_user : Icons.gpp_bad,
            color: alive ? Colors.green : Colors.redAccent,
          ),
          title: e.label.isEmpty
              ? Text(_shortId(e.clientIdHex),
                  style: const TextStyle(fontFamily: 'monospace'))
              : Text(e.label, maxLines: 1, overflow: TextOverflow.ellipsis),
          subtitle: Text(
            '${e.label.isEmpty ? '' : '${_shortId(e.clientIdHex)} · '}'
            '${e.status}${expired ? ' · истёк' : ''}'
            ' · до ${_fmtDate(e.validUntilUnix.toInt())}',
          ),
          trailing: e.active
              ? IconButton(
                  tooltip: 'Отозвать',
                  icon: const Icon(Icons.block),
                  onPressed: _busy ? null : () => _revoke(e),
                )
              : null,
          onTap: () {
            Clipboard.setData(ClipboardData(text: e.clientIdHex));
            ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('client_id скопирован')));
          },
        );
      },
    );
  }

  static String _shortId(String hex) => hex.length <= 20
      ? hex
      : '${hex.substring(0, 10)}…${hex.substring(hex.length - 6)}';

  static String _fmtDate(int unix) {
    final d = DateTime.fromMillisecondsSinceEpoch(unix * 1000).toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${d.year}-${two(d.month)}-${two(d.day)}';
  }

  static String _short(String s) {
    final t = s.replaceAll('\n', ' ').trim();
    return t.length > 200 ? '${t.substring(0, 197)}…' : t;
  }
}

// ═══════════════════════════ QR-рендер ═══════════════════════════

/// QR-код из битовой матрицы ядра ([`linkQr`]) — кастомный painter, без SVG-зависимостей.
/// Всегда чёрным по белому с тихой зоной (4 модуля) — иначе сканеры в тёмной теме сбоят.
class QrView extends StatelessWidget {
  const QrView({super.key, required this.qr, required this.dimension});
  final QrDto qr;
  final double dimension;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: dimension,
      height: dimension,
      color: Colors.white,
      child: CustomPaint(painter: _QrPainter(qr)),
    );
  }
}

class _QrPainter extends CustomPainter {
  _QrPainter(this.qr);
  final QrDto qr;

  static const int _quiet = 4; // тихая зона по спецификации QR — 4 модуля с каждой стороны

  @override
  void paint(Canvas canvas, Size size) {
    final n = qr.size;
    final total = n + 2 * _quiet;
    final cell = size.width / total;
    final paint = Paint()..color = Colors.black;
    for (var y = 0; y < n; y++) {
      for (var x = 0; x < n; x++) {
        if (qr.cells[y * n + x] == 1) {
          // лёгкий overlap (+2%), чтобы антиалиасинг не рисовал белую сетку между модулями
          canvas.drawRect(
            Rect.fromLTWH((_quiet + x) * cell, (_quiet + y) * cell,
                cell * 1.02, cell * 1.02),
            paint,
          );
        }
      }
    }
  }

  @override
  bool shouldRepaint(_QrPainter old) => old.qr != qr;
}

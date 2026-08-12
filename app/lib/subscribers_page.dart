import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:app/app_state.dart';
import 'package:app/errors.dart';
import 'package:app/l10n/strings.dart';
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

  /// Номер идущей попытки и сколько их всего в текущей операции — показываем прямо на экране.
  /// Без этого ожидание было немым: попытки идут по 10–30с каждая, а человек всё это время видит
  /// одну и ту же надпись «загрузка» и не понимает, живо ли вообще что-нибудь.
  int _attempt = 0;
  int _attemptsTotal = 0;

  /// Сколько раз экран уже пытался подтянуть список САМ. Потолок обязателен: авто-загрузка
  /// висит на «сессия поднялась», а неудачная попытка оставляет `_entries == null`, поэтому
  /// каждый реконнект запускал её заново — получался бесконечный круг «загрузка → отказ →
  /// переподключение → загрузка», ровно тот, на который жалуются. Дальше — только «Обновить».
  int _autoTried = 0;
  static const _autoLimit = 2;

  /// Сколько раз потолок авто-загрузок был возвращён из-за оборвавшейся под попыткой сессии
  /// (см. [_autoRefresh]). Ограничен, чтобы мигающий туннель не давал бесконечный круг попыток.
  int _refunds = 0;
  static const _refundLimit = 2;

  AppState get s => widget.state;

  /// Строки текущего языка.
  Strings get t => Strings.of(context);

  /// Туннель этого профиля поднят (admin-канал достижим).
  bool get _sessionUp =>
      s.activeProfileId == widget.profile.id && s.phase == VpnPhase.up;

  @override
  void initState() {
    super.initState();
    s.addListener(_onStateChanged);
    if (_sessionUp) _autoRefresh();
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
    _autoRefresh();
  }

  /// Авто-загрузка списка — с потолком попыток (см. [_autoLimit]). Ручное «Обновить» потолок
  /// сбрасывает: человек нажал сам, значит, ждёт результата именно сейчас.
  ///
  /// Попытка, под которой ОБОРВАЛАСЬ сама сессия, потолок не тратит: она проверяла не admin-канал,
  /// а туннель, которого в тот момент уже не было. Именно так уходила первая из двух попыток —
  /// движок за 4с признавал путь мёртвым и переустанавливал сессию другим транспортом, а экран
  /// засчитывал себе неудачу и после второй такой же сдавался на «Обновить». Возвраты ограничены
  /// ([_refundLimit]), иначе мигающий туннель крутил бы загрузку бесконечно.
  void _autoRefresh() {
    if (!_sessionUp || _busy || _entries != null || _autoTried >= _autoLimit) return;
    _autoTried++;
    _refresh().then((_) {
      if (!mounted || _entries != null || _sessionUp || _refunds >= _refundLimit) return;
      _refunds++;
      _autoTried--;
      // Отказ был про оборвавшуюся сессию, а не про реестр: баннер с ним только пугает, пока
      // движок переподключается. Новая попытка пойдёт сама на событии «сессия поднялась».
      setState(() => _error = null);
    });
  }

  /// Потолок ожидания ОДНОЙ попытки. У ядра свои таймауты (10с connect + 15с на операцию канала),
  /// но полагаться только на них нельзя: на мобильной сети SYN в никуда, зависший TLS-хендшейк или
  /// не проложенный маршрут к VIP давали экран, который «крутится вечно» — жалоба ровно такая.
  /// Лучше честный отказ через минуту, чем бесконечный индикатор без единого слова.
  static const _opTimeout = Duration(seconds: 30);

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
      _attempt = 1;
      _attemptsTotal = retries + 1;
    });
    try {
      for (var attempt = 0;; attempt++) {
        if (mounted && attempt > 0) setState(() => _attempt = attempt + 1);
        try {
          return await op().timeout(_opTimeout);
        } catch (e) {
          if (attempt >= retries || !mounted) {
            if (mounted) {
              setState(() => _error = e is TimeoutException
                  ? t('admin_timeout')
                  : _short(humanError(e, t)));
            }
            return null;
          }
          await Future.delayed(delay); // admin-путь после туннеля мог ещё не подняться
        }
      }
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _attemptsTotal = 0;
        });
      }
    }
  }

  /// Ручное «Обновить»: потолок авто-попыток сброшен (человек ждёт результата сейчас).
  Future<void> _manualRefresh() async {
    _autoTried = 0;
    _refunds = 0;
    await _refresh();
  }

  Future<void> _refresh() async {
    // #0.1: авто-загрузка после подъёма туннеля — повтор, пока admin-путь стабилизируется
    // (DNAT/маршрут к VIP могут быть готовы на секунду позже самого туннеля). Повторов ДВА, а не
    // четыре: каждая неудачная попытка стоит до `_opTimeout`, и четыре подряд превращались в две
    // минуты немого ожидания — за это время туннель успевал переподключиться, и круг начинался
    // сначала.
    final list = await _run(
      () => adminSubscribers(profileId: widget.profile.id),
      retries: 1,
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
        title: Text(t('issue_access')),
        // Прокрутка: с поднятой клавиатурой диалогу остаётся полоска в пару сотен пикселей, и два
        // поля с подсказками в неё не влезают (та же беда, что была у листа добавления профиля).
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: labelC,
                autofocus: true,
                decoration: InputDecoration(
                  labelText: t('issue_label'),
                  hintText: t('issue_label_hint'),
                  helperText: t('issue_label_helper'),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: vuC,
                decoration: InputDecoration(
                  labelText: t('issue_valid_until'),
                  hintText: t('issue_valid_until_hint'),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: Text(t('cancel'))),
          FilledButton(
              onPressed: () => Navigator.pop(dctx, true),
              child: Text(t('issue'))),
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
                label.isEmpty
                    ? t('issued_title')
                    : t('issued_title_named', {'label': label}),
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
              // M-9: код сверки — единственное, что ловит подмену ссылки при доставке, поэтому
              // он показан крупно и рядом сказано, что диктовать его надо ОТДЕЛЬНО от ссылки.
              if (issued.verifyCode.isNotEmpty) ...[
                const SizedBox(height: 16),
                Text(
                  t('verify_code_title'),
                  style: Theme.of(sheetCtx).textTheme.labelLarge,
                  textAlign: TextAlign.center,
                ),
                SelectableText(
                  issued.verifyCode,
                  textAlign: TextAlign.center,
                  style: Theme.of(sheetCtx).textTheme.headlineSmall?.copyWith(
                        fontFamily: 'monospace',
                        letterSpacing: 2,
                      ),
                ),
                const SizedBox(height: 4),
                Text(
                  t('verify_code_note'),
                  style: Theme.of(sheetCtx).textTheme.bodySmall,
                  textAlign: TextAlign.center,
                ),
              ],
              if (issued.activateUntilUnix > 0) ...[
                const SizedBox(height: 12),
                Text(
                  t('activate_note', {'when': _fmtWhen(issued.activateUntilUnix)}),
                  style: Theme.of(sheetCtx).textTheme.bodySmall,
                  textAlign: TextAlign.center,
                ),
              ],
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: issued.uri));
                  ScaffoldMessenger.of(sheetCtx).showSnackBar(
                      SnackBar(content: Text(t('link_copied'))));
                },
                icon: const Icon(Icons.copy),
                label: Text(t('copy_link')),
              ),
              const SizedBox(height: 8),
              Text(
                t('issued_note'),
                style: Theme.of(sheetCtx).textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// Момент времени для человека: «до 10.08 12:34». Локаль не подключаем — формат числовой и
  /// одинаково читается на всех девяти языках интерфейса.
  static String _fmtWhen(int unix) {
    final d = DateTime.fromMillisecondsSinceEpoch(unix * 1000).toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    return '${two(d.day)}.${two(d.month)} ${two(d.hour)}:${two(d.minute)}';
  }

  // ─────────────────────────── отзыв ───────────────────────────

  Future<void> _revoke(SubscriberDto e) async {
    final who = e.label.isEmpty ? _shortId(e.clientIdHex) : '«${e.label}»';
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: Text(t('revoke_title')),
        content: Text(t('revoke_body', {'who': who})),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: Text(t('cancel'))),
          FilledButton(
            style: FilledButton.styleFrom(
                backgroundColor: Theme.of(dctx).colorScheme.error),
            onPressed: () => Navigator.pop(dctx, true),
            child: Text(t('revoke')),
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
        title: Text(t('subscribers_title', {'name': widget.profile.name})),
        actions: [
          // #5.4: «Выдать доступ» — в AppBar (как «Добавить профиль» на главном), не плавающей кнопкой.
          IconButton(
            tooltip: t('issue_access'),
            onPressed: _busy || !_sessionUp ? null : _issueDialog,
            icon: const Icon(Icons.person_add_alt),
          ),
          IconButton(
            tooltip: t('refresh'),
            onPressed: _busy || !_sessionUp ? null : _manualRefresh,
            icon: const Icon(Icons.refresh),
          ),
        ],
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
  ///
  /// Два РАЗНЫХ состояния, которые нельзя показывать одинаково:
  ///   * сессии нет вовсе — нужна кнопка «Подключить»;
  ///   * сессия была и восстанавливается движком (смена транспорта после мёртвого пути, смена
  ///     сети) — здесь «Нужна активная сессия» с кнопкой читается как ОТКАЗ, хотя всё идёт своим
  ///     чередом и через несколько секунд список подтянется сам. Ровно на это и жалуются: «ретраи,
  ///     затем „Нужна активная сессия“, после этого открывается».
  Widget _gate(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final mine = s.activeProfileId == widget.profile.id;
    final connecting = mine && s.phase == VpnPhase.connecting;
    final restoring = connecting && s.reconnecting;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(restoring ? Icons.autorenew : Icons.vpn_lock,
                size: 56, color: cs.outline),
            const SizedBox(height: 16),
            Text(t(restoring ? 'session_restoring' : 'need_session'),
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              t(restoring ? 'session_restoring_body' : 'need_session_body',
                  {'name': widget.profile.name}),
              textAlign: TextAlign.center,
              style: Theme.of(context)
                  .textTheme
                  .bodyMedium
                  ?.copyWith(color: cs.outline),
            ),
            const SizedBox(height: 24),
            // При восстановлении кнопки нет: движок уже подключается сам, а нажатие подняло бы
            // ВТОРУЮ сессию (ядро гасит прежнюю) — то есть отбросило бы человека назад.
            if (restoring)
              const SizedBox(
                  width: 24, height: 24, child: CircularProgressIndicator(strokeWidth: 2))
            else
              FilledButton.icon(
                onPressed:
                    connecting ? null : () => s.connectProfile(widget.profile.id),
                icon: connecting
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.shield_outlined),
                label: Text(connecting ? t('status_connecting') : t('connect')),
              ),
          ],
        ),
      ),
    );
  }

  Widget _list() {
    if (_entries == null) {
      // Попытки кончились (причина — в баннере сверху): «Загружаю реестр…» здесь было бы враньём
      // и именно оно выглядело как «висит вечно». Показываем кнопку повтора.
      if (!_busy) {
        return Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: OutlinedButton.icon(
              onPressed: _sessionUp ? _manualRefresh : null,
              icon: const Icon(Icons.refresh),
              label: Text(t('refresh')),
            ),
          ),
        );
      }
      // Номер попытки — рядом с надписью: ожидание перестаёт быть немым, а по «2/2» видно, что
      // дальше экран сам пробовать не будет.
      final counter = _attemptsTotal > 1 ? ' ($_attempt/$_attemptsTotal)' : '';
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text('${t('registry_loading')}$counter', textAlign: TextAlign.center),
        ),
      );
    }
    if (_entries!.isEmpty) {
      return Center(child: Text(t('registry_empty')));
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
            '${e.status}${expired ? ' · ${t('entry_expired')}' : ''}'
            ' · ${t('entry_until', {'date': _fmtDate(e.validUntilUnix.toInt())})}',
          ),
          trailing: e.active
              ? IconButton(
                  tooltip: t('revoke'),
                  icon: const Icon(Icons.block),
                  onPressed: _busy ? null : () => _revoke(e),
                )
              : null,
          onTap: () {
            Clipboard.setData(ClipboardData(text: e.clientIdHex));
            ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(t('client_id_copied'))));
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

  /// Однострочная форма для узкой плашки отказа. Текст сюда приходит уже человеческим (см.
  /// [humanError]) — здесь только схлопываем переносы и подрезаем длину.
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

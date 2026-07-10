import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:app/src/rust/api/admin.dart';

/// Admin-экран: управление Layer-1 реестром абонентов развёрнутого сервера по SSH.
/// Параметры подключения держим в памяти экрана; каждая операция — самодостаточный
/// SSH connect→op→close на стороне ядра (см. api/admin.rs).
class AdminRegistryPage extends StatefulWidget {
  const AdminRegistryPage({super.key});

  @override
  State<AdminRegistryPage> createState() => _AdminRegistryPageState();
}

class _AdminRegistryPageState extends State<AdminRegistryPage> {
  final _host = TextEditingController();
  final _port = TextEditingController(text: '22');
  final _user = TextEditingController(text: 'root');
  final _pass = TextEditingController();

  List<RegistryEntryDto>? _entries;
  bool _busy = false;
  String? _error;

  int get _portNum => int.tryParse(_port.text.trim()) ?? 22;
  bool get _connReady =>
      _host.text.trim().isNotEmpty && _user.text.trim().isNotEmpty && _pass.text.isNotEmpty;

  @override
  void dispose() {
    for (final c in [_host, _port, _user, _pass]) {
      c.dispose();
    }
    super.dispose();
  }

  /// Обёртка операции: занятость + ошибка в баннер + опциональный тост об успехе.
  Future<T?> _run<T>(Future<T> Function() op, {String? okMsg}) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await op();
      if (okMsg != null && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(okMsg)));
      }
      return r;
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
      return null;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _refresh() async {
    final list = await _run(() => adminRegistryList(
          host: _host.text.trim(),
          port: _portNum,
          user: _user.text.trim(),
          password: _pass.text,
        ));
    if (list != null && mounted) setState(() => _entries = list);
  }

  Future<void> _revoke(RegistryEntryDto e) async {
    final ok = await _confirm(
      'Отозвать абонента?',
      'Доступ ${_short(e.clientId)} будет отозван (status=revoked). '
          'Действует со следующего коннекта, ≤ длины эпохи.',
    );
    if (ok != true) return;
    await _run(
      () => adminRegistryRevoke(
        host: _host.text.trim(),
        port: _portNum,
        user: _user.text.trim(),
        password: _pass.text,
        clientId: e.clientId,
      ),
      okMsg: 'Абонент отозван',
    );
    await _refresh();
  }

  Future<void> _addDialog() async {
    final idC = TextEditingController();
    final vuC = TextEditingController();
    final added = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: const Text('Добавить абонента'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: idC,
              autofocus: true,
              inputFormatters: [
                FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                LengthLimitingTextInputFormatter(64),
              ],
              decoration: const InputDecoration(
                labelText: 'client_id (Ed25519 pub, 64 hex)',
                helperText: 'из citadel-token pubkey / linkgen',
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
          TextButton(onPressed: () => Navigator.pop(dctx, false), child: const Text('Отмена')),
          FilledButton(
            onPressed: idC.text.trim().length == 64 ? () => Navigator.pop(dctx, true) : null,
            child: const Text('Добавить'),
          ),
        ],
      ),
    );
    if (added != true) return;
    await _run(
      () => adminRegistryAdd(
        host: _host.text.trim(),
        port: _portNum,
        user: _user.text.trim(),
        password: _pass.text,
        clientId: idC.text.trim(),
        validUntil: vuC.text.trim(),
      ),
      okMsg: 'Абонент зарегистрирован',
    );
    await _refresh();
  }

  Future<bool?> _confirm(String title, String body) => showDialog<bool>(
        context: context,
        builder: (dctx) => AlertDialog(
          title: Text(title),
          content: Text(body),
          actions: [
            TextButton(onPressed: () => Navigator.pop(dctx, false), child: const Text('Отмена')),
            FilledButton(onPressed: () => Navigator.pop(dctx, true), child: const Text('Отозвать')),
          ],
        ),
      );

  static String _short(String hex) =>
      hex.length <= 20 ? hex : '${hex.substring(0, 10)}…${hex.substring(hex.length - 6)}';

  static String _fmtDate(int unix) {
    final d = DateTime.fromMillisecondsSinceEpoch(unix * 1000).toLocal();
    String two(int n) => n.toString().padLeft(2, '0');
    return '${d.year}-${two(d.month)}-${two(d.day)}';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Admin · реестр абонентов'),
        actions: [
          IconButton(
            tooltip: 'Обновить',
            onPressed: _busy || !_connReady ? null : _refresh,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      floatingActionButton: _entries == null
          ? null
          : FloatingActionButton.extended(
              onPressed: _busy ? null : _addDialog,
              icon: const Icon(Icons.person_add_alt),
              label: const Text('Добавить'),
            ),
      body: Column(
        children: [
          _connectionCard(),
          if (_busy) const LinearProgressIndicator(),
          if (_error != null)
            Container(
              width: double.infinity,
              color: Theme.of(context).colorScheme.errorContainer,
              padding: const EdgeInsets.all(12),
              child: Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.onErrorContainer),
              ),
            ),
          Expanded(child: _list()),
        ],
      ),
    );
  }

  Widget _connectionCard() {
    return Card(
      margin: const EdgeInsets.all(12),
      child: ExpansionTile(
        initiallyExpanded: _entries == null,
        leading: const Icon(Icons.dns_outlined),
        title: const Text('Сервер (SSH)'),
        subtitle: Text(_host.text.isEmpty ? 'не подключено' : '${_user.text}@${_host.text}:${_port.text}'),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          Row(
            children: [
              Expanded(
                flex: 3,
                child: TextField(
                  controller: _host,
                  onChanged: (_) => setState(() {}),
                  decoration: const InputDecoration(labelText: 'Хост / IP'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: TextField(
                  controller: _port,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(labelText: 'Порт'),
                ),
              ),
            ],
          ),
          TextField(
            controller: _user,
            onChanged: (_) => setState(() {}),
            decoration: const InputDecoration(labelText: 'Пользователь SSH'),
          ),
          TextField(
            controller: _pass,
            obscureText: true,
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => _connReady ? _refresh() : null,
            decoration: const InputDecoration(labelText: 'Пароль SSH'),
          ),
          const SizedBox(height: 12),
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              onPressed: _busy || !_connReady ? null : _refresh,
              icon: const Icon(Icons.login),
              label: Text(_entries == null ? 'Подключиться' : 'Обновить'),
            ),
          ),
          const Padding(
            padding: EdgeInsets.only(top: 8),
            child: Text(
              'Пароль хранится только в памяти этого экрана. Host-key принимается при первом '
              'подключении (TOFU).',
              style: TextStyle(fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _list() {
    if (_entries == null) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text('Подключитесь к серверу, чтобы увидеть абонентов.', textAlign: TextAlign.center),
        ),
      );
    }
    if (_entries!.isEmpty) {
      return const Center(child: Text('Реестр пуст — добавьте абонента.'));
    }
    return ListView.separated(
      itemCount: _entries!.length,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (_, i) {
        final e = _entries![i];
        final expired = e.validUntilUnix.toInt() * 1000 < DateTime.now().millisecondsSinceEpoch;
        return ListTile(
          leading: Icon(
            e.active && !expired ? Icons.verified_user : Icons.gpp_bad,
            color: e.active && !expired ? Colors.green : Colors.redAccent,
          ),
          title: Text(_short(e.clientId), style: const TextStyle(fontFamily: 'monospace')),
          subtitle: Text('${e.status}${expired ? " · истёк" : ""} · до ${_fmtDate(e.validUntilUnix.toInt())}'),
          trailing: e.active
              ? IconButton(
                  tooltip: 'Отозвать',
                  icon: const Icon(Icons.block),
                  onPressed: _busy ? null : () => _revoke(e),
                )
              : null,
          onTap: () {
            Clipboard.setData(ClipboardData(text: e.clientId));
            ScaffoldMessenger.of(context)
                .showSnackBar(const SnackBar(content: Text('client_id скопирован')));
          },
        );
      },
    );
  }
}

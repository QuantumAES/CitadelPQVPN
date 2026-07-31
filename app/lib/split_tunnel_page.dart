import 'dart:io';

import 'package:flutter/material.dart';

import 'package:app/android_vpn.dart';
import 'package:app/errors.dart';
import 'package:app/src/rust/api/citadel.dart';

/// C8.3 split-tunneling. Две независимые оси:
///   • по приложениям  — только выбранные через туннель / только выбранные в обход (только Android);
///   • по назначениям  — домен / IP / CIDR (в т.ч. локальная подсеть) через туннель или в обход
///     (Android + desktop Linux/Windows — единый winnet::split_routes + bypass helper'а/службы).
/// Настройка глобальная (как kill-switch), применяется со СЛЕДУЮЩЕГО подключения; хранится ядром
/// рядом с vault.
class SplitTunnelPage extends StatefulWidget {
  const SplitTunnelPage({super.key});

  @override
  State<SplitTunnelPage> createState() => _SplitTunnelPageState();
}

const _modeOff = 'off';
const _modeInclude = 'include';
const _modeExclude = 'exclude';

class _SplitTunnelPageState extends State<SplitTunnelPage> {
  String _appMode = _modeOff;
  final Set<String> _apps = {};
  String _destMode = _modeOff;
  final List<String> _dests = [];
  final _destCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    final c = splitConfig();
    _appMode = c.appMode;
    _apps.addAll(c.apps);
    _destMode = c.destMode;
    _dests.addAll(c.dests);
  }

  @override
  void dispose() {
    _destCtrl.dispose();
    super.dispose();
  }

  void _save() {
    setSplitConfig(
      cfg: SplitTunnelDto(
        appMode: _appMode,
        apps: _apps.toList(),
        destMode: _destMode,
        dests: _dests,
      ),
    );
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Сохранено · применится со следующего подключения')),
    );
    Navigator.of(context).pop();
  }

  Future<void> _pickApps() async {
    final picked = await Navigator.of(context).push<Set<String>>(
      MaterialPageRoute(builder: (_) => _AppPickerPage(initial: _apps)),
    );
    if (picked != null) {
      setState(() {
        _apps
          ..clear()
          ..addAll(picked);
      });
    }
  }

  /// Определить локальные подсети устройства (/24 из каждого не-loopback IPv4) и предложить добавить.
  /// Интерфейс САМОГО туннеля пропускаем: его подсеть — это шлюз exit'а (ADMIN_VIP, admin-канал),
  /// она обязана оставаться в туннеле, и «обход» по ней всё равно не применяется (VpnService
  /// вернёт её в маршруты). Кнопка нажимается при поднятом VPN, поэтому tun тут виден.
  Future<void> _addLocalSubnet() async {
    final subnets = <String>{};
    try {
      for (final ni in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
        if (ni.name.startsWith('tun') || ni.name.startsWith('citadel')) continue;
        for (final a in ni.addresses) {
          if (a.isLoopback) continue;
          final p = a.address.split('.');
          if (p.length == 4) subnets.add('${p[0]}.${p[1]}.${p[2]}.0/24');
        }
      }
    } catch (_) {}
    if (!mounted) return;
    if (subnets.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Локальная подсеть не определена')),
      );
      return;
    }
    setState(() {
      for (final s in subnets) {
        if (!_dests.contains(s)) _dests.add(s);
      }
    });
  }

  void _addDest() {
    final v = _destCtrl.text.trim();
    if (v.isEmpty) return;
    setState(() {
      if (!_dests.contains(v)) _dests.add(v);
      _destCtrl.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Split-туннель'),
        actions: [
          TextButton(onPressed: _save, child: const Text('Сохранить')),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: [
          // Ось приложений — только Android (нативный VpnService per-app). На Linux per-app
          // (cgroup2+fwmark) пока не реализован — показываем лишь ось назначений.
          if (Platform.isAndroid) ...[
            _sectionHeader(context, Icons.apps, 'Приложения'),
            _modeSelector(_appMode, (m) => setState(() => _appMode = m)),
            if (_appMode != _modeOff) ...[
              ListTile(
                leading: const Icon(Icons.checklist),
                title: Text('Выбрано приложений: ${_apps.length}'),
                subtitle: const Text('Нажми, чтобы выбрать из установленных'),
                trailing: const Icon(Icons.chevron_right),
                onTap: _pickApps,
              ),
              if (_apps.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                  child: Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: _apps
                        .map((p) => Chip(
                              label: Text(p, overflow: TextOverflow.ellipsis),
                              onDeleted: () => setState(() => _apps.remove(p)),
                            ))
                        .toList(),
                  ),
                ),
            ],
            const Divider(height: 24),
          ],
          _sectionHeader(context, Icons.lan_outlined, 'Адреса назначения'),
          _modeSelector(_destMode, (m) => setState(() => _destMode = m)),
          if (_destMode != _modeOff) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _destCtrl,
                      decoration: const InputDecoration(
                        labelText: 'домен / IP / CIDR',
                        hintText: 'example.com · 1.2.3.4 · 192.168.0.0/16',
                        isDense: true,
                      ),
                      onSubmitted: (_) => _addDest(),
                    ),
                  ),
                  IconButton(icon: const Icon(Icons.add), onPressed: _addDest),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(
                  icon: const Icon(Icons.wifi),
                  label: const Text('Добавить локальную подсеть'),
                  onPressed: _addLocalSubnet,
                ),
              ),
            ),
            for (final d in _dests)
              ListTile(
                dense: true,
                leading: const Icon(Icons.circle, size: 8),
                title: Text(d),
                trailing: IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: () => setState(() => _dests.remove(d)),
                ),
              ),
          ],
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              'Внимание: приложения/адреса «в обход» идут напрямую и раскрывают ваш реальный IP. '
              'Домены резолвятся при подключении; у CDN с меняющимися IP правило может «протекать» '
              'между переподключениями.'
              '${Platform.isAndroid ? ' Исключение назначений требует Android 13+.' : ''}'
              // Ось приложений есть только на Android, и DNS там делится ровно по ней: система
              // выбирает резолвер по приложению, а не по адресу. Это неочевидно и важно.
              '${Platform.isAndroid ? '\n\nDNS: приложения в туннеле резолвят через резолвер '
                  'туннеля, остальные — через DNS вашей сети (Wi-Fi/оператор), и он видит их '
                  'домены. Если в системе включён «Личный DNS» (DNS-over-TLS), Android применит '
                  'его и внутри туннеля.' : ''}',
              style: const TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ),
        ],
      ),
    );
  }

  Widget _sectionHeader(BuildContext context, IconData icon, String title) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
        child: Row(
          children: [
            Icon(icon, size: 20),
            const SizedBox(width: 8),
            Text(title, style: Theme.of(context).textTheme.titleMedium),
          ],
        ),
      );

  Widget _modeSelector(String value, ValueChanged<String> onChanged) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        child: SegmentedButton<String>(
          segments: const [
            ButtonSegment(value: _modeOff, label: Text('Выкл')),
            ButtonSegment(value: _modeInclude, label: Text('Через туннель')),
            ButtonSegment(value: _modeExclude, label: Text('В обход')),
          ],
          selected: {value},
          showSelectedIcon: false,
          onSelectionChanged: (s) => onChanged(s.first),
        ),
      );
}

/// Пикер установленных приложений (multi-select). Возвращает выбранный набор package-имён.
class _AppPickerPage extends StatefulWidget {
  const _AppPickerPage({required this.initial});
  final Set<String> initial;

  @override
  State<_AppPickerPage> createState() => _AppPickerPageState();
}

class _AppPickerPageState extends State<_AppPickerPage> {
  List<({String package, String label})>? _all;
  String? _error;
  String _filter = '';
  late final Set<String> _selected = {...widget.initial};

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final apps = await AndroidVpn.listInstalledApps();
      if (mounted) setState(() => _all = apps);
    } catch (e) {
      if (mounted) setState(() => _error = humanError(e));
    }
  }

  @override
  Widget build(BuildContext context) {
    final all = _all;
    final filtered = all == null
        ? const <({String package, String label})>[]
        : all
            .where((a) =>
                _filter.isEmpty ||
                a.label.toLowerCase().contains(_filter) ||
                a.package.toLowerCase().contains(_filter))
            .toList();
    return Scaffold(
      appBar: AppBar(
        title: const Text('Выбор приложений'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(_selected),
            child: Text('Готово (${_selected.length})'),
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: TextField(
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                labelText: 'Поиск',
                isDense: true,
              ),
              onChanged: (v) => setState(() => _filter = v.trim().toLowerCase()),
            ),
          ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text('Не удалось получить список приложений: $_error'),
            )
          else if (all == null)
            const Expanded(child: Center(child: CircularProgressIndicator()))
          else
            Expanded(
              child: ListView.builder(
                itemCount: filtered.length,
                itemBuilder: (_, i) {
                  final a = filtered[i];
                  final on = _selected.contains(a.package);
                  return CheckboxListTile(
                    value: on,
                    title: Text(a.label),
                    subtitle: Text(a.package, style: const TextStyle(fontSize: 11)),
                    onChanged: (v) => setState(() {
                      if (v == true) {
                        _selected.add(a.package);
                      } else {
                        _selected.remove(a.package);
                      }
                    }),
                  );
                },
              ),
            ),
        ],
      ),
    );
  }
}

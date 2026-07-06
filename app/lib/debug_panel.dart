import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:app/src/rust/api/diag.dart';

/// Живой журнал ядра (stderr движка захвачен в Rust — см. api::diag). Приминг снимком +
/// подписка на хвост. Используется в debug-режиме на главном экране.
class DebugLogPanel extends StatefulWidget {
  const DebugLogPanel({super.key});

  @override
  State<DebugLogPanel> createState() => _DebugLogPanelState();
}

class _DebugLogPanelState extends State<DebugLogPanel> {
  final List<String> _lines = [];
  StreamSubscription<String>? _sub;

  @override
  void initState() {
    super.initState();
    _lines.addAll(debugLogSnapshot());
    _sub = debugLogStream().listen((l) {
      if (!mounted) return;
      setState(() {
        _lines.add(l);
        if (_lines.length > 4000) {
          _lines.removeRange(0, _lines.length - 4000);
        }
      });
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MonoLogView(
      title: 'Журнал ядра',
      icon: Icons.terminal,
      lines: _lines,
      onClear: () {
        debugLogClear();
        setState(() => _lines.clear());
      },
    );
  }
}

/// Переиспользуемое поле лога: моноширинные строки, автоскролл вниз, копирование, опц. очистка.
/// Подсвечивает предупреждения/ошибки по эвристике (WARN/недоступен/таймаут/ошибка/false/MITM).
class MonoLogView extends StatefulWidget {
  const MonoLogView({
    super.key,
    required this.title,
    required this.icon,
    required this.lines,
    this.onClear,
    this.height = 240,
    this.trailing,
  });

  final String title;
  final IconData icon;
  final List<String> lines;
  final VoidCallback? onClear;
  final double height;
  final Widget? trailing;

  @override
  State<MonoLogView> createState() => _MonoLogViewState();
}

class _MonoLogViewState extends State<MonoLogView> {
  final _scroll = ScrollController();
  bool _autoscroll = true;

  @override
  void didUpdateWidget(covariant MonoLogView old) {
    super.didUpdateWidget(old);
    if (_autoscroll) _scheduleJump();
  }

  void _scheduleJump() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  Color? _lineColor(BuildContext context, String l) {
    final cs = Theme.of(context).colorScheme;
    final low = l.toLowerCase();
    if (low.contains('mitm') ||
        low.contains('ошибка') ||
        low.contains('недоступен') ||
        low.contains('failed') ||
        low.contains('✗')) {
      return cs.error;
    }
    if (low.contains('warn') ||
        low.contains('таймаут') ||
        low.contains('false')) {
      return Colors.amber.shade700;
    }
    if (low.contains('✔') || low.contains('✓')) {
      return Colors.green.shade600;
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    _scheduleJump();
    return Container(
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: cs.outlineVariant),
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 6, 4, 6),
            child: Row(
              children: [
                Icon(widget.icon, size: 16, color: cs.onSurfaceVariant),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(widget.title,
                      style: Theme.of(context).textTheme.labelLarge),
                ),
                if (widget.trailing != null) widget.trailing!,
                IconButton(
                  visualDensity: VisualDensity.compact,
                  tooltip: _autoscroll ? 'Автоскролл: вкл' : 'Автоскролл: выкл',
                  icon: Icon(_autoscroll
                      ? Icons.vertical_align_bottom
                      : Icons.pause_circle_outline),
                  onPressed: () => setState(() => _autoscroll = !_autoscroll),
                ),
                IconButton(
                  visualDensity: VisualDensity.compact,
                  tooltip: 'Копировать',
                  icon: const Icon(Icons.copy_all_outlined),
                  onPressed: () {
                    Clipboard.setData(
                        ClipboardData(text: widget.lines.join('\n')));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Лог скопирован')),
                    );
                  },
                ),
                if (widget.onClear != null)
                  IconButton(
                    visualDensity: VisualDensity.compact,
                    tooltip: 'Очистить',
                    icon: const Icon(Icons.delete_outline),
                    onPressed: widget.onClear,
                  ),
              ],
            ),
          ),
          const Divider(height: 1),
          SizedBox(
            height: widget.height,
            child: widget.lines.isEmpty
                ? Center(
                    child: Text('пусто',
                        style: TextStyle(color: cs.outline)),
                  )
                : Scrollbar(
                    controller: _scroll,
                    child: ListView.builder(
                      controller: _scroll,
                      padding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 8),
                      itemCount: widget.lines.length,
                      itemBuilder: (_, i) {
                        final l = widget.lines[i];
                        return Text(
                          l,
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 11.5,
                            height: 1.35,
                            color: _lineColor(context, l) ?? cs.onSurface,
                          ),
                        );
                      },
                    ),
                  ),
          ),
        ],
      ),
    );
  }
}

import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:app/android_vpn.dart';
import 'package:app/app_state.dart';
import 'package:app/biometric.dart';
import 'package:app/debug_panel.dart';
import 'package:app/errors.dart';
import 'package:app/format.dart';
import 'package:app/l10n/strings.dart';
import 'package:app/qr_scan_page.dart';
import 'package:app/src/rust/api/citadel.dart';
import 'package:app/split_tunnel_page.dart';
import 'package:app/subscribers_page.dart';
import 'package:app/traffic.dart';
import 'package:app/verify_code.dart';
import 'package:app/window_visibility.dart';

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

  /// Индикация трафика: текущая скорость (байт/с), посчитанная по дельте монотонных счётчиков ядра
  /// между двумя тиками. Итогов за сессию не ведём — их и не просили, а хранить историю трафика
  /// пользователя на устройстве незачем. Сам расчёт — в `lib/traffic.dart` (общий с плашкой на
  /// экране разблокировки).
  final _traffic = TrafficSampler();

  @override
  void initState() {
    super.initState();
    // C9: готовность биометрии спрашиваем у платформы (отпечаток могли добавить или удалить в
    // системных настройках между запусками) — от ответа зависит, есть ли вообще тумблер.
    unawaited(s.refreshBiometric());
    // обновляем счётчик времени сессии раз в секунду, пока подключены и пока окно видно:
    // перестраивать экран, спрятанный в трей, незачем (см. window_visibility.dart)
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (widget.state.phase == VpnPhase.up && mounted && windowVisible.value) {
        _sampleTraffic();
        setState(() {});
      }
    });
  }

  /// Снять счётчики ядра и пересчитать скорость (арифметика — в [TrafficSampler]).
  void _sampleTraffic() {
    if (!s.trafficMeter) {
      _traffic.reset();
      return;
    }
    final c = trafficCounters();
    _traffic.sample(c.rxBytes.toInt(), c.txBytes.toInt(), DateTime.now());
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  AppState get s => widget.state;

  /// Строки текущего языка (см. `lib/l10n/strings.dart`).
  Strings get t => Strings.of(context);

  // ─────────────────────────── подключение ───────────────────────────

  Future<void> _tapProfile(ProfileDto p) async {
    if (s.isBusy && s.activeProfileId == p.id) return; // уже этот профиль
    if (s.isBusy && s.activeProfileId != p.id) {
      final cur = _activeName();
      final ok = await _confirm(
        t('switch_title'),
        t('switch_body', {'current': cur, 'name': p.name}),
        confirmLabel: t('switch_confirm'),
      );
      if (ok != true) return;
      s.disconnect();
      await Future.delayed(const Duration(milliseconds: 350)); // дать helper свернуть citadel0
    }
    s.connectProfile(p.id);
  }

  String _activeName() {
    final id = s.activeProfileId;
    if (id == null) return t('new_profile_fallback');
    return s.profiles
        .firstWhere((x) => x.id == id, orElse: () => _ghost(id))
        .name;
  }

  ProfileDto _ghost(String id) => ProfileDto(
        id: id,
        name: t('profile_fallback_name'),
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
      // С клавиатурой лист занимает почти весь экран: без safe-area его шапка уезжает под
      // статус-бар/вырез (на Android это видно сразу).
      useSafeArea: true,
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
        title: t('unlock_vault'),
        action: t('unlock'),
        onSubmit: (pw) => s.unlock(pw),
      );
    }
    return await _passwordDialog(
      title: t('create_vault'),
      hint: t('vault_create_hint'),
      action: t('create'),
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
          // Замок хранилища — на главном экране, а не только в настройках: это действие «на
          // выход из-за стола», и лезть за ним в меню в такой момент неудобно. Сессию замок не
          // рвёт (см. AppState.lockVault) — прячет профили и требует пароль. Кнопка живёт в
          // AnimatedBuilder: у закрытого хранилища её быть не должно, а состояние меняется на лету.
          AnimatedBuilder(
            animation: s,
            builder: (_, _) => s.unlocked
                ? IconButton(
                    icon: const Icon(Icons.lock_outline),
                    tooltip: t('lock_vault'),
                    onPressed: s.lockVault,
                  )
                : const SizedBox.shrink(),
          ),
          // #0.3: «Добавить профиль» — в AppBar, а не FAB: плавающая кнопка перекрывала
          // popup-меню (три точки) нижних плиток профилей.
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: t('add_profile'),
            onPressed: _addProfile,
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: t('settings'),
            onPressed: _openSettings,
          ),
        ],
      ),
      body: AnimatedBuilder(
        animation: s,
        builder: (context, _) {
          // Шапка (статус + отладка + заголовок списка) — не часть перетаскиваемого списка:
          // ReorderableListView отдаёт под неё отдельный слот `header`, поэтому вложенных
          // прокруток нет и автопрокрутка при перетаскивании к краю экрана работает штатно.
          final header = Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _StatusCard(
                state: s,
                onDisconnect: s.disconnect,
                rxRate: _traffic.rxRate,
                txRate: _traffic.txRate,
              ),
              if (s.debugEnabled) ...[
                const SizedBox(height: 16),
                _DebugSection(state: s),
              ],
              const SizedBox(height: 20),
              if (s.profiles.isNotEmpty) ...[
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 4),
                  child: Text(t('profiles'),
                      style: Theme.of(context).textTheme.titleSmall),
                ),
                const SizedBox(height: 8),
              ],
            ],
          );

          if (s.profiles.isEmpty) {
            return ListView(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
              children: [header, _EmptyProfiles(onAdd: _addProfile)],
            );
          }

          // Порядок профилей меняется перетаскиванием (долгое нажатие на плитке). Кнопок
          // «выше/ниже» больше нет: на списке из нескольких профилей они требовали по нажатию
          // на позицию, а порядок всё равно хранится в vault и переживает перезапуск.
          return ReorderableListView(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
            header: header,
            // Свои «ручки»: дефолтные на desktop рисуют иконку-хват поверх плитки (там уже меню
            // «три точки»), а тащить начинают с первого же движения мыши — по случайному сдвигу
            // при попытке нажать. Нам нужен один и тот же жест везде: долгое нажатие.
            buildDefaultDragHandles: false,
            onReorderStart: (_) => HapticFeedback.mediumImpact(),
            proxyDecorator: _dragProxy,
            onReorderItem: _onReorder,
            children: [
              for (final (i, p) in s.profiles.indexed)
                ReorderableDelayedDragStartListener(
                  key: ValueKey(p.id),
                  index: i,
                  child: _ProfileTile(
                    profile: p,
                    active: s.activeProfileId == p.id,
                    phase: s.phase,
                    busy: s.isBusy,
                    onTap: () => _tapProfile(p),
                    onDelete: () => _deleteProfile(p),
                    onDisconnect: s.disconnect,
                    onRename: () => _renameProfile(p),
                    onSubscribers:
                        p.isAdmin ? () => _openSubscribers(p) : null,
                  ),
                ),
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
      t('delete_profile_title'),
      t('delete_profile_body', {'name': p.name}),
      confirmLabel: t('delete'),
      destructive: true,
    );
    if (ok == true) s.removeProfile(p.id);
  }

  /// Переименовать профиль. Имя — только вывеска в списке: ссылка, ключи и порядок не меняются.
  /// Отказ ядра (пустое имя, закрытое хранилище) показываем прямо в форме, а не тостом вдогонку.
  Future<void> _renameProfile(ProfileDto p) async {
    final ctrl = TextEditingController(text: p.name);
    final maxLen = vaultMaxNameLen();
    final done = await showDialog<bool>(
      context: context,
      builder: (dctx) {
        String? err;
        return StatefulBuilder(builder: (dctx, setLocal) {
          void submit() {
            try {
              s.renameProfile(p.id, ctrl.text);
              Navigator.pop(dctx, true);
            } catch (e) {
              setLocal(() => err = humanError(e));
            }
          }

          return AlertDialog(
            title: Text(t('rename_profile')),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextField(
                    controller: ctrl,
                    autofocus: true,
                    maxLength: maxLen,
                    onSubmitted: (_) => submit(),
                    decoration: InputDecoration(
                      labelText: t('profile_name'),
                      border: const OutlineInputBorder(),
                    ),
                  ),
                  if (err != null) ...[
                    const SizedBox(height: 4),
                    ErrorNote(text: err!),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(dctx, false),
                  child: Text(t('cancel'))),
              FilledButton(onPressed: submit, child: Text(t('save'))),
            ],
          );
        });
      },
    );
    ctrl.dispose();
    if (done == true) _toast(t('profile_renamed'));
  }

  /// Перетаскивание профиля завершено (`onReorderItem` уже привёл `newIndex` к координатам списка
  /// ПОСЛЕ изъятия перетаскиваемого элемента — поправка на «съехавший» индекс не нужна).
  /// Порядок хранится в vault, поэтому переживает перезапуск.
  void _onReorder(int oldIndex, int newIndex) {
    if (oldIndex == newIndex) return;
    final p = s.profiles[oldIndex];
    try {
      s.moveProfileTo(p.id, newIndex);
    } catch (e) {
      _toast(humanError(e));
    }
  }

  /// Вид «оторванной» плитки под пальцем: чуть приподнята и увеличена. Мини-анимация нужна не для
  /// красоты — она отвечает на вопрос «режим перетаскивания включился или я просто держу палец»,
  /// который иначе решается только пробным движением. Дефолтный декоратор поднимает только тень.
  Widget _dragProxy(Widget child, int index, Animation<double> animation) {
    return AnimatedBuilder(
      animation: animation,
      builder: (context, c) {
        final k = Curves.easeOut.transform(animation.value);
        return Transform.scale(
          scale: 1 + 0.04 * k,
          child: Material(
            color: Colors.transparent,
            elevation: 8 * k,
            shadowColor: Theme.of(context).colorScheme.shadow,
            borderRadius: BorderRadius.circular(12),
            child: c,
          ),
        );
      },
      child: child,
    );
  }

  // ─────────────────────────── настройки ───────────────────────────

  void _openSettings() {
    showModalBottomSheet(
      context: context,
      showDragHandle: true,
      isScrollControlled: true, // #п3: снять дефолтный лимит высоты (9/16 экрана) → все пункты видны
      builder: (sheetCtx) => SafeArea(
        child: SingleChildScrollView( // fallback: скролл только если пунктов больше, чем влезает
          child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (s.unlocked) ...[
              ListTile(
                leading: const Icon(Icons.password_outlined),
                title: Text(t('change_password')),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  _changePassword();
                },
              ),
              ListTile(
                leading: const Icon(Icons.lock_outline),
                title: Text(t('lock_vault')),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  s.lockVault();
                },
              ),
              // C9: вход по отпечатку. Показываем только там, где он реально работает — платформа
              // умеет И в устройстве есть зарегистрированный отпечаток сильного класса. Тумблер
              // рядом со сменой пароля, потому что это ровно тот же вопрос: как открывается
              // хранилище. Дефолт — выключено: палец прикладывают под принуждением, пароль — нет.
              if (s.biometricOffered)
                SwitchListTile(
                  secondary: const Icon(Icons.fingerprint),
                  title: Text(t('biometric_title')),
                  subtitle: Text(t('biometric_sub')),
                  value: s.biometricEnrolled,
                  onChanged: (on) {
                    Navigator.pop(sheetCtx); // системный диалог отпечатка — поверх, без шторки
                    _toggleBiometric(on: on);
                  },
                ),
            ],
            // Индикация трафика: только текущая скорость на плашке подключения, без итогов.
            // По умолчанию выключена — лишняя строка на главном экране нужна не всем.
            SwitchListTile(
              secondary: const Icon(Icons.speed_outlined),
              title: Text(t('traffic_meter_title')),
              subtitle: Text(t('traffic_meter_sub')),
              value: s.trafficMeter,
              onChanged: (_) {
                s.toggleTrafficMeter();
                Navigator.pop(sheetCtx);
              },
            ),
            // M-8/П7: маскировка таймингов — три профиля, а не тумблер. Подпись называет ВЫБРАННЫЙ
            // профиль и его цену: маскировка стоит трафика и заряда, и человек вправе знать
            // сколько, прежде чем включать (прежний тумблер не сообщал ни цены, ни того, что в
            // простое маскировать нечего).
            ListTile(
              leading: const Icon(Icons.blur_on_outlined),
              title: Text(t('pacing_title')),
              subtitle: Text(t(_pacingSubKey(s.pacing))),
              onTap: () {
                Navigator.pop(sheetCtx);
                _pickPacing();
              },
            ),
            SwitchListTile(
              secondary: const Icon(Icons.bug_report_outlined),
              title: Text(t('debug_title')),
              subtitle: Text(t('debug_sub')),
              value: s.debugEnabled,
              onChanged: (_) {
                s.toggleDebug();
                Navigator.pop(sheetCtx);
              },
            ),
            // C8.5 запрет скриншотов — по умолчанию включён. Показываем там, где он реально
            // применяется: Android (FLAG_SECURE) и Windows (SetWindowDisplayAffinity). На Linux
            // такого механизма нет, и тумблер обещал бы несуществующую защиту.
            if (AppState.screenshotBlockSupported)
              SwitchListTile(
                secondary: const Icon(Icons.screenshot_monitor_outlined),
                title: Text(t('screenshot_title')),
                subtitle: Text(t('screenshot_sub')),
                value: s.screenshotBlock,
                onChanged: (_) {
                  s.toggleScreenshotBlock();
                  Navigator.pop(sheetCtx);
                },
              ),
            // Kill-switch — на десктопе тумблер (Linux-хелпер через firewall); на Android это
            // СИСТЕМНЫЙ always-on+lockdown (приложение не может форсить), поэтому — гайд в настройки.
            if (!Platform.isAndroid && !Platform.isIOS)
              SwitchListTile(
                secondary: const Icon(Icons.shield_outlined),
                title: Text(t('killswitch_title')),
                subtitle: Text(t('killswitch_sub')),
                value: s.killswitch,
                onChanged: (_) {
                  s.toggleKillswitch();
                  Navigator.pop(sheetCtx);
                },
              ),
            if (Platform.isAndroid)
              ListTile(
                leading: const Icon(Icons.shield_outlined),
                title: Text(t('killswitch_android_title')),
                subtitle: Text(t('killswitch_android_sub')),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  _showAlwaysOnGuide();
                },
              ),
            // C8.3 split-tunnel — Android (приложения+назначения); Linux/Windows (только назначения:
            // единый winnet::split_routes + bypass привилегированной части — helper/служба).
            if (Platform.isAndroid || Platform.isLinux || Platform.isWindows)
              ListTile(
                leading: const Icon(Icons.alt_route),
                title: Text(t('split_title')),
                subtitle: Text(Platform.isAndroid
                    ? t('split_sub_android')
                    : t('split_sub_desktop')),
                onTap: () {
                  Navigator.pop(sheetCtx);
                  Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const SplitTunnelPage()),
                  );
                },
              ),
            // Admin (C7.4): реестр абонентов живёт в меню admin-профиля («Абоненты»), не здесь —
            // операции идут по туннелю этого профиля, SSH-путь удалён.
            // Где лежит файл хранилища. Не мелочь: разбор жалобы «пароль не меняется» на Windows
            // упёрся именно в то, что путь был не виден, а зависел от того, откуда запущен процесс.
            // Тап — копирует путь (в поддержку/для проверки прав на папку).
            ListTile(
              leading: const Icon(Icons.folder_outlined),
              title: Text(t('vault_location_title')),
              subtitle: Text(vaultLocation(), style: const TextStyle(fontSize: 11)),
              onTap: () async {
                await Clipboard.setData(ClipboardData(text: vaultLocation()));
                if (sheetCtx.mounted) Navigator.pop(sheetCtx);
                _toast(t('vault_path_copied'));
              },
            ),
            // Язык интерфейса. Выбор пользователя, а не системная локаль: клиент часто ставят на
            // чужом или рабочем устройстве, где локаль не та, на которой человек читает.
            ListTile(
              leading: const Icon(Icons.language),
              title: Text(t('language_title')),
              subtitle: Text(langLabel(s.lang)),
              onTap: () {
                Navigator.pop(sheetCtx);
                _pickLanguage();
              },
            ),
            ListTile(
              leading: const Icon(Icons.info_outline),
              title: Text(t('about_title')),
              subtitle: Text(t('about_sub', {'version': appVersion})),
              onTap: () {
                Navigator.pop(sheetCtx);
                _showAbout();
              },
            ),
          ],
        ),
        ),
      ),
    );
  }

  /// П7: ключ подписи под выбранным профилем маскировки — она же и есть честная цена настройки.
  static String _pacingSubKey(String profile) => switch (profile) {
        kPacingLite => 'pacing_lite_sub',
        kPacingStrict => 'pacing_strict_sub',
        _ => 'pacing_off_sub',
      };

  /// Выбор профиля маскировки таймингов. Три состояния вместо тумблера: у маскировки есть цена в
  /// мегабайтах и заряде, и она разная. Рядом с выбором — строка о главном свойстве, которое
  /// раньше нигде не было сказано: маскировка работает, пока идёт трафик, а в простое молчит.
  Future<void> _pickPacing() async {
    final picked = await showDialog<String>(
      context: context,
      builder: (dctx) => RadioGroup<String>(
        groupValue: s.pacing,
        onChanged: (v) => Navigator.pop(dctx, v),
        child: SimpleDialog(
          title: Text(Strings.of(dctx)('pacing_title')),
          children: [
            for (final (value, titleKey, subKey) in const [
              (kPacingOff, 'pacing_off', 'pacing_off_sub'),
              (kPacingLite, 'pacing_lite', 'pacing_lite_sub'),
              (kPacingStrict, 'pacing_strict', 'pacing_strict_sub'),
            ])
              RadioListTile<String>(
                value: value,
                title: Text(Strings.of(dctx)(titleKey)),
                subtitle: Text(Strings.of(dctx)(subKey)),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 8, 24, 16),
              child: Text(
                Strings.of(dctx)('pacing_note'),
                style: Theme.of(dctx).textTheme.bodySmall,
              ),
            ),
          ],
        ),
      ),
    );
    if (picked != null && picked != s.pacing) s.setPacing(picked);
  }

  /// Выбор языка интерфейса. Языки перечислены на самих себе («Deutsch», «हिन्दी») — человек ищет
  /// в списке свой язык, а не перевод его названия на текущий. Выбор применяется сразу (весь
  /// MaterialApp перестраивается) и сохраняется ядром рядом с хранилищем.
  Future<void> _pickLanguage() async {
    final picked = await showDialog<String>(
      context: context,
      builder: (dctx) => RadioGroup<String>(
        groupValue: s.lang,
        onChanged: (v) => Navigator.pop(dctx, v),
        child: SimpleDialog(
          title: Text(Strings.of(dctx)('language_title')),
          children: [
            for (final code in kSupportedLocales.map((l) => l.languageCode))
              RadioListTile<String>(
                value: code,
                title: Text(langLabel(code)),
              ),
          ],
        ),
      ),
    );
    if (picked != null) s.setLang(picked);
  }

  /// «О приложении»: что это, чем отличается, какая версия. Версии — двумя строками и с
  /// возможностью скопировать: при разборе жалобы первым делом спрашивают именно их, а сборка
  /// приложения и версия ядра расходятся (ядро обновляется отдельно от оболочки).
  Future<void> _showAbout() async {
    final core = coreVersion();
    // Строка «для поддержки»: её копируют в переписку, поэтому собираем её из тех же
    // локализованных кусков, что показаны в диалоге, — чтобы человек прислал ровно то, что видит.
    final versions =
        'CitadelPQVPN $appVersion · ${t('about_core_version', {'version': core})}';
    await showDialog<void>(
      context: context,
      builder: (dctx) {
        final cs = Theme.of(dctx).colorScheme;
        return AlertDialog(
          title: Row(
            children: [
              Image.asset('assets/logo.png', width: 32, height: 32),
              const SizedBox(width: 12),
              const Expanded(child: Text('CitadelPQVPN')),
            ],
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  t('about_body'),
                  style: Theme.of(dctx).textTheme.bodyMedium,
                ),
                const SizedBox(height: 16),
                Text(t('about_version'), style: Theme.of(dctx).textTheme.labelLarge),
                const SizedBox(height: 4),
                Text(t('about_app_version', {'version': appVersion}),
                    style: Theme.of(dctx).textTheme.bodySmall?.copyWith(color: cs.outline)),
                Text(t('about_core_version', {'version': core}),
                    style: Theme.of(dctx).textTheme.bodySmall?.copyWith(color: cs.outline)),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: versions));
                if (dctx.mounted) Navigator.pop(dctx);
                _toast(t('version_copied'));
              },
              child: Text(t('copy_version')),
            ),
            FilledButton(
                onPressed: () => Navigator.pop(dctx), child: Text(t('close'))),
          ],
        );
      },
    );
  }

  /// Android kill-switch = системный always-on+lockdown: объясняем и ведём в настройки VPN.
  Future<void> _showAlwaysOnGuide() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: Text(t('killswitch_android_title')),
        content: Text(t('alwayson_body')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(dctx, false), child: Text(t('close'))),
          FilledButton(
            onPressed: () => Navigator.pop(dctx, true),
            child: Text(t('open_settings')),
          ),
        ],
      ),
    );
    if (ok == true) await AndroidVpn.openVpnSettings();
  }

  /// Смена мастер-пароля. Диалог не закрывается, пока ядро не подтвердит успех: отказ показывается
  /// прямо в форме и ТЕМ текстом, который вернуло ядро. Прежняя версия закрывалась сразу и писала
  /// в тосте «текущий пароль неверен» на любую ошибку — в том числе на слишком короткий новый
  /// пароль и на отказ записи файла, из-за чего смена выглядела сломанной при верном пароле.
  Future<void> _changePassword() async {
    final oldC = TextEditingController();
    final newC = TextEditingController();
    final new2C = TextEditingController();
    final minLen = vaultMinPasswordLen();
    final done = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (dctx) {
        String? err;
        bool busy = false;
        return StatefulBuilder(builder: (dctx, setLocal) {
          Future<void> submit() async {
            if (oldC.text.isEmpty) {
              setLocal(() => err = t('enter_current_password'));
              return;
            }
            if (newC.text.characters.length < minLen) {
              setLocal(() => err = t('new_password_too_short', {'n': '$minLen'}));
              return;
            }
            if (newC.text != new2C.text) {
              setLocal(() => err = t('new_passwords_mismatch'));
              return;
            }
            setLocal(() {
              busy = true;
              err = null;
            });
            try {
              await s.changePassword(oldC.text, newC.text);
              if (dctx.mounted) Navigator.pop(dctx, true);
            } catch (e) {
              setLocal(() {
                busy = false;
                err = humanError(e, t);
              });
            }
          }

          return AlertDialog(
            title: Text(t('change_password')),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextField(
                    controller: oldC,
                    autofocus: true,
                    obscureText: true,
                    enabled: !busy,
                    decoration: InputDecoration(labelText: t('current_password')),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: newC,
                    obscureText: true,
                    enabled: !busy,
                    decoration: InputDecoration(
                      labelText: t('new_password'),
                      helperText: t('password_min', {'n': '$minLen'}),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: new2C,
                    obscureText: true,
                    enabled: !busy,
                    onSubmitted: busy ? null : (_) => submit(),
                    decoration: InputDecoration(labelText: t('new_password_repeat')),
                  ),
                  if (err != null) ...[
                    const SizedBox(height: 12),
                    ErrorNote(text: err!),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: busy ? null : () => Navigator.pop(dctx, false),
                child: Text(t('cancel')),
              ),
              FilledButton(
                onPressed: busy ? null : submit,
                child: busy
                    ? const SizedBox(
                        height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : Text(t('change')),
              ),
            ],
          );
        });
      },
    );
    if (done == true) _toast(t('password_changed'));
    oldC.dispose();
    newC.dispose();
    new2C.dispose();
  }

  // ─────────────────────────── общие диалоги ───────────────────────────

  Future<bool?> _confirm(String title, String body,
      {String confirmLabel = 'OK', bool destructive = false}) {
    final t = this.t;
    return showDialog<bool>(
      context: context,
      builder: (dctx) => AlertDialog(
        title: Text(title),
        content: Text(body),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(dctx, false),
              child: Text(t('cancel'))),
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
  ///
  /// Ошибку показываем отдельным блоком с переносом строк, а не в `errorText` поля: тот однострочный
  /// и обрезал сообщение — ровно поэтому «не видно сообщение об ошибке полностью» при первой
  /// установке пароля. Текст берём человеческий ([`humanError`]), без служебной обёртки FFI.
  Future<bool> _passwordDialog({
    required String title,
    required String action,
    required Future<void> Function(String) onSubmit,
    String? hint,
    bool confirm = false,
  }) async {
    final pw = TextEditingController();
    final pw2 = TextEditingController();
    final minLen = vaultMinPasswordLen();
    final ok = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (dctx) {
        String? err;
        bool busy = false;
        return StatefulBuilder(builder: (dctx, setLocal) {
          Future<void> submit() async {
            if (pw.text.isEmpty) {
              setLocal(() => err = t('password_empty'));
              return;
            }
            // Политику длины проверяем здесь же: то же число, что enforce'ит ядро (оно и отдаёт
            // его через FFI), но человек узнаёт о ней сразу, а не после Argon2-derive. Только при
            // создании: у существующего хранилища пароль мог быть задан прежней политикой.
            if (confirm && pw.text.characters.length < minLen) {
              setLocal(() => err = t('password_too_short', {'n': '$minLen'}));
              return;
            }
            if (confirm && pw.text != pw2.text) {
              setLocal(() => err = t('passwords_mismatch'));
              return;
            }
            setLocal(() {
              busy = true;
              err = null;
            });
            try {
              await onSubmit(pw.text);
              if (dctx.mounted) Navigator.pop(dctx, true);
            } catch (e) {
              setLocal(() {
                busy = false;
                err = humanError(e, t);
              });
            }
          }

          return AlertDialog(
            title: Text(title),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
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
                    enabled: !busy,
                    decoration: InputDecoration(
                      labelText: t('password'),
                      helperText: confirm ? t('password_min', {'n': '$minLen'}) : null,
                    ),
                    onSubmitted: confirm || busy ? null : (_) => submit(),
                  ),
                  if (confirm) ...[
                    const SizedBox(height: 12),
                    TextField(
                      controller: pw2,
                      obscureText: true,
                      enabled: !busy,
                      decoration:
                          InputDecoration(labelText: t('password_repeat')),
                      onSubmitted: busy ? null : (_) => submit(),
                    ),
                  ],
                  if (err != null) ...[
                    const SizedBox(height: 12),
                    ErrorNote(text: err!),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                  onPressed: busy ? null : () => Navigator.pop(dctx, false),
                  child: Text(t('cancel'))),
              FilledButton(
                onPressed: busy ? null : submit,
                child: busy
                    ? const SizedBox(
                        height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                    : Text(action),
              ),
            ],
          );
        });
      },
    );
    pw.dispose();
    pw2.dispose();
    return ok ?? false;
  }

  /// C9: включить/выключить вход по отпечатку. Включение спрашивает палец (иначе мы завернули бы
  /// ключ в Keystore, ни разу не проверив, что человек вообще может им пользоваться), выключение —
  /// нет: отзывать себе доступ человек должен свободно и мгновенно.
  Future<void> _toggleBiometric({required bool on}) async {
    try {
      if (on) {
        await s.enableBiometric(BiometricTexts(
          title: 'CitadelPQVPN',
          subtitle: t('biometric_prompt_enable'),
          cancel: t('cancel'),
        ));
      } else {
        await s.disableBiometric();
      }
    } on BiometricFailure catch (e) {
      if (e.cancelled) return; // отмену комментировать не нужно
      debugPrint('[biometric] $e'); // код платформы — в журнал, не в лицо человеку
      _toast(e.keyGone ? t('biometric_key_gone') : t('biometric_failed'));
    } catch (e) {
      _toast(humanError(e)); // отказ ядра (не записалось хранилище) — уже человеческая фраза
    }
  }

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
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

  /// Строки текущего языка.
  Strings get t => Strings.of(context);

  /// Профиль для диагностики: активный, иначе тот, с которым работали последним, и лишь затем
  /// первый в списке. Средняя ступень принципиальна: диагностику запускают ПОСЛЕ неудачной
  /// попытки, когда активного профиля уже нет, — и без неё проверялся первый профиль списка,
  /// то есть совсем другой сервер.
  String? get _targetId =>
      s.activeProfileId ??
      s.lastProfileId ??
      (s.profiles.isNotEmpty ? s.profiles.first.id : null);

  void _run() {
    final id = _targetId;
    if (id == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(t('diag_no_profile'))),
      );
      return;
    }
    _sub?.cancel();
    // Профиль называем в первой же строке: вывод диагностики читают как приговор серверу, и он
    // обязан говорить, КАКОЙ сервер проверяли. Профилей у человека несколько, они отличаются
    // версией и адресом — молчаливая проверка «какого-то» из них дезориентирует сильнее, чем
    // отсутствие диагностики.
    final name = s.profileName(id);
    setState(() {
      _diag
        ..clear()
        ..add(name.isEmpty ? '▶ ${t('diag_start')}' : '▶ ${t('diag_start')} · $name');
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
            _diag.add('✗ ${t('diag_aborted', {'error': '$e'})}');
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
                label: Text(_running ? t('diag_running') : t('diag_run')),
              ),
            ),
          ],
        ),
        if (_diag.isNotEmpty) ...[
          const SizedBox(height: 12),
          MonoLogView(
            title: t('diag_title'),
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
  const _StatusCard({
    required this.state,
    required this.onDisconnect,
    this.rxRate = 0,
    this.txRate = 0,
  });
  final AppState state;
  final VoidCallback onDisconnect;

  /// Текущая скорость приёма/передачи, байт/с (0, если индикация выключена или сессии нет).
  final double rxRate, txRate;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final t = Strings.of(context);
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
        label = t('status_protected');
      case VpnPhase.connecting:
        bg = (dark ? Colors.amber.shade900 : Colors.amber.shade50);
        fg = (dark ? Colors.amber.shade200 : Colors.amber.shade900);
        icon = Icons.shield_outlined;
        label = t('status_connecting');
        lead = SizedBox(
          height: 22,
          width: 22,
          child: CircularProgressIndicator(strokeWidth: 2.4, color: fg),
        );
      case VpnPhase.error:
        bg = cs.errorContainer;
        fg = cs.onErrorContainer;
        icon = Icons.gpp_bad_outlined;
        // Человеку — что произошло, а не текст ошибки движка: подробности (полная цепочка
        // причин) остаются в журнале отладки, кому надо — посмотрит там.
        // errorTitle — КЛЮЧ строки (см. AppState._classify): переводим при отрисовке, поэтому
        // смена языка меняет и уже показанный отказ.
        label = t(state.errorTitle.isEmpty ? 'err_server_unreachable' : state.errorTitle);
        // Движок после отказа НЕ сдаётся — он ждёт и пробует снова, пока его не остановят.
        // Без этого индикатора экран выглядел как окончательный приговор, хотя попытки идут:
        // человек закрывал окно (на Windows — в трей) и оставлял цикл работать вслепую.
        if (state.sessionLive) {
          lead = SizedBox(
            height: 22,
            width: 22,
            child: CircularProgressIndicator(strokeWidth: 2.4, color: fg),
          );
        }
      case VpnPhase.off:
        bg = cs.surfaceContainerHighest;
        fg = cs.onSurfaceVariant;
        icon = Icons.lock_open_outlined;
        label = t('status_unprotected');
    }

    // Что показываем о живой сессии: узел выхода и транспорт. Ни номера порта, ни назначенного
    // нам внутреннего адреса с маской (`state.cidr`) здесь нет — человеку они бесполезны, а
    // скриншот главного экрана перестаёт выдавать конфигурацию сервера и адрес клиента.
    // Для разбора всё это по-прежнему в журнале отладки и диагностике.
    final details = <String>[
      if (state.exit.isNotEmpty) hostOnly(state.exit),
      if (state.transport.isNotEmpty) state.transport,
    ].join('  ·  ');

    // В отказе показываем ПРОФИЛЬ, к которому пытались подключиться, и подсказку по этому виду
    // отказа — сам текст ошибки ядра здесь не показываем (он в журнале отладки).
    final name = state.activeProfileName;
    final failure = <String>[
      if (name.isNotEmpty) t('status_profile_named', {'name': name}),
      if (state.errorHint.isNotEmpty) t(state.errorHint),
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
          if (details.isNotEmpty || state.phase == VpnPhase.error) ...[
            const SizedBox(height: 6),
            // По центру: строка «узел · транспорт» относится ко всей плашке, а не к иконке слева,
            // и в узком портретном окне выключка по левому краю смотрелась обрывком.
            SizedBox(
              width: double.infinity,
              child: Text(
                state.phase == VpnPhase.error ? failure : details,
                textAlign: TextAlign.center,
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: fg.withValues(alpha: 0.9)),
              ),
            ),
          ],
          // Индикация трафика (настройка «Показывать индикацию трафика», по умолчанию выключена):
          // только текущая скорость, без итогов за сессию. Показываем на поднятом туннеле —
          // на «подключении» цифры были бы нулями, а место на плашке уже занято.
          if (state.trafficMeter && state.phase == VpnPhase.up) ...[
            const SizedBox(height: 10),
            TrafficRow(rxRate: rxRate, txRate: txRate, fg: fg, t: t),
          ],
          if (state.isBusy) ...[
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: onDisconnect,
                icon: const Icon(Icons.power_settings_new),
                label: Text(t('disconnect')),
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
    required this.busy,
    required this.onTap,
    required this.onDelete,
    required this.onDisconnect,
    required this.onRename,
    this.onSubscribers,
  });
  final ProfileDto profile;
  final bool active;
  final VpnPhase phase;
  /// Сессия ядра жива (см. `AppState.isBusy`). Отдельно от `phase`: во время бесконечного
  /// реконнекта фаза показывает причину последнего отказа, но останавливать по-прежнему есть что.
  final bool busy;
  final VoidCallback onTap;
  final VoidCallback onDelete;
  final VoidCallback onDisconnect;
  final VoidCallback onRename;
  /// C7.4: открыть экран абонентов (не null только у admin-профиля).
  final VoidCallback? onSubscribers;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final t = Strings.of(context);
    Color dot;
    if (active && phase == VpnPhase.up) {
      dot = Colors.green;
    } else if (active && busy) {
      // Не только `connecting`: во время бесконечного реконнекта фаза = отказ последней попытки,
      // но профиль всё ещё занят сессией — точка обязана это показывать.
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
      // (admin/PQ-auth/obfs/pin — короткие технические метки, одинаковые на всех языках)
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
            // Адреса серверов — без портов (см. format.dart): номер порта человеку ничего не
            // говорит, а список на экране выдаёт конфигурацию exit'ов.
            if (profile.servers.isNotEmpty)
              Text(hostsOnly(profile.servers),
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
            switch (v) {
              case 'delete':
                onDelete();
              case 'connect':
                onTap();
              case 'disconnect':
                onDisconnect();
              case 'subscribers':
                onSubscribers?.call();
              case 'rename':
                onRename();
            }
          },
          itemBuilder: (_) => [
            if (active && busy)
              PopupMenuItem(value: 'disconnect', child: Text(t('disconnect')))
            else
              PopupMenuItem(value: 'connect', child: Text(t('connect'))),
            if (onSubscribers != null)
              PopupMenuItem(value: 'subscribers', child: Text(t('subscribers'))),
            PopupMenuItem(value: 'rename', child: Text(t('rename'))),
            // Порядок списка меняется перетаскиванием (долгое нажатие на плитке) — пунктов
            // «переместить выше/ниже» здесь больше нет.
            PopupMenuItem(value: 'delete', child: Text(t('delete'))),
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
    final t = Strings.of(context);
    return Padding(
      padding: const EdgeInsets.only(top: 48),
      child: Column(
        children: [
          Icon(Icons.vpn_key_outlined, size: 56, color: cs.outline),
          const SizedBox(height: 16),
          Text(t('no_profiles'),
              style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 4),
          Text(t('no_profiles_hint'),
              textAlign: TextAlign.center,
              style: Theme.of(context)
                  .textTheme
                  .bodyMedium
                  ?.copyWith(color: cs.outline)),
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: onAdd,
            icon: const Icon(Icons.add),
            label: Text(t('add_profile')),
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
  /// M-9: код сверки, который абоненту назвал администратор ДРУГИМ каналом (голосом, при встрече).
  final _code = TextEditingController();
  LinkSummaryDto? _summary;

  /// Пауза после последнего нажатия, по истечении которой ссылку отдаём на проверку. Без неё
  /// вердикт «ссылка не распознана» выскакивал на КАЖДЫЙ символ недописанной ссылки: и раздражает,
  /// и превращает разбор в посимвольный оракул (проверка в ядре к тому же ограничивает темп).
  static const _debounce = Duration(milliseconds: 500);
  Timer? _pending;

  /// Текст, к которому относится идущая проверка: ответ на устаревший текст выбрасываем (проверка
  /// небыстрая, а пользователь за это время мог дописать ссылку).
  String _checking = '';
  bool _busy = false;

  void _onLinkChanged(String v) {
    _pending?.cancel();
    final t = v.trim();
    if (t.isEmpty) {
      setState(() {
        _summary = null;
        _busy = false;
      });
      return;
    }
    // Пока не проверили — ни «валидна», ни «не распознана»: показываем ожидание.
    setState(() {
      _summary = null;
      _busy = true;
    });
    _pending = Timer(_debounce, () => _check(t));
  }

  Future<void> _check(String uri) async {
    _checking = uri;
    final res = await parseLinkSummary(uri: uri);
    if (!mounted || _checking != uri) return; // ответ на уже неактуальный текст
    setState(() {
      _summary = res;
      _busy = false;
    });
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

  /// Ссылка требует сверки кода по другому каналу: только ПЕРВИЧНЫЕ (одноразовые) ссылки — у них
  /// код показал администратор при выдаче. Ранее розданные (многоразовые) ссылки кода не имеют,
  /// и требовать его значило бы запереть уже работающих абонентов.
  bool get _needsCode => (_summary?.isEnroll ?? false) && (_summary?.verifyCode ?? '').isNotEmpty;

  /// Введённый код совпал с кодом самой ссылки (правила сравнения — `lib/verify_code.dart`).
  bool get _codeOk =>
      !_needsCode || verifyCodeMatches(_code.text, _summary?.verifyCode ?? '');

  void _submit() {
    final uri = _link.text.trim();
    Navigator.pop<({String name, String uri})>(
        context, (name: _name.text.trim(), uri: uri));
  }

  @override
  void dispose() {
    _pending?.cancel();
    _link.dispose();
    _name.dispose();
    _code.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = Strings.of(context);
    final valid = _summary?.valid ?? false;
    // Прокрутка обязательна, а не «на всякий случай»: полей здесь до четырёх (ссылка, код сверки,
    // имя) плюс превью и кнопка, а поднявшаяся клавиатура забирает половину экрана. Без Scrollable
    // Column просто обрезался снизу — поля и «Подключить и сохранить» оказывались ПОД клавиатурой,
    // и добавить профиль на телефоне было нельзя. Отступ `viewInsets.bottom` держит последний
    // элемент над клавиатурой, а Scrollable ещё и сам подматывает сфокусированное поле в видимую
    // часть (EditableText.showOnScreen работает только внутри прокручиваемого предка).
    return SingleChildScrollView(
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
          Text(t('new_profile'),
              style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 16),
          TextField(
            controller: _link,
            onChanged: _onLinkChanged,
            minLines: 1,
            maxLines: 3,
            decoration: InputDecoration(
              labelText: t('link_label'),
              hintText: _canScan ? t('link_hint_scan') : t('link_hint_paste'),
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: const Icon(Icons.content_paste),
                tooltip: t('paste_from_clipboard'),
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
              label: Text(t('scan_qr_camera')),
            ),
          ],
          if (_busy) ...[
            const SizedBox(height: 12),
            Row(
              children: [
                const SizedBox(
                    height: 16, width: 16, child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: 10),
                Text(t('checking_link'),
                    style: Theme.of(context).textTheme.bodyMedium),
              ],
            ),
          ] else if (_summary != null) ...[
            const SizedBox(height: 12),
            _LinkPreview(summary: _summary!),
          ],
          // M-9: сверка кода. Подмену ссылки при доставке (мессенджер, почта, чужой Wi-Fi) не
          // ловит ничто ВНУТРИ самой ссылки — подменивший перевыпустит её целиком вместе с любой
          // внутренней подписью. Ловит только сравнение по ДРУГОМУ каналу, поэтому код здесь
          // спрашивается, а не показывается «для сведения»: без совпадения профиль не сохраняем.
          if (valid && _needsCode) ...[
            const SizedBox(height: 12),
            TextField(
              controller: _code,
              onChanged: (_) => setState(() {}),
              textCapitalization: TextCapitalization.characters,
              decoration: InputDecoration(
                labelText: t('verify_code_label'),
                hintText: t('verify_code_hint'),
                helperText: t('verify_code_help'),
                helperMaxLines: 3,
                border: const OutlineInputBorder(),
                errorText: _code.text.trim().isEmpty || _codeOk
                    ? null
                    : t('verify_code_mismatch'),
                suffixIcon: _codeOk && _code.text.trim().isNotEmpty
                    ? Icon(Icons.check_circle_outline, color: Colors.green.shade600)
                    : null,
              ),
            ),
          ],
          if (valid) ...[
            const SizedBox(height: 12),
            TextField(
              controller: _name,
              decoration: InputDecoration(
                labelText: t('profile_name_optional'),
                hintText: t('profile_name_hint'),
                border: const OutlineInputBorder(),
              ),
            ),
          ],
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: valid && _codeOk && (!_needsCode || _code.text.trim().isNotEmpty)
                ? _submit
                : null,
            icon: const Icon(Icons.shield_outlined),
            label: Text(t('connect_and_save')),
          ),
          const SizedBox(height: 4),
          Text(
            t('add_profile_note'),
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
    final t = Strings.of(context);
    if (!summary.valid) {
      return Row(
        children: [
          Icon(Icons.error_outline, size: 18, color: cs.error),
          const SizedBox(width: 8),
          Text(t('link_invalid'), style: TextStyle(color: cs.error)),
        ],
      );
    }
    final feats = <String>[
      if (summary.isAdmin) t('feat_admin_master'),
      // M-9: первичная ссылка живёт до активации на ОДНОМ устройстве — человек должен видеть это
      // до того, как отдаст её кому-то ещё «на всякий случай».
      if (summary.isEnroll) t('feat_one_time'),
      if (summary.hasPqAuth) 'PQ-auth',
      if (summary.hasObfs) t('feat_obfs_full'),
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
              // Тоже без портов — превью ссылки и список профилей должны говорить об одном и том
              // же одинаково (сама ссылка с портами остаётся в поле ввода выше).
              Expanded(
                  child: Text(hostsOnly(summary.servers),
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
                      t('link_admin_warn'),
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

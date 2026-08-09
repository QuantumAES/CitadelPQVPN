import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'package:app/android_vpn.dart';
import 'package:app/l10n/strings.dart';
import 'package:app/src/rust/api/citadel.dart';
import 'package:app/windows_secure.dart';

/// Человекочитаемая фаза подключения (UI ветвится по ней, не по сырым строкам ядра).
enum VpnPhase { off, connecting, up, error }

/// Единый источник состояния приложения: vault (разблокировка/профили) + активная VPN-сессия.
/// Тонкая обёртка над FFI `citadel-client`; UI слушает через [ChangeNotifier].
class AppState extends ChangeNotifier {
  bool _unlocked = false;
  bool get unlocked => _unlocked;

  /// Существует ли файл хранилища на диске (есть что разблокировать).
  bool get hasVault => vaultExists();

  List<ProfileDto> profiles = [];

  VpnPhase phase = VpnPhase.off;

  /// Режим отладки: показывает журнал ядра и кнопку диагностики. Персистится ядром в файл рядом
  /// с vault (переживает рестарт); дефолт (файла нет) — включён (предрелиз).
  bool debugEnabled = debugEnabledPersisted();

  void toggleDebug() {
    debugEnabled = !debugEnabled;
    setDebugEnabled(on_: debugEnabled);
    notifyListeners();
  }

  /// C6/M9 kill-switch (desktop): блокировать не-туннельный трафик, пока туннель активен (fail-closed
  /// при краше движка). Применяется со СЛЕДУЮЩЕГО подключения. Session-level (персист — follow-up).
  bool killswitch = killswitchEnabled();

  void toggleKillswitch() {
    killswitch = !killswitch;
    setKillswitch(on_: killswitch);
    notifyListeners();
  }

  /// Язык интерфейса (код `ru`, `en`, …). Хранится ядром рядом с vault, а не внутри него: экран
  /// разблокировки уже говорит с человеком, а хранилище на тот момент закрыто. Дефолт — русский.
  String lang = language();

  void setLang(String code) {
    if (code == lang) return;
    lang = code;
    setLanguage(code: code);
    _pushNotifStrings();
    notifyListeners();
  }

  /// Отдать Android'у тексты постоянной нотификации на языке ПРИЛОЖЕНИЯ. Нотификация — часть того
  /// же интерфейса (при закрытом окне — единственная его видимая часть), а системная локаль
  /// устройства может быть другой, поэтому строки идут отсюда, а не из ресурсов `values-xx`.
  void _pushNotifStrings() {
    if (!Platform.isAndroid) return;
    final t = Strings.forCode(lang);
    AndroidVpn.setNotifStrings(
      up: t('notif_up'),
      connecting: t('notif_connecting'),
      reconnecting: t('notif_reconnecting'),
      down: t('notif_down'),
    );
  }

  /// Индикация трафика: показывать текущую скорость приёма/передачи на плашке подключения.
  /// Персистится ядром рядом с vault; **дефолт выключен** (см. `traffic_meter_enabled` в ядре).
  bool trafficMeter = trafficMeterEnabled();

  void toggleTrafficMeter() {
    trafficMeter = !trafficMeter;
    setTrafficMeter(on_: trafficMeter);
    notifyListeners();
  }

  /// M-8 (аудит-4): маскировка таймингов исходящего потока — выпуск пакетов по слот-сетке плюс
  /// adaptive chaff (DAITA-стиль). Персистится ядром рядом с vault; **дефолт выключен**: шейпинг
  /// платит задержкой и лишним трафиком, а выигрыш — стойкость к сопоставлению по времени, и этот
  /// размен делает пользователь. Маскирует ОТПРАВКУ; ответное направление шейпит сам exit.
  bool pacing = pacingEnabled();

  void togglePacing() {
    pacing = !pacing;
    setPacing(on_: pacing);
    notifyListeners();
  }

  /// C8.5 запрет скриншотов/записи экрана. Персистится ядром рядом с vault; **дефолт включён**
  /// (файла нет → true). Применяет платформа:
  ///   * Android — `FLAG_SECURE` на окне Activity;
  ///   * Windows — `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`; на Copilot+ ПК это
  ///     единственное, что убирает окно из СИСТЕМНЫХ снимков экрана (Recall снимает сам, без
  ///     участия пользователя, и складывает кадры в локальный индекс);
  ///   * Linux — эквивалента нет (ни X11, ни Wayland такого не дают), настройка не показывается.
  bool screenshotBlock = screenshotBlockEnabled();

  void toggleScreenshotBlock() {
    screenshotBlock = !screenshotBlock;
    setScreenshotBlock(on_: screenshotBlock);
    _applyScreenshotBlock();
    notifyListeners();
  }

  /// Платформа, где запрет захвата экрана реально применяется (иначе тумблер обещал бы то, чего нет).
  static bool get screenshotBlockSupported =>
      Platform.isAndroid || WindowsSecure.supported;

  void _applyScreenshotBlock() {
    if (Platform.isAndroid) AndroidVpn.setSecureFlag(screenshotBlock);
    if (WindowsSecure.supported) WindowsSecure.setSecure(screenshotBlock);
  }

  /// id сохранённого профиля в работе (null — «пробный» коннект ещё-не-сохранённой ссылки).
  String? activeProfileId;
  String exit = '';
  String transport = '';
  String cidr = '';

  /// Технический текст ошибки от ядра. В интерфейсе НЕ показывается: он про причины внутри
  /// (цепочка `{e:#}`), а человеку нужен итог. Полностью дублируется в журнал отладки.
  String errorMsg = '';

  /// КЛЮЧИ строк отказа: заголовок для человека («сервер недоступен») и подсказка, что делать.
  /// Разделены, потому что отказы бывают разные: недоступный сервер — это лог, а отсутствие
  /// разрешения на VPN — действие пользователя, и путать их нельзя. Здесь именно ключи
  /// локализации (см. [_classify]): текст собирает экран на языке, выбранном в момент отрисовки.
  String errorTitle = '';
  String errorHint = '';

  void _setError(String title, String hint, String detail) {
    phase = VpnPhase.error;
    errorTitle = title;
    errorHint = hint;
    errorMsg = detail;
    since = null;
  }

  void _clearError() {
    errorTitle = errorHint = errorMsg = '';
  }

  /// Момент перехода в `up` — для счётчика времени сессии.
  DateTime? since;

  /// Имя профиля текущей (или последней) попытки подключения. Нужно для человекочитаемых
  /// сообщений: «Сервер недоступен» само по себе не говорит, к ЧЕМУ не удалось подключиться.
  /// Пусто для пробного коннекта по сырой ссылке (профиля ещё нет).
  String get activeProfileName {
    final id = activeProfileId;
    if (id == null) return '';
    for (final p in profiles) {
      if (p.id == id) return p.name;
    }
    return '';
  }

  StreamSubscription<VpnEventDto>? _sub;

  bool get isBusy => phase == VpnPhase.connecting || phase == VpnPhase.up;

  AppState() {
    // C8.5: применить сохранённую настройку запрета скриншотов. Платформа уже поставила запрет по
    // умолчанию при создании окна (Android — FLAG_SECURE в onCreate, Windows — аффинити в
    // FlutterWindow::OnCreate до первого показа), здесь мы его СНИМАЕМ, если пользователь выключил.
    // Порядок именно такой: до чтения настройки не должно быть ни одного незащищённого кадра.
    _applyScreenshotBlock();
    // Тексты нотификации VPN — на языке приложения (сервис мог пережить прошлый запуск с другим).
    _pushNotifStrings();
    // C6/S3 (нюанс 2): новый изолят при перезапуске может застать ЖИВУЮ нативную сессию (loop
    // пережил закрытие окна, процесс держит foreground-сервис) — отразить её, а не показать «off».
    if (Platform.isAndroid) _restoreAndroidSession();
  }

  /// Спросить ядро о статусе сессии; если живая — отразить состояние и переподписаться на события
  /// (иначе UI показал бы «отключено» над живым VPN, а «Подключить» поднял бы второй коннект поверх).
  void _restoreAndroidSession() {
    final st = androidSessionStatus();
    if (st.state != 'up' && st.state != 'connecting' && st.state != 'migrating') return;
    activeProfileId = st.profileId.isEmpty ? null : st.profileId;
    exit = st.exit;
    transport = st.transport;
    cidr = st.cidr;
    _onState(st.state);
    _sub?.cancel();
    _sub = androidAttachEvents().listen(_handleEvent, onError: _onStreamError);
    notifyListeners();
  }

  // ─────────────────────────── vault ───────────────────────────

  Future<void> unlock(String pw) async {
    await vaultUnlock(passphrase: pw);
    _unlocked = true;
    _reloadProfiles();
    notifyListeners();
  }

  Future<void> createVault(String pw) async {
    await vaultCreate(passphrase: pw);
    _unlocked = true;
    _reloadProfiles();
    notifyListeners();
  }

  Future<void> changePassword(String oldPw, String newPw) =>
      vaultChangePassword(old: oldPw, new_: newPw);

  /// Заблокировать хранилище. Живую сессию НЕ трогаем: замок — про секреты на диске, а не про
  /// туннель. Всё нужное для работы движок уже держит у себя (ссылка разобрана при старте сессии,
  /// свежий Layer-1 токен на каждый establish добывает собственный refresher); из хранилища живая
  /// сессия только best-effort отмечает последний exit, и под замком эта отметка просто
  /// пропускается. Раньше здесь стоял `disconnect()` — и «Заблокировать хранилище» на поднятом
  /// туннеле обрывало связь, хотя пользователь просил ровно обратное: убрать профили с глаз.
  ///
  /// Чтобы замок не «прятал» работающий VPN, экран разблокировки показывает состояние сессии и
  /// даёт её отключить (см. `UnlockScreen` в `main.dart`).
  void lockVault() {
    vaultLock();
    _unlocked = false;
    profiles = [];
    notifyListeners();
  }

  void _reloadProfiles() {
    profiles = _unlocked ? vaultList() : [];
  }

  void refreshProfiles() {
    _reloadProfiles();
    notifyListeners();
  }

  void removeProfile(String id) {
    vaultRemove(id: id);
    if (activeProfileId == id) disconnect();
    refreshProfiles();
  }

  /// Переименовать профиль. Бросает, если имя пустое/хранилище закрыто — вызывающий показывает
  /// текст ядра в форме (см. [humanError]).
  void renameProfile(String id, String name) {
    vaultRename(id: id, name: name);
    refreshProfiles();
  }

  /// Переставить профиль на позицию `index` (перетаскивание в списке). Порядок живёт в хранилище,
  /// поэтому переживает перезапуск; ядро прижимает индекс за границей к концу списка.
  void moveProfileTo(String id, int index) {
    vaultMoveTo(id: id, index: index);
    refreshProfiles();
  }

  // ─────────────────────────── vpn ───────────────────────────

  void connectProfile(String id) {
    if (Platform.isAndroid) {
      _androidConnect(profileId: id);
    } else {
      _listen(vpnConnectProfile(id: id), profileId: id);
    }
  }

  /// Добавить профиль и подключиться. Профиль сохраняется в vault **сразу** (а не по успеху
  /// коннекта) — конфиг не теряется при неудаче; ненужный пользователь удалит сам.
  /// `vaultAdd` асинхронный: ядро валидирует ссылку через тот же ограничитель темпа, что и превью.
  Future<void> addAndConnect(String name, String uri) async {
    String? id;
    try {
      id = (await vaultAdd(name: name, uri: uri)).id;
      _reloadProfiles();
      notifyListeners();
    } catch (_) {
      // vault недоступен — деградируем на пробный коннект по сырой ссылке
    }
    if (Platform.isAndroid) {
      _androidConnect(profileId: id, link: id == null ? uri : null);
    } else if (id != null) {
      _listen(vpnConnectProfile(id: id), profileId: id);
    } else {
      _listen(vpnConnect(link: uri), profileId: null);
    }
  }

  /// Android: старт нативной сессии. Консент (`prepare`) + `startService` (foreground + JNI-протектор)
  /// — один раз; дальше нативный `VpnController`-loop (`android_start_session`) САМ держит
  /// establish + авто-реконнект (backoff, always-retry, свежий токен, kill-switch) и переживает
  /// смерть UI-изолята (сессия жива, пока сервис активен, даже при закрытом окне — C6). Dart лишь
  /// слушает поток событий — тем же `_listen`, что desktop-путь.
  Future<void> _androidConnect({String? profileId, String? link}) async {
    // «Подключаемся» уже на время консента/старта сервиса (может всплыть системный диалог).
    phase = VpnPhase.connecting;
    activeProfileId = profileId;
    exit = transport = cidr = '';
    _clearError();
    since = null;
    notifyListeners();

    if (!await AndroidVpn.prepare()) {
      // Не «сервер недоступен»: пользователь не дал разрешение на VPN — это его действие.
      _setError('err_no_vpn_permission', 'err_no_vpn_permission_hint',
          'VpnService.prepare отклонён пользователем');
      notifyListeners();
      return;
    }
    await AndroidVpn.startService();

    _listen(
      profileId != null
          ? androidStartSessionProfile(id: profileId)
          : androidStartSession(link: link!),
      profileId: profileId,
    );
  }

  void _listen(Stream<VpnEventDto> stream, {String? profileId}) {
    _sub?.cancel();
    phase = VpnPhase.connecting;
    activeProfileId = profileId;
    exit = transport = cidr = '';
    _clearError();
    since = null;
    notifyListeners();
    _sub = stream.listen(_handleEvent, onError: _onStreamError);
  }

  /// Применить событие сессии к состоянию (общее для первого коннекта и re-attach при перезапуске).
  void _handleEvent(VpnEventDto ev) {
    switch (ev.kind) {
      case 'state':
        _onState(ev.state);
      case 'connected':
        exit = ev.exit;
        transport = ev.transport;
        cidr = ev.cidr;
      case 'error':
        final (title, hint) = _classify(ev.error);
        _setError(title, hint, ev.error);
    }
    notifyListeners();
  }

  void _onStreamError(Object e) {
    final (title, hint) = _classify('$e');
    _setError(title, hint, '$e');
    notifyListeners();
  }

  /// Отнести отказ движка к виду, понятному человеку. По умолчанию это «сервер недоступен» — но
  /// далеко не всякий отказ про сервер, и молча выдавать этот заголовок вредно: пользователь идёт
  /// чинить не то (менял бы профиль там, где не запущена служба Windows). Разбираем ровно те случаи,
  /// где виновник ЛОКАЛЬНЫЙ и человек может что-то сделать; остальное — прежний общий текст.
  ///
  /// Подсказка — только там, где она говорит, ЧТО делать. Отсылки к журналу отладки здесь нет: у
  /// выключённого режима отладки журнала попросту не существует, а совет «посмотрите в журнал»
  /// человеку, который хочет подключиться, ничего не даёт (полная цепочка причин пишется туда и
  /// так, когда режим включён).
  ///
  /// Возвращаем КЛЮЧИ строк, а не готовый текст: состояние живёт дольше одного кадра и не знает
  /// про выбранный язык, а экран (`_StatusCard`) переводит их при отрисовке — так смена языка
  /// перерисовывает и уже показанный отказ.
  static (String, String) _classify(String err) {
    if (err.contains('citadel-svc') || err.contains('CitadelPQVPN')) {
      if (err.contains('SERVICE_START') || err.contains('os error 5')) {
        return ('err_service_not_started', 'err_service_not_started_hint');
      }
      return ('err_service_unavailable', 'err_service_unavailable_hint');
    }
    return ('err_server_unreachable', '');
  }

  void _onState(String s) {
    switch (s) {
      case 'connecting':
        if (phase != VpnPhase.error) phase = VpnPhase.connecting;
      case 'migrating':
        phase = VpnPhase.connecting;
      case 'up':
        phase = VpnPhase.up;
        since ??= DateTime.now();
      case 'down':
      case 'idle':
        if (phase != VpnPhase.error) phase = VpnPhase.off;
        since = null;
    }
  }

  void disconnect() {
    // Останавливает нативный loop (гасит авто-реконнект, connect-loop дропает tun → fd → TUN гаснет).
    if (Platform.isAndroid) {
      androidStopSession(); // + сброс статуса/sink: перезапуск не примет мёртвую сессию за живую (S3)
      AndroidVpn.stopService(); // + снять foreground-сервис и мониторинг сети
    } else {
      vpnDisconnect();
    }
    _sub?.cancel();
    _sub = null;
    phase = VpnPhase.off;
    activeProfileId = null;
    exit = transport = cidr = '';
    _clearError(); // отключились сами — прошлый отказ больше не про текущее состояние
    since = null;
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}

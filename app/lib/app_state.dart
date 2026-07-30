import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import 'package:app/android_vpn.dart';
import 'package:app/src/rust/api/citadel.dart';

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

  /// C8.5 запрет скриншотов/записи экрана (Android FLAG_SECURE). Персистится ядром рядом с vault;
  /// **дефолт включён** (файла нет → true). Флаг применяет платформа (Android); desktop не enforce'ит.
  bool screenshotBlock = screenshotBlockEnabled();

  void toggleScreenshotBlock() {
    screenshotBlock = !screenshotBlock;
    setScreenshotBlock(on_: screenshotBlock);
    if (Platform.isAndroid) AndroidVpn.setSecureFlag(screenshotBlock);
    notifyListeners();
  }

  /// id сохранённого профиля в работе (null — «пробный» коннект ещё-не-сохранённой ссылки).
  String? activeProfileId;
  String exit = '';
  String transport = '';
  String cidr = '';

  /// Технический текст ошибки от ядра. В интерфейсе НЕ показывается: он про причины внутри
  /// (цепочка `{e:#}`), а человеку нужен итог. Полностью дублируется в журнал отладки.
  String errorMsg = '';

  /// Заголовок отказа для человека («Сервер недоступен») и подсказка, что делать/куда смотреть.
  /// Разделены, потому что отказы бывают разные: недоступный сервер — это лог, а отсутствие
  /// разрешения на VPN — действие пользователя, и путать их нельзя.
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
    // C8.5: применить сохранённую настройку запрета скриншотов (onCreate уже поставил FLAG_SECURE
    // по умолчанию; здесь СНИМАЕМ, если пользователь выключил). Дефолт — запрет включён.
    if (Platform.isAndroid) AndroidVpn.setSecureFlag(screenshotBlock);
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

  void lockVault() {
    disconnect();
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
  void addAndConnect(String name, String uri) {
    String? id;
    try {
      id = vaultAdd(name: name, uri: uri).id;
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
      _setError('Нет разрешения на VPN', 'разрешите подключение в системном диалоге',
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
  /// где виновник ЛОКАЛЬНЫЙ и человек может что-то сделать; остальное — прежний общий текст, а полная
  /// цепочка причин в любом случае лежит в журнале отладки.
  static (String, String) _classify(String err) {
    if (err.contains('citadel-svc') || err.contains('CitadelPQVPN')) {
      if (err.contains('SERVICE_START') || err.contains('os error 5')) {
        return ('Служба CitadelPQVPN не запущена', 'перезагрузите компьютер или переустановите приложение');
      }
      return ('Служба CitadelPQVPN недоступна', 'проверьте, что она установлена и запущена');
    }
    return ('Сервер недоступен', 'подробности в журнале отладки');
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

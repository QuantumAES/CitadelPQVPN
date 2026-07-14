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

  /// Режим отладки: показывает журнал ядра и кнопку диагностики. Для предрелиза — включён,
  /// чтобы упростить диагностику коннекта в бою. Хранится в памяти (сбрасывается при рестарте).
  bool debugEnabled = true;

  void toggleDebug() {
    debugEnabled = !debugEnabled;
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

  /// id сохранённого профиля в работе (null — «пробный» коннект ещё-не-сохранённой ссылки).
  String? activeProfileId;
  String exit = '';
  String transport = '';
  String cidr = '';
  String errorMsg = '';

  /// Момент перехода в `up` — для счётчика времени сессии.
  DateTime? since;

  StreamSubscription<VpnEventDto>? _sub;

  /// Пользователь сам нажал «Отключить» — гасит форс-реконнект по смене сети (`_onNetworkChanged`)
  /// в зазоре, пока не долетит `down`. Сам авто-реконнект держит нативный `VpnController` (обе
  /// платформы). Сбрасывается в false на новом коннекте.
  bool _userStopped = false;

  bool get isBusy => phase == VpnPhase.connecting || phase == VpnPhase.up;

  AppState() {
    if (Platform.isAndroid) {
      AndroidVpn.ensureHandler();
      AndroidVpn.onNetworkChanged = _onNetworkChanged;
    }
  }

  /// Смена underlying-сети (native NetworkCallback): транспорт над старой сетью, скорее всего,
  /// мёртв → сигналим нативному loop переустановить сессию над новой сетью СРАЗУ (не ждём
  /// pump-watchdog ~8с / QUIC idle-timeout). Игнор, если пользователь отключил VPN.
  void _onNetworkChanged() {
    debugPrint('[CitadelNet] _onNetworkChanged phase=$phase stopped=$_userStopped');
    if (_userStopped) return;
    if (phase == VpnPhase.up || phase == VpnPhase.connecting) {
      androidNotifyNetworkChanged(); // нативный VpnController оборвёт pump и реконнектнётся
    }
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
    _userStopped = false;
    phase = VpnPhase.connecting;
    activeProfileId = profileId;
    exit = transport = cidr = errorMsg = '';
    since = null;
    notifyListeners();

    if (!await AndroidVpn.prepare()) {
      phase = VpnPhase.error;
      errorMsg = 'Нет разрешения на VPN';
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
    _userStopped = false;
    phase = VpnPhase.connecting;
    activeProfileId = profileId;
    exit = transport = cidr = errorMsg = '';
    since = null;
    notifyListeners();

    _sub = stream.listen((ev) {
      switch (ev.kind) {
        case 'state':
          _onState(ev.state);
        case 'connected':
          exit = ev.exit;
          transport = ev.transport;
          cidr = ev.cidr;
        case 'error':
          phase = VpnPhase.error;
          errorMsg = ev.error;
          since = null;
      }
      notifyListeners();
    }, onError: (Object e) {
      phase = VpnPhase.error;
      errorMsg = '$e';
      since = null;
      notifyListeners();
    });
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
    _userStopped = true;
    // Останавливает нативный loop (ACTIVE.disconnect): гасит авто-реконнект, connect-loop дропает
    // tun → fd закрывается → TUN гаснет. Симметрично обеим платформам.
    vpnDisconnect();
    if (Platform.isAndroid) AndroidVpn.stopService(); // + снять foreground-сервис и мониторинг сети
    _sub?.cancel();
    _sub = null;
    phase = VpnPhase.off;
    activeProfileId = null;
    exit = transport = cidr = '';
    since = null;
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }
}

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

  /// Пользователь сам нажал «Отключить» — глушит авто-реконнект (Android-путь; на Linux
  /// реконнект живёт в ядре `VpnController`). Сбрасывается в false на новом коннекте.
  bool _userStopped = false;

  bool get isBusy => phase == VpnPhase.connecting || phase == VpnPhase.up;

  AppState() {
    if (Platform.isAndroid) {
      AndroidVpn.ensureHandler();
      AndroidVpn.onNetworkChanged = _onNetworkChanged;
    }
  }

  /// Смена underlying-сети (native NetworkCallback): транспорт над старой сетью, скорее всего,
  /// мёртв → абортим data-plane, и цикл [_androidConnect] переустановит сессию над новой сетью
  /// (быстрый реконнект, не ждём QUIC idle-timeout). Игнор, если пользователь отключил VPN.
  void _onNetworkChanged() {
    debugPrint('[CitadelNet] _onNetworkChanged phase=$phase stopped=$_userStopped');
    if (_userStopped) return;
    if (phase == VpnPhase.up || phase == VpnPhase.connecting) {
      androidDisconnect(); // аборт data-plane → _androidRunDataPlane завершится → реконнект
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

  /// Android: двухфазно — establish (сеть) → VpnService строит TUN → run_data_plane. Держит
  /// соединение живым: **любой** сбой (в т.ч. первичный коннект без сети или разрыв при смене
  /// WiFi/LTE) → авто-ретрай с прогрессивным backoff (1→2→…→30с), пока пользователь не нажмёт
  /// «Отключить». Причина сбоя показывается на карточке (и в лог-панели), но попытки продолжаются
  /// — так соединение само поднимается, когда сеть возвращается. Backoff сбрасывается после
  /// успешной сессии.
  Future<void> _androidConnect({String? profileId, String? link}) async {
    _sub?.cancel();
    _userStopped = false;
    phase = VpnPhase.connecting;
    activeProfileId = profileId;
    exit = transport = cidr = errorMsg = '';
    since = null;
    notifyListeners();

    // Консент + запуск сервиса — ОДИН раз; сервис живёт всю сессию (реконнект переустанавливает
    // только TUN+транспорт, а не сам VpnService). Так native NetworkCallback стабилен и при смене
    // сети реконнект чистый, без teardown'а сервиса.
    if (!await AndroidVpn.prepare()) {
      phase = VpnPhase.error;
      errorMsg = 'Нет разрешения на VPN';
      notifyListeners();
      return;
    }
    await AndroidVpn.startService();

    var backoff = const Duration(seconds: 1);

    while (!_userStopped) {
      var attemptFailed = false;
      try {
        final setup = profileId != null
            ? await androidEstablishProfile(id: profileId)
            : await androidEstablish(link: link!);
        final fd = await AndroidVpn.establishTun(setup); // заменяет предыдущий TUN
        if (fd < 0) throw 'VpnService не выдал TUN-fd';

        // блокирует до разрыва транспорта; true — сессия успела подняться (сброс backoff)
        final wasUp = await _androidRunDataPlane(fd, setup);
        if (wasUp) backoff = const Duration(seconds: 1);
      } catch (e) {
        // НЕ сдаёмся: показываем причину, но продолжаем ретраи (keep-connected).
        attemptFailed = true;
        errorMsg = '$e';
        phase = VpnPhase.error;
        since = null;
        notifyListeners();
      }

      if (_userStopped) break;
      // разрыв без явной ошибки → «восстановление» (amber); при ошибке оставляем причину видимой
      if (!attemptFailed) {
        phase = VpnPhase.connecting;
        since = null;
        notifyListeners();
      }
      await Future.delayed(backoff);
      backoff = backoff * 2 >= const Duration(seconds: 30)
          ? const Duration(seconds: 30)
          : backoff * 2;
      if (_userStopped) break;
      phase = VpnPhase.connecting; // начинаем новую попытку
      notifyListeners();
    }
  }

  /// Запустить Android data-plane и дождаться его завершения. Возвращает, поднялась ли сессия
  /// (была ли фаза `up`) — для решения о реконнекте.
  Future<bool> _androidRunDataPlane(int fd, TunSetupDto setup) {
    final done = Completer<bool>();
    var up = false;
    exit = setup.exit;
    transport = setup.transport;
    cidr = '${setup.addr}/${setup.prefix}';
    _sub?.cancel();
    _sub = androidRunDataPlane(fd: fd).listen(
      (ev) {
        switch (ev.kind) {
          case 'state':
            _onState(ev.state);
            if (ev.state == 'up') up = true;
          case 'connected':
            exit = ev.exit;
            transport = ev.transport;
            cidr = ev.cidr;
          case 'error':
            errorMsg = ev.error;
        }
        notifyListeners();
      },
      onDone: () {
        if (!done.isCompleted) done.complete(up);
      },
      onError: (Object e) {
        errorMsg = '$e';
        notifyListeners();
        if (!done.isCompleted) done.complete(up);
      },
    );
    return done.future;
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
    _userStopped = true; // глушим авто-реконнект (Android-путь)
    if (Platform.isAndroid) {
      androidDisconnect(); // abort data-plane → fd закрывается → TUN гаснет
      AndroidVpn.stopService();
    } else {
      vpnDisconnect();
    }
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

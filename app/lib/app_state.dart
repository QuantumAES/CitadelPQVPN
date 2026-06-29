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

  /// id сохранённого профиля в работе (null — «пробный» коннект ещё-не-сохранённой ссылки).
  String? activeProfileId;
  String exit = '';
  String transport = '';
  String cidr = '';
  String errorMsg = '';

  /// Момент перехода в `up` — для счётчика времени сессии.
  DateTime? since;

  StreamSubscription<VpnEventDto>? _sub;
  ({String name, String uri})? _pendingSave;

  bool get isBusy => phase == VpnPhase.connecting || phase == VpnPhase.up;

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

  /// Пробное подключение по сырой ссылке; при успехе (событие `up`) — сохранить в vault.
  void addAndConnect(String name, String uri) {
    _pendingSave = (name: name, uri: uri);
    if (Platform.isAndroid) {
      _androidConnect(link: uri);
    } else {
      _listen(vpnConnect(link: uri), profileId: null);
    }
  }

  /// Android: двухфазно — establish (сеть) → VpnService строит TUN → run_data_plane.
  Future<void> _androidConnect({String? profileId, String? link}) async {
    _sub?.cancel();
    phase = VpnPhase.connecting;
    activeProfileId = profileId;
    exit = transport = cidr = errorMsg = '';
    since = null;
    notifyListeners();
    try {
      if (!await AndroidVpn.prepare()) {
        phase = VpnPhase.error;
        errorMsg = 'Нет разрешения на VPN';
        notifyListeners();
        return;
      }
      await AndroidVpn.startService();
      final setup = profileId != null
          ? await androidEstablishProfile(id: profileId)
          : await androidEstablish(link: link!);
      final fd = await AndroidVpn.establishTun(setup);
      if (fd < 0) {
        phase = VpnPhase.error;
        errorMsg = 'VpnService не выдал TUN-fd';
        notifyListeners();
        await AndroidVpn.stopService();
        return;
      }
      _listen(androidRunDataPlane(fd: fd), profileId: profileId);
    } catch (e) {
      phase = VpnPhase.error;
      errorMsg = '$e';
      since = null;
      notifyListeners();
      await AndroidVpn.stopService();
    }
  }

  void _listen(Stream<VpnEventDto> stream, {String? profileId}) {
    _sub?.cancel();
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
        _savePendingIfAny();
      case 'down':
      case 'idle':
        if (phase != VpnPhase.error) phase = VpnPhase.off;
        since = null;
    }
  }

  /// На первом `up` пробного коннекта — сохранить профиль и «привязать» сессию к нему.
  void _savePendingIfAny() {
    final pend = _pendingSave;
    if (pend == null) return;
    _pendingSave = null;
    try {
      final p = vaultAdd(name: pend.name, uri: pend.uri);
      activeProfileId = p.id;
      _reloadProfiles();
    } catch (_) {
      // сохранение не критично для уже поднятого туннеля — профиль просто не осядет
    }
  }

  void disconnect() {
    if (Platform.isAndroid) {
      androidDisconnect(); // abort data-plane → fd закрывается → TUN гаснет
      AndroidVpn.stopService();
    } else {
      vpnDisconnect();
    }
    _sub?.cancel();
    _sub = null;
    _pendingSave = null;
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

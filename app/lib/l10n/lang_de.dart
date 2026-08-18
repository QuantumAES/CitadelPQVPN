/// Deutsch. Набор ключей обязан совпадать с `lang_ru.dart` (проверяется тестом l10n_test.dart).
library;

const Map<String, String> langDe = {
  'cancel': 'Abbrechen',
  'close': 'Schließen',
  'save': 'Speichern',
  'delete': 'Löschen',
  'connect': 'Verbinden',
  'disconnect': 'Trennen',
  'rename': 'Umbenennen',
  'unknown_error': 'Unbekannter Fehler',

  'add_profile': 'Profil hinzufügen',
  'lock_vault': 'Speicher sperren',
  'settings': 'Einstellungen',
  'profiles': 'Profile',
  'no_profiles': 'Keine Profile',
  'no_profiles_hint': 'Fügen Sie einen citadel://-Link hinzu,\num sich mit einem Server zu verbinden',
  'profile_fallback_name': 'Profil',
  'new_profile_fallback': 'neues Profil',

  'status_protected': 'Geschützt',
  'status_connecting': 'Verbinden…',
  'status_unprotected': 'Nicht geschützt',
  'status_profile_named': 'Profil „{name}“',
  'traffic_rx': 'Empfang',
  'traffic_tx': 'Senden',
  'rate_units': 'B/s,KB/s,MB/s,GB/s,TB/s',
  'decimal_sep': ',',

  'err_server_unreachable': 'Server nicht erreichbar',
  'err_service_not_started': 'Der Dienst CitadelPQVPN läuft nicht',
  'err_service_not_started_hint': 'Starten Sie den Computer neu oder installieren Sie die App erneut',
  'err_service_unavailable': 'Der Dienst CitadelPQVPN ist nicht verfügbar',
  'err_service_unavailable_hint': 'Prüfen Sie, ob er installiert ist und läuft',
  'err_no_vpn_permission': 'Keine VPN-Berechtigung',
  'err_no_vpn_permission_hint': 'Erlauben Sie die Verbindung im Systemdialog',
  'err_activation_failed': 'Der Link konnte nicht aktiviert werden',
  'err_activation_failed_hint': 'bitten Sie den Administrator um einen neuen Link: ein Erstlink wird einmal und nur begrenzte Zeit aktiviert',
  'err_ipv6_required': 'Tunnel nicht aufgebaut: IPv6 läuft am Tunnel vorbei',
  'err_ipv6_required_hint': 'striktes IPv6 ist aktiv — schalten Sie es in den Einstellungen ab oder aktivieren Sie ein immer aktives VPN',

  'switch_title': 'Verbindung wechseln?',
  'switch_body': 'Aktuell ist „{current}“ verbunden. Trennen und mit „{name}“ verbinden?',
  'switch_confirm': 'Wechseln',

  'unlock_vault': 'Speicher entsperren',
  'unlock': 'Entsperren',
  'create_vault': 'Speicher anlegen',
  'create': 'Anlegen',
  'vault_create_hint':
      'Profile werden mit diesem Master-Passwort verschlüsselt (AES-256-GCM). Ohne es sind sie nicht wiederherstellbar.',
  'vault_locked': 'Profilspeicher ist gesperrt',
  'master_password': 'Master-Passwort',
  'password': 'Passwort',
  'password_repeat': 'Passwort wiederholen',
  'password_min': 'mindestens {n} Zeichen',
  'password_empty': 'Das Passwort darf nicht leer sein',
  'password_too_short': 'Passwort zu kurz: mindestens {n} Zeichen',
  'passwords_mismatch': 'Die Passwörter stimmen nicht überein',
  'change_password': 'Master-Passwort ändern',
  'current_password': 'Aktuelles Passwort',
  'new_password': 'Neues Passwort',
  'new_password_repeat': 'Neues Passwort wiederholen',
  'enter_current_password': 'Geben Sie das aktuelle Passwort ein',
  'new_password_too_short': 'Neues Passwort zu kurz: mindestens {n} Zeichen',
  'new_passwords_mismatch': 'Die neuen Passwörter stimmen nicht überein',
  'change': 'Ändern',
  'password_changed': 'Master-Passwort geändert',

  'delete_profile_title': 'Profil löschen?',
  'delete_profile_body':
      'Das Profil „{name}“ wird aus dem Speicher entfernt. Das lässt sich nicht rückgängig machen.',
  'rename_profile': 'Profil umbenennen',
  'profile_name': 'Profilname',
  'profile_renamed': 'Profil umbenannt',
  'subscribers': 'Teilnehmer',

  'traffic_meter_title': 'Datenrate anzeigen',
  'traffic_meter_sub': 'Aktuelle Empfangs- und Senderate auf der Verbindungskarte',
  'pacing_title': 'Zeitmuster verschleiern',
  'pacing_off': 'Aus',
  'pacing_off_sub': 'Kein zusätzlicher Datenverkehr, keine Akkulast',
  'pacing_lite': 'Sparsam',
  'pacing_lite_sub': 'Bis zu 2 MB pro Stunde zusätzlich; deutlich akkuschonender',
  'pacing_strict': 'Streng',
  'pacing_strict_sub': 'Bis zu 8 MB pro Stunde zusätzlich; spürbarer Akkuverbrauch',
  'pacing_note': 'Die Verschleierung wirkt, solange Verkehr fließt: im Leerlauf schweigt sie und kostet nichts. Gilt ab der nächsten Sitzung.',
  // ── C9 ──
  'biometric_title': 'Entsperren per Fingerabdruck',
  'biometric_sub': 'Tresor per Fingerabdruck öffnen; das Master-Passwort funktioniert weiterhin',
  'biometric_unlock': 'Mit Fingerabdruck entsperren',
  'biometric_prompt_unlock': 'Sensor berühren, um den Tresor zu öffnen',
  'biometric_prompt_enable': 'Sensor berühren, um das Entsperren per Fingerabdruck zu aktivieren',
  'biometric_key_gone':
      'Die Biometrie des Geräts hat sich geändert — mit dem Master-Passwort anmelden und den Fingerabdruck erneut aktivieren',
  'biometric_failed': 'Fingerabdruck konnte nicht verwendet werden',
  'biometric_none_enrolled':
      'Fügen Sie zuerst einen Fingerabdruck in den Geräteeinstellungen hinzu',
  'debug_title': 'Debug-Modus',
  'debug_sub': 'Kern-Protokoll und Verbindungsdiagnose',
  'screenshot_title': 'Screenshots blockieren',
  'screenshot_sub': 'Bildschirmfotos und -aufnahmen der App blockieren',
  'killswitch_title': 'Kill-Switch',
  'killswitch_sub': 'Verkehr außerhalb des Tunnels blockieren (fail-closed); ab der nächsten Sitzung',
  'killswitch_android_title': 'Kill-Switch (Always-on)',
  'killswitch_android_sub': 'In den System-VPN-Einstellungen konfigurieren',
  'strict_ipv6_title': 'Striktes IPv6',
  'strict_ipv6_sub': 'Nicht verbinden, wenn IPv6 am Tunnel vorbeiläuft',
  'split_title': 'Split-Tunnel',
  'split_sub_android': 'Nach Apps und Adressen: durch den Tunnel / daran vorbei',
  'split_sub_desktop': 'Nach Zieladressen: durch den Tunnel / daran vorbei',
  'autolock_title': 'Automatische Tresorsperre',
  'autolock_sub_off': 'Aus — der Tresor bleibt bis zum Beenden der App offen',
  'autolock_sub_on': 'Nach {min} Min. ohne Aktivität sperren',
  'autolock_off': 'Aus',
  'autolock_minutes': '{min} Min.',
  'autolock_note': 'Die Sperre nimmt Profile und Master-Link vom Bildschirm und aus dem '
      'Speicher. Einen aktiven Tunnel rührt sie nicht an; zurück geht es per '
      'Fingerabdruck oder Master-Passwort.',
  'vault_location_title': 'Profilspeicher',
  'vault_path_copied': 'Speicherpfad kopiert',
  'language_title': 'App-Sprache',
  'about_title': 'Über die App',
  'about_sub': 'CitadelPQVPN · Version {version}',

  'about_body': 'Post-Quanten-VPN.\n\n'
      'Die Sitzung wird durch einen hybriden Schlüsselaustausch X25519 + ML-KEM-768 und eine '
      'ML-DSA-65-Serversignatur geschützt: heute abgefangener Verkehr lässt sich auch mit dem '
      'Quantencomputer von morgen nicht entschlüsseln.\n\n'
      'Der Verkehr wird als gewöhnlicher Datenstrom getarnt, Profile und Schlüssel liegen in einem '
      'verschlüsselten Speicher auf dem Gerät, und der Server führt keine Verbindungsprotokolle.',
  'about_version': 'Version',
  'about_app_version': 'App: {version}',
  'about_core_version': 'Kern: v{version}',
  'copy_version': 'Version kopieren',
  'version_copied': 'Version kopiert',

  'alwayson_body': 'Unter Android blockiert das System den Verkehr am VPN vorbei, nicht die App.\n\n'
      'Aktivieren Sie in den System-VPN-Einstellungen für CitadelPQVPN:\n'
      '• Immer aktives VPN (Always-on VPN)\n'
      '• Verbindungen ohne VPN blockieren',
  'open_settings': 'Einstellungen öffnen',
  'ipv6_warn': 'IPv6 läuft am Tunnel vorbei — Details',
  'ipv6_warn_title': 'IPv6 nicht erfasst',
  'ipv6_warn_body': 'Der Tunnel arbeitet, aber IPv6-Verkehr (und IPv6-DNS) verlässt das Gerät direkt '
      'am Tunnel vorbei — in einem IPv6-Netz gibt das Ihre Adresse preis.\n\n'
      'Was tun:\n'
      '• für CitadelPQVPN „Immer aktives VPN“ und „Verbindungen ohne VPN blockieren“ '
      'einschalten — dann sperrt das System jeden Verkehr außerhalb des Tunnels;\n'
      '• oder „Striktes IPv6“ in den Einstellungen aktivieren — dann kommt der Tunnel '
      'ohne erfasstes IPv6 gar nicht erst hoch.',

  'new_profile': 'Neues Profil',
  'link_label': 'citadel://-Link',
  'link_hint_scan': 'Link einfügen oder QR-Code scannen',
  'link_hint_paste': 'Link oder QR-Daten einfügen',
  'wrapped_link_hint': 'Das ist ein Master-Link in einem Passwort-Umschlag. Gib das Passwort ein — es wird getrennt vom Block übermittelt.',
  'wrapped_password': 'Umschlag-Passwort',
  'wrapped_unwrap': 'Entpacken',
  'wrapped_unwrapping': 'Entpacke…',
  'wrapped_bad_password': 'Falsches Passwort oder beschädigter Block',
  'paste_from_clipboard': 'Aus Zwischenablage einfügen',
  'scan_qr_camera': 'QR-Code mit Kamera scannen',
  'checking_link': 'Link wird geprüft…',
  'link_invalid': 'Link nicht erkannt',
  'link_admin_warn': 'Master-Link: erlaubt die Verwaltung von Teilnehmern. Geben Sie ihn niemandem weiter.',
  'profile_name_optional': 'Profilname (optional)',
  'profile_name_hint': 'z. B. exit-nl',
  'connect_and_save': 'Verbinden und speichern',
  'add_profile_note':
      'Das Profil wird nach der ersten erfolgreichen Verbindung im verschlüsselten Speicher abgelegt.',
  'feat_admin_master': 'admin (Master)',
  'feat_obfs_full': 'Verschleierung',

  'diag_run': 'Verbindungsdiagnose',
  'diag_running': 'Prüfung…',
  'diag_title': 'Diagnose',
  'diag_no_profile': 'Kein Profil für die Diagnose',
  'diag_start': 'Testverbindung für die Diagnose (eigene Sitzung, nicht der Haupttunnel)…',
  'diag_aborted': 'Diagnose abgebrochen: {error}',
  'log_core_title': 'Kern-Protokoll',
  'log_autoscroll_on': 'Auto-Scroll: an',
  'log_autoscroll_off': 'Auto-Scroll: aus',
  'log_copy': 'Kopieren',
  'log_copied': 'Protokoll kopiert',
  'log_clear': 'Leeren',
  'log_empty': 'leer',

  'tunnel_active': 'Tunnel ist aktiv',
  'close_window_body': 'Das VPN ist verbunden. Was soll beim Schließen des Fensters geschehen?\n\n'
      '• Im Hintergrund behalten — das Fenster wird minimiert, die Verbindung bleibt bestehen.\n'
      '• Trennen und beenden — den Tunnel abbauen und die App schließen.',
  'close_background': 'Im Hintergrund behalten',
  'close_quit': 'Trennen und beenden',

  'tray_up': 'CitadelPQVPN — Tunnel ist aktiv',
  'tray_up_at': 'CitadelPQVPN — Tunnel ist aktiv ({exit})',
  'tray_connecting': 'CitadelPQVPN — Verbindung…',
  'tray_off': 'CitadelPQVPN — Tunnel ist aus',
  'tray_error': 'CitadelPQVPN — {reason}',

  'tray_open': 'CitadelPQVPN öffnen',
  'tray_disconnect': 'Tunnel trennen',
  'tray_exit': 'Beenden',

  'notif_up': 'Post-Quanten-Tunnel ist aktiv',
  'notif_connecting': 'Verbinden…',
  'notif_reconnecting': 'Keine Verbindung — stelle wieder her',
  'notif_down': 'Tunnel ist nicht aktiv',

  'split_saved': 'Gespeichert · gilt ab der nächsten Verbindung',
  'split_apps': 'Apps',
  'split_dests': 'Zieladressen',
  'split_apps_selected': 'Ausgewählte Apps: {n}',
  'split_apps_pick': 'Tippen, um aus installierten Apps zu wählen',
  'split_dest_label': 'Domain / IP / CIDR',
  'split_add_local_subnet': 'Lokales Subnetz hinzufügen',
  'split_local_subnet_none': 'Lokales Subnetz nicht erkannt',
  'split_mode_off': 'Aus',
  'split_mode_include': 'Durch den Tunnel',
  'split_mode_exclude': 'Vorbei',
  'split_warn': 'Achtung: Apps/Adressen „vorbei“ gehen direkt und geben Ihre echte IP preis. '
      'Domains werden beim Verbinden aufgelöst; bei CDNs mit wechselnden IPs kann die Regel '
      'zwischen Neuverbindungen „lecken“.',
  'split_warn_android13': 'Das Ausschließen von Zielen erfordert Android 13+.',
  'split_warn_dns': 'DNS: Apps im Tunnel lösen über den Tunnel-Resolver auf, die übrigen über das '
      'DNS Ihres Netzes (WLAN/Mobilfunk), das deren Domains sieht. Ist im System „Privates DNS“ '
      '(DNS-over-TLS) aktiv, wendet Android es auch im Tunnel an.',
  'split_apps_title': 'Apps auswählen',
  'split_apps_done': 'Fertig ({n})',
  'search': 'Suche',
  'split_apps_failed': 'App-Liste konnte nicht geladen werden: {error}',

  'subscribers_title': 'Teilnehmer · {name}',
  'issue_access': 'Zugang ausstellen',
  'refresh': 'Aktualisieren',
  'issue_label': 'Bezeichnung (für wen)',
  'issue_label_hint': 'z. B. „Alis Telefon“',
  'issue_label_helper': 'wird nur auf diesem Gerät gespeichert',
  'issue_valid_until': 'Gültigkeit (optional)',
  'issue_valid_until_hint': '+30d · +12h · unix · leer = +365d',
  'issue': 'Ausstellen',
  'issued_title': 'Zugang ausgestellt',
  'issued_title_named': 'Zugang ausgestellt: {label}',
  'copy_link': 'Link kopieren',
  'link_copied': 'Link kopiert',
  'clipboard_autoclear': 'die Zwischenablage leert sich selbst',
  'verify_code_label': 'Prüfcode vom Administrator',
  'verify_code_hint': '6 Zeichen',
  'verify_code_help': 'Der Administrator nennt ihn getrennt vom Link (mündlich, persönlich). Stimmt er überein, wurde der Link unterwegs nicht verändert.',
  'verify_code_mismatch': 'Code stimmt nicht: Das ist nicht der vom Administrator ausgegebene Link. Nicht verbinden — neuen Link anfordern.',
  'feat_one_time': 'einmalig',
  'admin_timeout': 'Server hat innerhalb von 30 s nicht geantwortet. Steht der Tunnel dieses Profils? Falls ja: Details im Kern-Log ([admin]-Zeilen).',
  'verify_code_title': 'Prüfcode',
  'verify_code_note': 'Nennen Sie diesen Code getrennt vom Link (mündlich, persönlich). Beim Import sieht der Abonnent denselben Code — so wird eine Manipulation bei der Zustellung erkannt.',
  'activate_note': 'Der Link muss bis {when} und nur auf einem Gerät aktiviert werden: nach der Aktivierung ist eine Kopie wertlos.',
  'issued_note': 'Übergeben Sie den Link jetzt an den Teilnehmer (QR-Code oder sicherer Kanal). '
      'Ein erneutes Abrufen ist nicht möglich: das Geheimnis des Teilnehmers wird auf diesem Gerät nicht gespeichert.',
  'revoke_title': 'Zugang widerrufen?',
  'revoke_body': 'Der Zugang {who} wird widerrufen (status=revoked). '
      'Wirksam ab der nächsten Verbindung, höchstens innerhalb einer Epoche.',
  'revoke': 'Widerrufen',
  'need_session': 'Eine aktive Sitzung ist erforderlich',
  'need_session_body': 'Die Teilnehmerverwaltung läuft über den Admin-Kanal im Tunnel. '
      'Verbinden Sie sich mit „{name}“, um fortzufahren.',
  'session_restoring': 'Sitzung wird wiederhergestellt',
  'session_restoring_body': 'Der Tunnel zu „{name}“ verbindet sich neu. '
      'Die Teilnehmerliste lädt von selbst, sobald der Kanal zurück ist.',
  'registry_loading': 'Register wird geladen…',
  'registry_empty': 'Das Register ist leer — stellen Sie den ersten Zugang aus.',
  'entry_expired': 'abgelaufen',
  'entry_until': 'bis {date}',
  'client_id_copied': 'client_id kopiert',

  'scan_qr': 'QR-Code scannen',
  'torch': 'Taschenlampe',
  'scan_hint': 'Richten Sie die Kamera auf den QR-Code eines citadel://-Links',
  'camera_denied': 'Kein Kamerazugriff. Erlauben Sie die Kamera in den App-Einstellungen '
      'oder fügen Sie den Link manuell ein.',
  'camera_unavailable': 'Kamera nicht verfügbar: {error}. Fügen Sie den Link manuell ein.',
};

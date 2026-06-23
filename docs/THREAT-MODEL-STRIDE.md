# CitadelPQVPN — модель угроз (STRIDE)

**Документ-компаньон к SPEC.md (раскрывает §1). Метод: STRIDE per-element.**
Дата: 2026-06-19
Привязка к коду: M0 (`citadel-m0`), M1 (`citadel-m1` + `docker/`), spec L1 (`citadel-obfs`), data plane (`citadel-masque`).

---

## 1. Область, метод, границы доверия

**Метод:** STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) по элементам потока данных (DFD).

**Система (DFD, упрощённо):**
```
[Приложение]─(1)─►[TUN client]─(2)─►[citadel-m1 client]═══(3: PQ-QUIC)═══►[citadel-m1 exit]─(4)─►[TUN exit]─(5: NAT)─►[Интернет]
                                          ▲                                    │
                                          └────────── (6: control/capsule) ────┘
   ── граница доверия A ──┤                ├── граница B (сеть/цензор) ──┤        ├── граница C (exit↔интернет) ──
```

**Границы доверия:**
- **A** — устройство пользователя (приложение ↔ наш клиент). Доверяем ОС; вредонос на устройстве — вне области (SPEC §0).
- **B** — публичная сеть между client и exit. Здесь сидят A1 (HNDL), A2 (DPI), A3 (пробер), A5 (MITM). Главная граница.
- **C** — exit ↔ интернет. Здесь exit действует как NAT-шлюз; провайдер (A4) видит выходной трафик.

**Активы:** (K1) сессионные ключи / содержимое трафика; (K2) долговременные секреты (server-ключ, PSK); (K3) метаданные/идентичность пользователя; (K4) доступность сервиса; (K5) ресурсы exit-узла (полоса, IP-репутация); (K6) внутренняя сеть exit (docker/host/metadata).

**Противники (SPEC §1):** A1 пассивный+CRQC, A2 DPI-цензор, A3 пробер, A4 провайдер, A5 MITM.

---

## 2. STRIDE-анализ по категориям

Статусы: ✅ закрыто · 🟡 частично/план · 🔴 разрыв (gap) · ⚪ вне области/by-design.
«Fixed-now» помечает то, что устранено в этой итерации (см. §3).

### S — Spoofing (подмена сущности)
| # | Угроза | Поток | Противник | Митигация | Статус |
|---|---|---|---|---|---|
| S1 | Подмена exit-сервера (MITM выдаёт себя за exit) | (3) | A5 (+CRQC) | TLS 1.3 server-auth + **pinning** (F1) + **M7 ML-DSA-65 подпись** (PQ — устойчиво к CRQC-MITM в реальном времени) | ✅ F1 + M7 (гибрид Ed25519+ML-DSA) |
| S2 | Подмена клиента / использование exit чужими | (3) | любой, кто достал до порта | M3 obfs PSK-гейт транспорта + **M4 per-user анонимный токен** на control-стриме | ✅ M3+M4 |
| S3 | Off-path инъекция в QUIC | (3) | A5 | QUIC connection ID + AEAD + анти-spoofing миграции | ✅ (quinn) |
| S4 | Подмена inner-source IP клиентом (выдать чужой src) | (4) | клиент | Ingress-фильтр на exit по назначению; src-проверка | 🟡 dst-фильтр **fixed-now (F2)**; src-pinning → M2 |

### T — Tampering (искажение данных)
| # | Угроза | Поток | Митигация | Статус |
|---|---|---|---|---|
| T1 | Изменение/инъекция пакетов в туннеле | (3) | AEAD TLS 1.3 over QUIC (целостность) | ✅ |
| T2 | Искажение obfs-заголовка (когда L1 включён) | (B) | enc_header в AAD тела AEAD (PHASE0-OBFS §3.2) | ✅ в spec, 🟡 не подключён к транспорту (M3) |
| T3 | Подмена capsule (ADDRESS_ASSIGN) на control-stream | (6) | Идёт внутри QUIC-стрима (уже аутентифицирован peer'ом) | ✅ (после S1) |
| T4 | Порча образа/бинаря (supply chain) | сборка | Reproducible build, подпись (SPEC §4) | 🟡 план |

### R — Repudiation
| # | Угроза | Митигация | Статус |
|---|---|---|---|
| R1 | Пользователь отрицает действия | No-logs — **намеренно** (приватность, SPEC §8). Неотслеживаемость — цель, не дефект | ⚪ by-design |
| R2 | Нет аудита злоупотреблений exit | Минимальный rate-limit/abuse-counters без привязки к личности | 🟡 план (баланс с приватностью) |

### I — Information disclosure
| # | Угроза | Поток | Противник | Митигация | Статус |
|---|---|---|---|---|---|
| I1 | **Harvest-Now-Decrypt-Later** дешифровка трафика | (3) | A1+CRQC | Гибрид X25519+ML-KEM-768 (M0) | ✅ |
| I2 | Раскрытие, что это VPN (классификация протокола) | (B) | A2 | Обфускация L1 завёрнута под QUIC (на проводе — псевдослучайный поток) | ✅ M3 (ECH — позже) |
| I3 | DNS-leak (запросы мимо туннеля) | (1)(5) | A2/A4 | DNS только через туннель + fail-closed (drop прочего :53) + DoH | ✅ **F6** |
| I4 | Утечка SNI хендшейка туннеля | (3) | A2 | Обфускация L1 скрывает весь хендшейк → SNI на проводе нет | ✅ M3 (ECH — для mimicry-режима, future) |
| I5 | Корреляция по размеру/таймингу | (B) | A2 | Padding/шейпинг (PHASE0-OBFS §7) | 🟡 **размер:** bucketed padding `{256/512/1024/1280}` (default on); **тайминг:** slotted-пейсинг + chaff (`TYPE_PAD`, DAITA-стиль) в коде, env-gated `Citadel_PACING` (default off) |
| I6 | Провайдер связывает сессию с личностью/оплатой | (C) | A4 | **M4/M5: unlinkable blind-RSA токены + issuer↔exit split** (издатель подписывает вслепую в отдельном процессе, не видит токен) + no-logs | ✅ M4/M5 (exit видит трафик, но не личность; издатель видит оплату, но не токен) |

### D — Denial of service
| # | Угроза | Поток | Митигация | Статус |
|---|---|---|---|---|
| D1 | Амплификация на хендшейке (особенно большой PQC CH) | (3) | QUIC address validation / anti-amplification (quinn) | ✅ |
| D2 | Флуд датаграмм → OOM | (3)(4) | Ограниченные mpsc-каналы (backpressure), drop при переполнении | ✅ (bounded 1024) |
| D3 | Открытый exit-релей (нет client-auth) → исчерпание ресурсов/абуз | (3) | M3 obfs PSK + M4 токен гейтят доступ; rate-limit (F7) | ✅ доступ закрыт (M3/M4) + per-client token-bucket rate-limit (F7) |
| D4 | Probe-флуд на сервер | (B) | Probe-resistance L1 (молчание без PSK) | ✅ M3 |

### E — Elevation of privilege
| # | Угроза | Митигация | Статус |
|---|---|---|---|
| E1 | **Туннель→внутренняя сеть exit** (клиент шлёт на 169.254.169.254/RFC1918/loopback → metadata/docker/host) | Egress-фильтр на exit: drop приватных/служебных назначений | ✅ **fixed-now (F2)** |
| E2 | Процесс exit/client работает как root (нужен CAP_NET_ADMIN) | Сброс до nobody (65534) после setup; data-path работает без root | ✅ **fixed (F4)** |
| E3 | Side-channel в PQC (KyberSlash и т.п.) | Только проверенные реализации (aws-lc-rs) | ✅ |
| E4 | Контейнер с NET_ADMIN/`/dev/net/tun` | Минимум cap (только NET_ADMIN, без `--privileged`), отдельная netns | ✅ (compose) |

---

## 3. Findings → действия (приоритизировано)

| ID | Находка | Серьёзность | Действие | Когда |
|---|---|---|---|---|
| **F1** | Клиент принимал любой серверный сертификат (`AcceptAnyServerCert`) → MITM (S1) | **Высокая** | **Pinning** серверного ключа; клиент отвергает несовпадение | ✅ **сейчас** |
| **F2** | Exit форвардил inner-пакеты на любые адреса → пивот во внутреннюю сеть exit/metadata (E1, S4) | **Высокая** | **Egress-фильтр** на exit: drop приватных/loopback/link-local/multicast назначений | ✅ **сейчас** |
| F3 | Нет клиентской аутентификации/probe-resistance → открытый релей, палится зондированием (S2, D3, D4) | Высокая | PSK-гейт L1 (`citadel-obfs`): без PSK пакеты не открываются → exit молчит | ✅ **M3** |
| F4 | Процессы как root после настройки сети (E2) | Средняя | Drop до nobody (setgroups/setgid/setuid) после TUN/NAT/адресации | ✅ **сделано** |
| F5 | Обфускация L1 не подключена → трафик классифицируется как QUIC (I2, I5) | Высокая (для анти-DPI) | `citadel-obfs` завёрнут между UDP и QUIC (кастомный AsyncUdpSocket) | ✅ **M3** |
| F6 | DNS-leak, ECH не реализованы (I3, I4) | Средняя | DNS-leak protection (route+fail-closed+DoH); ECH субсумирован obfs (I4) | ✅ **сделано** |
| F7 | Нет rate-limit на exit (D3) | Средняя | Per-client лимиты (token bucket по байтам, env `Citadel_RATE_LIMIT`) | ✅ (проверено Docker-демо: флуд режется, легитимный трафик — нет) |

**Решение по итерации:** закрываем **F1 (pinning)** и **F2 (egress-фильтр)** немедленно — это реальные дыры в текущем PoC. F3/F5 — следующий крупный блок (M3, обфускация даёт сразу probe-resistance + client-auth + анти-DPI). F4/F6/F7 — в backlog с явным статусом.

---

## 4. Влияние на дорожную карту (актуально)
- ✅ **M1:** F1 (pinning), F2 (egress-фильтр).
- ✅ **M2:** динамическое назначение адреса капсулами (ADDRESS_ASSIGN) + control-stream.
- ✅ **M3:** обфускация L1 под QUIC — закрыла **F3** (probe-resistance + client-auth по PSK) и **F5** (анти-DPI); попутно D4 (probe-флуд) и I2 (классификация как VPN).
- ✅ **F4:** сброс привилегий до nobody после настройки сети (E2) — data-path работает без root.
- ✅ **F6:** DNS-leak protection (резолвер только через туннель + fail-closed) + DoH через туннель (I3); SNI хендшейка скрыт obfs (I4).
- ✅ **M4:** per-user unlinkable аутентификация (blind RSA, RFC 9474) — закрыла S2 (client-auth) и I6 (провайдер не связывает сессию с личностью); токен на control-стриме + double-spend учёт.
- ✅ **I5 (размер):** bucketed padding DATA на проводе `{256/512/1024/1280}` — `Citadel_obfs::pad_len_for` + политика в `ObfsUdpSocket` (default `Bucket(DEFAULT_BUCKETS)`); распределение длин схлопнуто в ≤4 значения. Покрыто тестами (инвариант «любая длина → бакет» + сквозной seal/open).
- ✅ **I5 (тайминг):** slotted-пейсинг + chaff в DAITA-стиле (как Mullvad 2024) — фоновый pacer выпускает пакеты по слот-сетке (квантует межпакетные интервалы), в паузы подмешивает dummy (`TYPE_PAD`, политики Off/Adaptive-WTF-PAD/Always). Bounded-очередь (дроп при переполнении = потеря UDP). Env-gated `Citadel_PACING` (default off — торгует латентностью). Покрыто юнит- (chaff-решение, парсер) + интеграционным loopback-тестом (pacer реально шлёт данные+chaff). **Не прогнано в Docker-туннеле** (нет CAP_NET_ADMIN локально).
- ✅ **F7:** per-client rate-limit на exit — token bucket по байтам в `pump` (входящее от клиента, `Citadel_quic::ratelimit`), env `Citadel_RATE_LIMIT`/`Citadel_RATE_BURST`. Превышение → дроп датаграммы (QUIC ретрансмитит). Проверено Docker-демо (ТЕСТ 9): preload-флуд режется (~88% loss + лог дропов), ping/HTTP не затронуты.
- ⬜ Дальше: включить/оттюнить пейсинг в туннеле (chaff-распределение = реальному, пейсинг входящего), полноценный h3 Extended-CONNECT, разделение issuer↔exit (интерактивный issuance).

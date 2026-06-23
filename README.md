# CitadelPQVPN — постквантовый консьюмерский VPN

Постквантовый VPN нового поколения: **QUIC/MASQUE**, гибридный обмен ключами `X25519 + ML-KEM-768`,
обфускация под анти-DPI, анонимная аутентификация и квантово-стойкая подпись сервера.
Rust + проверенные библиотеки (quinn, rustls/aws-lc-rs). Полный профиль и обоснования —
в [`docs/SPEC.md`](docs/SPEC.md).

> ⚠️ **Статус: исследовательский PoC (v0.1).** Код **не проходил независимый аудит безопасности**
> и **не предназначен для защиты в реальных условиях цензуры/слежки**. Не полагайтесь на него там,
> где от приватности зависит безопасность. Цель проекта — продемонстрировать архитектуру и собрать
> её до конца дорожной карты M0–M7.

## Что внутри (вся roadmap M0–M7 ✅)

- **PQ-транспорт (M0):** гибридный QUIC-хендшейк `X25519MLKEM768` (анти-Harvest-Now-Decrypt-Later).
- **Туннель (M1–M2):** CONNECT-IP поверх QUIC DATAGRAM, динамический адрес капсулой, NAT, pinning
  сертификата (F1), egress-фильтр против пивота во внутреннюю сеть (F2), сброс привилегий (F4),
  DNS-leak protection + DoH (F6).
- **Обфускация L1 (M3):** symmetric PSK-gated обёртка (Shadowsocks-2022-стиль) → на проводе
  псевдослучайный поток, probe-resistance (F3) и анти-DPI (F5). Анти-fingerprint по размеру
  (bucketed padding) и времени (DAITA-стиль пейсинг + chaff) — ось I5.
- **Анти-абуз (F7):** per-client token-bucket rate-limit на exit.
- **Resilience (M4):** TCP/443-fallback (obfs-over-TCP, когда UDP/QUIC заблокирован) +
  миграция соединения (WiFi↔LTE / NAT-rebind) по QUIC Connection ID.
- **Анонимность (M5):** unlinkable токены (blind RSA, RFC 9474) + интерактивный issuer↔exit split
  (издатель подписывает вслепую) + выбор exit из списка с failover.
- **Зрелость (M6):** robustness-fuzzing парсеров, criterion-бенчмарки ([`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)),
  кеш KDF/cipher в hot-path, crypto-agility (выбор KX-suite, TLS-negotiate).
- **PQ-аутентификация (M7):** гибрид Ed25519 (TLS-cert+pin) + **ML-DSA-65** (FIPS 204) —
  сервер ML-DSA-подписывает привязку сессии, клиент проверяет → анти-MITM устойчиво к CRQC.

Модель угроз и сопоставление findings → код — в [`docs/THREAT-MODEL-STRIDE.md`](docs/THREAT-MODEL-STRIDE.md).

## Архитектура (слои)

```
L4 control   токены/issuance, выбор exit, ADDRESS_ASSIGN (capsules)
L3 data      CONNECT-IP, IP-пакеты как QUIC DATAGRAM            ── citadel-masque, citadel-tun
L2 сессия    PQ-QUIC + TLS 1.3 (X25519MLKEM768), pinning, ML-DSA ── citadel-quic
L1 обфускация ChaCha20-Poly1305 PSK-wrap + padding/пейсинг       ── citadel-obfs
L0 транспорт UDP (основной) / TCP:443 (fallback)
```

| Крейт | Назначение |
|---|---|
| `citadel-obfs` | obfs L1 (PSK-gated AEAD, padding-политика, chaff) + байт-точные тест-векторы |
| `citadel-masque` | CONNECT-IP data plane: varint, datagram, capsules, IPv4/ICMP/UDP/DNS |
| `citadel-tun` | TUN-устройство (Linux `/dev/net/tun`) |
| `citadel-token` | анонимные токены (blind RSA) — роли клиент/издатель |
| `citadel-quic` | PQ-QUIC, obfs-socket, rate-limit, TCP-fallback, миграция, crypto-agility, PQ-auth; бинари `citadel-m0` (хендшейк-PoC), `citadel-m1` (туннель) |

## Быстрый старт

**Юнит-тесты (49, включая байт-точные obfs-векторы и fuzzing):**
```bash
# aws-lc-rs требует cmake; ставим в локальный venv без root (разово)
python3 -m venv .venv && .venv/bin/pip install cmake blake3 cryptography
PATH="$PWD/.venv/bin:$PATH" cargo test --workspace
```

**Бенчмарки:**
```bash
PATH="$PWD/.venv/bin:$PATH" cargo bench -p citadel-obfs   # см. docs/BENCHMARKS.md
```

**Полное демо — реальный туннель в Docker (15 сценариев M0–M7):**
```bash
bash docker/run-demo.sh                     # собрать → поднять issuer+2×exit+client → тесты
docker compose -f docker/compose.yml down   # остановить
```

Демо поднимает `issuer` + два `exit` + `client` в bridge-сети и прогоняет 15 тестов:
ping/HTTP через PQ-QUIC, egress-фильтр (F2), probe-resistance (F3), сброс привилегий (F4),
DNS-leak/DoH (F6), отказ поддельному токену (M4), rate-limit (F7), миграция (M4),
TCP/443-fallback (M4), multi-server failover (M5), слепой issuance (M5), crypto-agility (M6),
PQ-auth ML-DSA-65 позитив+негатив (M7).

Топология: `client TUN → [PQ-QUIC X25519MLKEM768 / obfs L1] → exit TUN → NAT → интернет`.

## Безопасность и секреты

- **Никаких секретов в репозитории.** Общий obfs-PSK, RSA-ключ издателя, ML-DSA-ключ exit,
  pin сертификата — **генерируются в рантайме** (в Docker-томе `pinshare`), не версионируются
  (см. `.gitignore`). В проде PSK/ключи доставляются по аутентифицированному каналу провижининга
  (docs/PHASE0-OBFS §8).
- Своё крипто не пишется — только проверенные примитивы (BLAKE3, ChaCha20-Poly1305, aws-lc-rs).
- Перед публичным форком замените `repository` в `Cargo.toml`.

## Нюансы окружения

- **`aws-lc-rs` требует `cmake`** (в `.venv`, без root) → перед `cargo` нужен `PATH="$PWD/.venv/bin:$PATH"`.
- **rustc 1.85 (без rustup)** → в `Cargo.lock` закреплён `time=0.3.41`.
- **Docker-образ** `debian:trixie-slim` (glibc как на хосте): бинарь собирается на хосте и копируется внутрь.
- **TUN в контейнере** требует `--cap-add=NET_ADMIN` + `--device=/dev/net/tun` (заданы в compose);
  локальная оболочка без CAP_NET_ADMIN реальный TUN не создаёт — поэтому туннель демонстрируется в Docker.

## Лицензия

[Apache-2.0](LICENSE).

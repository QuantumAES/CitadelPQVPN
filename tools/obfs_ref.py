#!/usr/bin/env python3
"""
CitadelPQVPN — референс-реализация obfs-слоя (L1), Фаза 0, протокол v1.
Назначение: КАНОНИЧЕСКИЙ генератор тест-векторов. Не для прод-использования
(нет постоянной защиты от replay, нет управления сессиями — только формат пакета).

Самопроверка:
  1) ChaCha20 keystream против RFC 8439 §2.3.2 (подтверждает формат IV: counter(4 LE)||nonce(12)).
  2) Круговой шифр/дешифр каждого тест-пакета (подтверждает самосогласованность вектора).

Запуск:  .venv/bin/python tools/obfs_ref.py
"""
from __future__ import annotations
import blake3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---- доменно-разделённые контексты KDF (фиксированы протоколом) ----
CTX_HDR     = "CitadelPQVPN/obfs/v1/header"
CTX_SESSION = "CitadelPQVPN/obfs/v1/session"

# ---- типы пакетов ----
TYPE_INIT_C = 0x01   # первый пакет клиента (несёт timestamp)
TYPE_INIT_S = 0x02   # первый пакет сервера  (несёт timestamp + echo_csid)
TYPE_DATA   = 0x03   # последующие пакеты любой стороны

# ---- KDF ----
def derive_key(context: str, key_material: bytes) -> bytes:
    return blake3.blake3(key_material, derive_key_context=context).digest(length=32)

def k_hdr(psk: bytes) -> bytes:
    return derive_key(CTX_HDR, psk)

def k_sess(psk: bytes, session_id: bytes) -> bytes:
    assert len(session_id) == 8
    return derive_key(CTX_SESSION, psk + session_id)

# ---- ChaCha20 «сырой» keystream (для шифрования заголовка) ----
def chacha20_keystream(key: bytes, nonce12: bytes, counter: int, n: int) -> bytes:
    assert len(nonce12) == 12
    iv = counter.to_bytes(4, "little") + nonce12      # формат OpenSSL/cryptography: counter(4 LE)||nonce(12)
    enc = Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor()
    return enc.update(b"\x00" * n)

def body_nonce(packet_id: int) -> bytes:
    return b"\x00\x00\x00\x00" + packet_id.to_bytes(8, "big")   # 12 байт

# ---- сборка inner_plaintext ----
def build_inner(ptype: int, *, timestamp: int | None, echo_csid: bytes | None,
                padding: bytes, quic_payload: bytes) -> bytes:
    out = bytes([ptype])
    if ptype in (TYPE_INIT_C, TYPE_INIT_S):
        assert timestamp is not None
        out += timestamp.to_bytes(8, "big")
    if ptype == TYPE_INIT_S:
        assert echo_csid is not None and len(echo_csid) == 8
        out += echo_csid
    out += len(padding).to_bytes(2, "big") + padding
    out += quic_payload
    return out

# ---- шифрование пакета ----
def seal(psk: bytes, session_id: bytes, packet_id: int, nonce_pkt: bytes,
         inner: bytes) -> dict:
    assert len(nonce_pkt) == 12 and len(session_id) == 8
    ks = chacha20_keystream(k_hdr(psk), nonce_pkt, 0, 16)
    hdr_pt = session_id + packet_id.to_bytes(8, "big")          # 16 байт
    enc_header = bytes(a ^ b for a, b in zip(hdr_pt, ks))       # XOR
    aad = nonce_pkt + enc_header                                # 28 байт
    aead = ChaCha20Poly1305(k_sess(psk, session_id))
    aead_body = aead.encrypt(body_nonce(packet_id), inner, aad)
    packet = nonce_pkt + enc_header + aead_body
    return dict(ks_hdr=ks, hdr_pt=hdr_pt, enc_header=enc_header, aad=aad,
                body_nonce=body_nonce(packet_id), aead_body=aead_body, packet=packet)

# ---- дешифрование (для round-trip проверки) ----
def open_packet(psk: bytes, packet: bytes) -> tuple[bytes, int, bytes]:
    nonce_pkt, enc_header, aead_body = packet[:12], packet[12:28], packet[28:]
    ks = chacha20_keystream(k_hdr(psk), nonce_pkt, 0, 16)
    hdr_pt = bytes(a ^ b for a, b in zip(enc_header, ks))
    session_id, packet_id = hdr_pt[:8], int.from_bytes(hdr_pt[8:16], "big")
    aad = nonce_pkt + enc_header
    inner = ChaCha20Poly1305(k_sess(psk, session_id)).decrypt(body_nonce(packet_id), aead_body, aad)
    return session_id, packet_id, inner

# ============================ САМОПРОВЕРКИ ============================
def selftest_rfc8439():
    # RFC 8439 §2.3.2: key=00..1f, nonce=00:00:00:09:00:00:00:4a:00:00:00:00, counter=1
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expect = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c0680304 22aa9ac3d46c4e".replace(" ", "")
        + "d2826446079faa0914c2d705d98b02a2"
        + "b5129cd1de164eb9cbd083e8a2503c4e")
    got = chacha20_keystream(key, nonce, 1, 64)
    assert got == expect, f"RFC8439 mismatch:\n got={got.hex()}\n exp={expect.hex()}"
    print("[selftest] ChaCha20 keystream == RFC 8439 §2.3.2  ✔  (IV-формат подтверждён)")

def roundtrip(name, psk, sid, pid, inner, packet):
    s, p, i = open_packet(psk, packet)
    assert s == sid and p == pid and i == inner, f"round-trip FAILED for {name}"
    print(f"[selftest] round-trip {name}: session_id/packet_id/inner восстановлены  ✔")

# ============================ ТЕСТ-ВЕКТОРЫ ============================
def h(b: bytes) -> str:
    return b.hex()

def dump(title, psk, sid, pid, nonce_pkt, inner, r):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)
    print(f"PSK_obf            ({len(psk):3}) = {h(psk)}")
    print(f"  K_hdr            ( 32) = {h(k_hdr(psk))}")
    print(f"  K_sess           ( 32) = {h(k_sess(psk, sid))}")
    print(f"session_id         (  8) = {h(sid)}")
    print(f"packet_id                = {pid}")
    print(f"nonce_pkt          ( 12) = {h(nonce_pkt)}")
    print(f"  KS_hdr[0:16]     ( 16) = {h(r['ks_hdr'])}")
    print(f"  hdr_pt(sid||pid) ( 16) = {h(r['hdr_pt'])}")
    print(f"  enc_header       ( 16) = {h(r['enc_header'])}")
    print(f"body_nonce         ( 12) = {h(r['body_nonce'])}")
    print(f"aad(npkt||enchdr)  ( 28) = {h(r['aad'])}")
    print(f"inner_plaintext    ({len(inner):3}) = {h(inner)}")
    print(f"aead_body(ct||tag) ({len(r['aead_body']):3}) = {h(r['aead_body'])}")
    print(f">> PACKET on wire  ({len(r['packet']):3}) = {h(r['packet'])}")

def main():
    selftest_rfc8439()

    PSK = bytes(range(32))                     # 000102...1f — фиксировано для вектора
    csid = bytes.fromhex("a1a2a3a4a5a6a7a8")
    ssid = bytes.fromhex("b1b2b3b4b5b6b7b8")

    # --- Вектор 1: INIT_C (клиент → сервер, первый пакет) ---
    npkt1 = bytes.fromhex("000102030405060708090a0b")
    ts1 = 1750000000
    pad1 = bytes.fromhex("f0f1f2f3")
    quic1 = bytes.fromhex("c000000001")        # имитация начала QUIC Initial (long header, ver 1)
    inner1 = build_inner(TYPE_INIT_C, timestamp=ts1, echo_csid=None, padding=pad1, quic_payload=quic1)
    r1 = seal(PSK, csid, 0, npkt1, inner1)
    dump("ВЕКТОР 1 — INIT_C (client→server, packet_id=0)", PSK, csid, 0, npkt1, inner1, r1)
    roundtrip("INIT_C", PSK, csid, 0, inner1, r1["packet"])

    # --- Вектор 2: INIT_S (сервер → клиент, ответ, echo csid) ---
    npkt2 = bytes.fromhex("101112131415161718191a1b")
    ts2 = 1750000001
    quic2 = bytes.fromhex("c000000001")
    inner2 = build_inner(TYPE_INIT_S, timestamp=ts2, echo_csid=csid, padding=b"", quic_payload=quic2)
    r2 = seal(PSK, ssid, 0, npkt2, inner2)
    dump("ВЕКТОР 2 — INIT_S (server→client, packet_id=0, echo_csid)", PSK, ssid, 0, npkt2, inner2, r2)
    roundtrip("INIT_S", PSK, ssid, 0, inner2, r2["packet"])

    # --- Вектор 3: DATA (клиент → сервер, стационарный) ---
    npkt3 = bytes.fromhex("202122232425262728292a2b")
    quic3 = bytes.fromhex("411234")             # имитация QUIC short-header пакета
    inner3 = build_inner(TYPE_DATA, timestamp=None, echo_csid=None, padding=b"", quic_payload=quic3)
    r3 = seal(PSK, csid, 1, npkt3, inner3)
    dump("ВЕКТОР 3 — DATA (client→server, packet_id=1)", PSK, csid, 1, npkt3, inner3, r3)
    roundtrip("DATA", PSK, csid, 1, inner3, r3["packet"])

    # --- негативный тест: чужой PSK не проходит probe-resistance ---
    try:
        open_packet(bytes([0xFF]) * 32, r1["packet"])
        raise SystemExit("FAIL: пакет расшифровался под неверным PSK (probe-resistance сломан)")
    except Exception as e:
        if isinstance(e, SystemExit):
            raise
        print("\n[selftest] неверный PSK → AEAD verify FAILED (probe-resistance держит)  ✔")

if __name__ == "__main__":
    main()

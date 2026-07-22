//! `WindowsTunProvider` — `TunProvider` для Windows-desktop (модель W2: служба-плумбер + пакет-пайп).
//!
//! Windows-аналог `GuiTunProvider` (Linux). Привилегированную часть (создание WinTUN-адаптера +
//! маршруты/DNS/WFP-kill-switch) делает служба **`citadel-svc`** (ставится elevated при установке
//! приложения); адаптер и её I/O-петля живут В СЛУЖБЕ, а неприв. приложение общается с ней по
//! **named pipe** `\\.\pipe\citadel-svc`. Пайп играет роль fd из Linux-SCM_RIGHTS: конфиг → служба
//! поднимает адаптер → дальше двунаправленный поток IP-пакетов (кадры `winnet`), движок крутится в
//! приложении, как на Linux.
//!
//! **Чистый std** (без WinAPI-крейтов): named pipe открывается `OpenOptions`, `File::try_clone`
//! даёт независимые read/write-хендлы (Windows-пайп полнодуплексный) → recv и send не блокируют
//! друг друга. Вся тяжёлая WinAPI (WinTUN/WFP/SCM) — в службе (`citadel-svc`), не здесь.
//!
//! Fail-closed (C6/M9): чистый disconnect шлёт службе маркер `len==0` (аналог байта `'Q'` Linux) →
//! служба снимает WFP-kill-switch. Реконнект/краш = пайп рвётся БЕЗ маркера → служба видит EOF без
//! маркера → kill-switch ОСТАЁТСЯ (не утекает), ровно как helper держит iptables при EOF-без-'Q'.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::IO::CancelIoEx;

use citadel_quic::vpn::{TunParams, TunProvider};
use citadel_tun::TunIo;

use crate::winnet::{self, TunReady, TunSetup};

/// Named pipe, на котором слушает привилегированная служба `citadel-svc`.
pub const PIPE_PATH: &str = r"\\.\pipe\citadel-svc";

/// `TunProvider` для Windows-desktop: привилегии — в службе `citadel-svc`, связь по named pipe.
pub struct WindowsTunProvider {
    /// Путь named pipe службы (по умолчанию [`PIPE_PATH`]; переопределяемо для dev/тестов).
    pub pipe_path: String,
}

impl Default for WindowsTunProvider {
    fn default() -> Self {
        Self { pipe_path: PIPE_PATH.into() }
    }
}

impl TunProvider for WindowsTunProvider {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>> {
        // C8.3 split → (маршруты_в_туннель, CIDR_в_обход): та же winnet::split_routes, что на Linux
        // (единая split-семантика, включая Q5 kill-switch⇄split).
        let (routes, bypass) = winnet::split_routes(p.dest_mode, &p.routes, &p.dest_routes);
        let setup = TunSetup {
            addr: p.addr,
            prefix: p.prefix,
            mtu: p.mtu.parse().unwrap_or(1400),
            routes,
            dns: p.dns.clone(),
            exit_ips: p.exit_ips.clone(),
            bypass,
            killswitch: p.killswitch,
        };

        // Подключиться к службе. Named pipe на Windows открывается как обычный File; отсутствие пайпа
        // = служба не установлена/не запущена (понятная ошибка вместо «file not found»).
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.pipe_path)
            .with_context(|| {
                format!("служба citadel-svc недоступна ({}) — установлена и запущена?", self.pipe_path)
            })?;

        // Фаза конфигурации: шлём TunSetup → ждём READY (служба подняла адаптер/маршруты/WFP).
        pipe.write_all(&winnet::encode_config(&setup)).context("отправить конфиг службе")?;
        pipe.flush().ok();
        let ready = read_ready(&mut pipe).context("служба не подтвердила поднятие адаптера")?;
        let _ = ready.adapter_luid; // диагностический LUID (пока не используется)

        // Разделяем хендлы: recv и send идут по независимым дубликатам (Windows-пайп полнодуплексный),
        // чтобы блокирующее чтение не держало запись, и наоборот.
        let read = pipe.try_clone().context("клонировать read-хендл пайпа")?;
        let read_handle = read.as_raw_handle() as isize;
        Ok(Arc::new(WindowsTun {
            read: Mutex::new(read),
            write: Mutex::new(pipe),
            read_handle,
            cancelled: AtomicBool::new(false),
        }))
    }
}

/// Прочитать управляющий кадр READY от службы: `TAG_READY ‖ status ‖ u32(len) ‖ body`.
/// status==0 → body=CBOR(TunReady); ≠0 → body=UTF-8 причина (пробрасываем как ошибку).
fn read_ready(pipe: &mut File) -> Result<TunReady> {
    let mut hdr = [0u8; 6]; // TAG_READY(1) + status(1) + len(4, BE)
    pipe.read_exact(&mut hdr).context("читать READY-заголовок от службы")?;
    if hdr[0] != winnet::TAG_READY {
        bail!("неожиданный тег ответа службы: 0x{:02x}", hdr[0]);
    }
    let status = hdr[1];
    let len = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
    if len > winnet::MAX_READY_BODY {
        bail!("READY-тело от службы слишком длинное: {len} > {}", winnet::MAX_READY_BODY);
    }
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body).context("читать READY-тело")?;
    if status != 0 {
        bail!("служба отклонила поднятие адаптера: {}", String::from_utf8_lossy(&body));
    }
    winnet::decode_ready(&body)
}

/// Туннель поверх named pipe к службе. `read`/`write` — независимые дубликаты одного пайпа (recv не
/// блокирует send). На `Drop` хендлы закрываются → служба ловит EOF; без предшествующего маркера
/// чистого disconnect (`clean_shutdown`) → WFP-kill-switch остаётся (fail-closed).
struct WindowsTun {
    read: Mutex<File>,
    write: Mutex<File>,
    /// Сырое значение HANDLE read-пайпа для `CancelIoEx` — держим ВНЕ `read`-Mutex: recv удерживает
    /// его во время блокирующего ReadFile, брать хэндл из-под Mutex в `cancel` = дедлок.
    read_handle: isize,
    /// Флаг отмены: recv проверяет ПЕРЕД чтением — закрывает гонку «cancel до входа в ReadFile»
    /// (тогда CancelIoEx ничего не прерывает, но следующий recv увидит флаг и вернёт Err).
    cancelled: AtomicBool,
}

impl TunIo for WindowsTun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "recv отменён (disconnect)"));
        }
        let mut r = self.read.lock().unwrap();
        let mut lenb = [0u8; 2];
        r.read_exact(&mut lenb)?;
        let len = u16::from_be_bytes(lenb) as usize;
        if len == 0 {
            return Ok(0); // служба закрывает поток данных
        }
        if len > buf.len() {
            // Кадр больше буфера recv — вычитываем его целиком, чтобы не рассинхронить поток, и
            // сигналим ошибку (штатно не бывает: пакеты ≤ MTU ≤ buf).
            let mut skip = vec![0u8; len];
            r.read_exact(&mut skip)?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "кадр пакета больше буфера recv"));
        }
        r.read_exact(&mut buf[..len])?;
        Ok(len)
    }

    fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        if pkt.len() > winnet::MAX_PACKET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "пакет больше MAX_PACKET"));
        }
        let frame = winnet::encode_packet(pkt);
        let mut w = self.write.lock().unwrap();
        w.write_all(&frame)?;
        w.flush()?;
        Ok(pkt.len())
    }

    /// C6/M9: чистый disconnect → маркер `len==0` службе ПЕРЕД закрытием пайпа → она снимает
    /// WFP-kill-switch. Реконнект/краш этот метод не зовёт → служба видит EOF без маркера → KS держится.
    fn clean_shutdown(&self) {
        if let Ok(mut w) = self.write.lock() {
            let _ = w.write_all(&winnet::clean_disconnect_marker());
            let _ = w.flush();
        }
    }

    /// Прервать блокирующий ReadFile reader-потока (реконнект/disconnect). Сначала флаг (recv,
    /// ещё не вошедший в ReadFile, увидит его и выйдет), затем `CancelIoEx` (прерывает уже идущий
    /// ReadFile). Вместе закрывают гонку → reader гарантированно получает Err и отпускает `Arc`.
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // SAFETY: read_handle — валидный HANDLE пайпа, живёт пока жив self; CancelIoEx безопасен
        // из другого потока и на handle без активного I/O (тогда просто вернёт FALSE — игнорируем).
        unsafe {
            let _ = CancelIoEx(self.read_handle as HANDLE, std::ptr::null());
        }
    }
}

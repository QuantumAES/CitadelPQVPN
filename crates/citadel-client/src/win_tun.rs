//! `WindowsTunProvider` — `TunProvider` для Windows-desktop (модель W2: служба-плумбер + пакет-пайп).
//!
//! Windows-аналог `GuiTunProvider` (Linux). Привилегированную часть (создание WinTUN-адаптера +
//! маршруты/DNS/WFP-kill-switch) делает служба **`citadel-svc`** (ставится elevated при установке
//! приложения); адаптер и её I/O-петля живут В СЛУЖБЕ, а неприв. приложение общается с ней по
//! **named pipe** `\\.\pipe\citadel-svc`. Пайп играет роль fd из Linux-SCM_RIGHTS: конфиг → служба
//! поднимает адаптер → дальше двунаправленный поток IP-пакетов (кадры `winnet`), движок крутится в
//! приложении, как на Linux.
//!
//! **Overlapped (асинхронный) I/O.** Пайп открывается с `FILE_FLAG_OVERLAPPED`, и recv/send идут
//! overlapped-операциями (блокируемся через `GetOverlappedResult`). Это КРИТИЧНО: в СИНХРОННОМ режиме
//! ядро сериализует все операции на file-object'е (`FO_SYNCHRONOUS_IO`), поэтому блокирующий `recv`
//! (reader-поток data-plane ждёт пакет из туннеля) повиснув держал бы лок и глушил `send`
//! (writer-поток) — pump вставал, через туннель не шло НИ ОДНОГО пакета (QUIC idle-timeout).
//! `try_clone`/дубль хэндла НЕ спасает: сериализация идёт по file-object'у, а не по хэндлу. Overlapped
//! этого не делает: recv и send с раздельными OVERLAPPED идут независимо. reader и writer держат по
//! своему [`OvIo`] (событие+OVERLAPPED); пайп-хэндл общий.
//!
//! Fail-closed (C6/M9): чистый disconnect шлёт службе маркер `len==0` (аналог байта `'Q'` Linux) →
//! служба снимает WFP-kill-switch. Реконнект/краш = пайп рвётся БЕЗ маркера → служба видит EOF без
//! маркера → kill-switch ОСТАЁТСЯ (не утекает), ровно как helper держит iptables при EOF-без-'Q'.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use citadel_quic::vpn::{TunParams, TunProvider};
use citadel_tun::TunIo;

use crate::winnet::{self, TunReady, TunSetup};

/// Named pipe, на котором слушает привилегированная служба `citadel-svc`.
pub const PIPE_PATH: &str = r"\\.\pipe\citadel-svc";

/// UTF-16 нуль-терминированная строка для *W-API.
fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Владеющий overlapped-хэндл пайпа (закрывается на `Drop`). `isize` (а не `HANDLE=*mut c_void`),
/// чтобы структура была `Send`+`Sync` (движок клонирует `Arc<dyn TunIo>` между потоками).
struct PipeHandle(isize);
// SAFETY: named pipe допускает конкурентный overlapped Read/Write из разных потоков; хэндл валиден,
// пока жив self (закрывается один раз в Drop).
unsafe impl Send for PipeHandle {}
unsafe impl Sync for PipeHandle {}
impl Drop for PipeHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 — валидный хэндл пайпа, больше не используется.
        unsafe { CloseHandle(self.0 as HANDLE) };
    }
}

/// Пер-направленческий overlapped-контекст: manual-reset событие для блокирующего завершения ОДНОЙ
/// операции. Reader и writer держат по своему `OvIo` — иначе конкурентные операции делили бы одно
/// событие. `event` как `isize` для `Send`.
struct OvIo {
    event: isize,
}
// SAFETY: каждый OvIo используется под своим Mutex одним потоком за раз.
unsafe impl Send for OvIo {}
impl OvIo {
    fn new() -> io::Result<Self> {
        // manual-reset (TRUE), начально несигнальное, без имени.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(OvIo { event: event as isize })
    }

    /// Одна overlapped Read/Write → число переданных байт. `write=false` → ReadFile.
    fn one(&self, h: isize, ptr: *mut u8, len: u32, write: bool) -> io::Result<u32> {
        // SAFETY: h — валидный overlapped-хэндл пайпа; ptr/len — валидный буфер; ov живёт до конца
        // GetOverlappedResult (блокирует до завершения); event — валидное событие OvIo.
        unsafe {
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = self.event as HANDLE;
            ResetEvent(self.event as HANDLE);
            let ok = if write {
                WriteFile(h as HANDLE, ptr as *const u8, len, std::ptr::null_mut(), &mut ov)
            } else {
                ReadFile(h as HANDLE, ptr, len, std::ptr::null_mut(), &mut ov)
            };
            if ok == 0 {
                let e = windows_sys::Win32::Foundation::GetLastError();
                if e != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(e as i32));
                }
            }
            let mut done = 0u32;
            // bWait=TRUE: ждём на ov.hEvent; CancelIoEx (реконнект/disconnect) завершит с ошибкой.
            if GetOverlappedResult(h as HANDLE, &ov, &mut done, 1) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(done)
        }
    }

    fn read_exact(&self, h: isize, buf: &mut [u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = self.one(h, buf[off..].as_mut_ptr(), (buf.len() - off) as u32, false)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "пайп закрыт (EOF)"));
            }
            off += n as usize;
        }
        Ok(())
    }

    fn write_all(&self, h: isize, buf: &[u8]) -> io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n =
                self.one(h, buf[off..].as_ptr() as *mut u8, (buf.len() - off) as u32, true)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "пайп закрыт при записи"));
            }
            off += n as usize;
        }
        Ok(())
    }
}
impl Drop for OvIo {
    fn drop(&mut self) {
        // SAFETY: event — валидный хэндл события, больше не используется.
        unsafe { CloseHandle(self.event as HANDLE) };
    }
}

/// Открыть named pipe службы в overlapped-режиме.
fn open_overlapped_pipe(path: &str) -> io::Result<PipeHandle> {
    let name = wide(path);
    // SAFETY: name — валидная UTF-16 строка; прочие аргументы — константы/null.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(PipeHandle(h as isize))
}

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

        // Подключиться к службе (overlapped-хэндл). Отсутствие пайпа = служба не установлена/не
        // запущена (понятная ошибка вместо «file not found»).
        let pipe = open_overlapped_pipe(&self.pipe_path).with_context(|| {
            format!("служба citadel-svc недоступна ({}) — установлена и запущена?", self.pipe_path)
        })?;
        // Раздельные overlapped-контексты recv/send (общий хэндл, независимые OVERLAPPED).
        let read_io = OvIo::new().context("создать read-событие пайпа")?;
        let write_io = OvIo::new().context("создать write-событие пайпа")?;

        // Фаза конфигурации: шлём TunSetup → ждём READY (служба подняла адаптер/маршруты/WFP).
        write_io
            .write_all(pipe.0, &winnet::encode_config(&setup))
            .context("отправить конфиг службе")?;
        let ready = read_ready(&read_io, pipe.0).context("служба не подтвердила поднятие адаптера")?;
        let _ = ready.adapter_luid; // диагностический LUID (пока не используется)

        Ok(Arc::new(WindowsTun {
            pipe,
            read: Mutex::new(read_io),
            write: Mutex::new(write_io),
            cancelled: AtomicBool::new(false),
        }))
    }
}

/// Прочитать управляющий кадр READY от службы: `TAG_READY ‖ status ‖ u32(len) ‖ body`.
/// status==0 → body=CBOR(TunReady); ≠0 → body=UTF-8 причина (пробрасываем как ошибку).
fn read_ready(io: &OvIo, h: isize) -> Result<TunReady> {
    let mut hdr = [0u8; 6]; // TAG_READY(1) + status(1) + len(4, BE)
    io.read_exact(h, &mut hdr).context("читать READY-заголовок от службы")?;
    if hdr[0] != winnet::TAG_READY {
        bail!("неожиданный тег ответа службы: 0x{:02x}", hdr[0]);
    }
    let status = hdr[1];
    let len = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
    if len > winnet::MAX_READY_BODY {
        bail!("READY-тело от службы слишком длинное: {len} > {}", winnet::MAX_READY_BODY);
    }
    let mut body = vec![0u8; len];
    io.read_exact(h, &mut body).context("читать READY-тело")?;
    if status != 0 {
        bail!("служба отклонила поднятие адаптера: {}", String::from_utf8_lossy(&body));
    }
    winnet::decode_ready(&body)
}

/// Туннель поверх overlapped named pipe к службе. `read`/`write` — раздельные OVERLAPPED-контексты
/// (recv не блокирует send). На `Drop` пайп закрывается → служба ловит EOF; без предшествующего
/// маркера чистого disconnect (`clean_shutdown`) → WFP-kill-switch остаётся (fail-closed).
struct WindowsTun {
    pipe: PipeHandle,
    read: Mutex<OvIo>,
    write: Mutex<OvIo>,
    /// Флаг отмены: recv проверяет ПЕРЕД чтением — закрывает гонку «cancel до входа в ReadFile»
    /// (тогда CancelIoEx ничего не прерывает, но следующий recv увидит флаг и вернёт Err).
    cancelled: AtomicBool,
}

impl TunIo for WindowsTun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "recv отменён (disconnect)"));
        }
        let io = self.read.lock().unwrap();
        let h = self.pipe.0;
        let mut lenb = [0u8; 2];
        io.read_exact(h, &mut lenb)?;
        let len = u16::from_be_bytes(lenb) as usize;
        if len == 0 {
            return Ok(0); // служба закрывает поток данных
        }
        if len > buf.len() {
            // Кадр больше буфера recv — вычитываем его целиком, чтобы не рассинхронить поток, и
            // сигналим ошибку (штатно не бывает: пакеты ≤ MTU ≤ buf).
            let mut skip = vec![0u8; len];
            io.read_exact(h, &mut skip)?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "кадр пакета больше буфера recv"));
        }
        io.read_exact(h, &mut buf[..len])?;
        Ok(len)
    }

    fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        if pkt.len() > winnet::MAX_PACKET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "пакет больше MAX_PACKET"));
        }
        let frame = winnet::encode_packet(pkt);
        let io = self.write.lock().unwrap();
        io.write_all(self.pipe.0, &frame)?;
        Ok(pkt.len())
    }

    /// C6/M9: чистый disconnect → маркер `len==0` службе ПЕРЕД закрытием пайпа → она снимает
    /// WFP-kill-switch. Реконнект/краш этот метод не зовёт → служба видит EOF без маркера → KS держится.
    fn clean_shutdown(&self) {
        if let Ok(io) = self.write.lock() {
            let _ = io.write_all(self.pipe.0, &winnet::clean_disconnect_marker());
        }
    }

    /// Прервать блокирующий overlapped-ReadFile reader-потока (реконнект/disconnect). Сначала флаг
    /// (recv, ещё не вошедший в ReadFile, увидит его и выйдет), затем `CancelIoEx` (прерывает уже
    /// идущий overlapped-ReadFile → GetOverlappedResult вернёт ошибку). Вместе закрывают гонку →
    /// reader гарантированно получает Err и отпускает `Arc`. `CancelIoEx` с null отменяет ВСЕ
    /// операции на хэндле (в т.ч. send) — при disconnect это и нужно.
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // SAFETY: pipe.0 — валидный HANDLE, живёт пока жив self; CancelIoEx безопасен из другого
        // потока и на handle без активного I/O (тогда просто вернёт FALSE — игнорируем).
        unsafe {
            CancelIoEx(self.pipe.0 as HANDLE, std::ptr::null());
        }
    }
}

//! Debug-логи: захват process-stderr в приложение (Фаза A, задача 2).
//!
//! На Android (и при запуске из GUI на десктопе) весь диагностический `eprintln!` движка —
//! все строки `[citadel-m1:client] …`, включая per-attempt ошибки QUIC/obfs при коннекте —
//! уходит в никуда, и причину сбоя не видно. Здесь мы ОДИН раз подменяем fd 2 (stderr) на
//! pipe и построчно раздаём вывод в UI: в broadcast-шину (живой хвост) и кольцевой буфер
//! (история), одновременно **тиражируя строки в сохранённый оригинальный stderr** (консоль/
//! logcat не теряем). Так весь вывод ядра виден в приложении без правки сотен call-site'ов.
//!
//! Ограничение: quinn/rustls логируют через `tracing`/`log`, не в stderr — они сюда не попадут;
//! наши `eprintln!` (именно диагностика коннекта) — попадут.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use flutter_rust_bridge::frb;
use std::io::Write;
use std::path::PathBuf;

use tokio::sync::broadcast;

use crate::frb_generated::StreamSink;

/// Файл персиста лога: строки дублируются сюда, чтобы ПЕРЕЖИТЬ краш процесса (Android hard-abort
/// в JNI/native теряет in-memory ring). При следующем запуске содержимое подхватывается в панель —
/// так виден лог/паника прошлой (упавшей) сессии без adb/logcat.
static LOG_FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Задать путь файла-персиста лога. NB (S1.4/M8): сам файловый персист по умолчанию ВЫКЛЮЧЕН
/// (приватность — лог несёт серверы/адреса/время); файл пишется ТОЛЬКО при `Citadel_DEBUG_LOG`,
/// иначе лог живёт лишь в in-memory ring. Путь задаётся заранее, чтобы дебаг-режим знал, куда писать.
#[frb(sync)]
pub fn set_log_file(path: String) {
    *LOG_FILE.lock().unwrap() = Some(PathBuf::from(path));
}

/// Сколько последних строк держим для истории (снимок/прайминг панели).
const RING_CAP: usize = 2000;
/// Ёмкость broadcast-канала живого хвоста (при переполнении подписчик получает Lagged — пропуск).
const CHAN_CAP: usize = 512;

struct LogBus {
    tx: broadcast::Sender<String>,
    ring: Mutex<VecDeque<String>>,
}

/// Глобальная шина логов. Ленивая — существует независимо от того, начат ли захват stderr,
/// чтобы `debug_log_stream`/`snapshot` были безопасны даже до `start_log_capture`.
fn bus() -> &'static LogBus {
    static BUS: OnceLock<LogBus> = OnceLock::new();
    BUS.get_or_init(|| {
        let (tx, _) = broadcast::channel(CHAN_CAP);
        LogBus {
            tx,
            ring: Mutex::new(VecDeque::with_capacity(RING_CAP)),
        }
    })
}

/// Положить строку в шину: кольцевой буфер (с вытеснением старых) + broadcast живого хвоста +
/// дозапись в файл персиста (переживает краш). Файл открывается per-line (flush) — объём логов
/// коннекта скромный, а надёжность важнее (краш не должен потерять последние строки).
fn push_line(line: String) {
    {
        let mut r = bus().ring.lock().unwrap();
        if r.len() == RING_CAP {
            r.pop_front();
        }
        r.push_back(line.clone());
    }
    // S1.4/M8: файл-персист только при явном опте (Citadel_DEBUG_LOG); по умолчанию — ring-only.
    if PERSIST.load(Ordering::Relaxed) {
        if let Some(path) = LOG_FILE.lock().unwrap().as_ref() {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, "{line}");
            }
        }
    }
    let _ = bus().tx.send(line); // Err только если нет подписчиков — игнор
}

/// Подхватить лог предыдущего (возможно упавшего) запуска в ring и обрезать файл под новую сессию.
/// Зовётся из `start_log_capture` до первых новых строк.
fn load_prev_log_history() {
    // S1.4/M8: без персиста (дефолт) файл не читаем и не создаём — никакого следа на диске.
    if !PERSIST.load(Ordering::SeqCst) {
        return;
    }
    let path = match LOG_FILE.lock().unwrap().clone() {
        Some(p) => p,
        None => return,
    };
    if let Ok(prev) = std::fs::read_to_string(&path) {
        let lines: Vec<&str> = prev.lines().filter(|l| !l.is_empty()).collect();
        if !lines.is_empty() {
            push_line_mem("──────── лог предыдущего запуска (для диагностики краша) ────────".into());
            for l in lines.iter().rev().take(RING_CAP).rev() {
                push_line_mem((*l).to_string());
            }
            push_line_mem("──────── текущий запуск ────────".into());
        }
    }
    let _ = std::fs::write(&path, ""); // новая сессия пишет с чистого файла
}

/// Как `push_line`, но ТОЛЬКО в ring/broadcast (без записи в файл) — для подгрузки истории,
/// чтобы не дублировать прошлые строки обратно в файл.
fn push_line_mem(line: String) {
    {
        let mut r = bus().ring.lock().unwrap();
        if r.len() == RING_CAP {
            r.pop_front();
        }
        r.push_back(line.clone());
    }
    let _ = bus().tx.send(line);
}

static CAPTURE_STARTED: AtomicBool = AtomicBool::new(false);
/// S1.4/M8: включён ли файловый персист лога. По умолчанию НЕТ (только in-memory ring) — иначе
/// на диске остаётся форензик-след коннектов (против no-logs). Опт-ин: env `Citadel_DEBUG_LOG`.
static PERSIST: AtomicBool = AtomicBool::new(false);

/// Один раз подменить stderr на pipe и начать раздачу строк в UI. Идемпотентно; зовётся из
/// `main.dart` сразу после `RustLib.init()`. Unix — dup2(fd 2); Windows — SetStdHandle(STDERR).
/// На прочих ОС — no-op.
#[frb(sync)]
pub fn start_log_capture() {
    #[cfg(any(unix, windows))]
    {
        if CAPTURE_STARTED.swap(true, Ordering::SeqCst) {
            return; // уже запущен
        }
        // S1.4/M8: файловый персист лога — OPT-IN. По умолчанию только in-memory ring (гаснет с
        // процессом, следа на диске нет). Включаем персист ТОЛЬКО по явному Citadel_DEBUG_LOG.
        if std::env::var("Citadel_DEBUG_LOG").is_ok() {
            PERSIST.store(true, Ordering::SeqCst);
        }
        let _ = bus(); // материализуем шину до первых writer'ов
        load_prev_log_history(); // (только при персисте) лог прошлой упавшей сессии → в панель
        // SAFETY: одноразовая подмена fd 2 под защитой CAPTURE_STARTED; читатель дренирует pipe.
        unsafe { spawn_stderr_capture() };
        // Паника ядра → в stderr (уже захвачен) ДО возможного abort: сообщение и место видны
        // в лог-панели, даже если процесс затем падает (диагностика нативных крашей на Android).
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("[PANIC] {info}");
            prev(info);
        }));
    }
}

/// Подменить fd 2 на write-конец pipe, поток-читатель раздаёт строки в шину и тиражирует их в
/// сохранённый оригинальный stderr. Читатель постоянно дренирует pipe — иначе его 64K-буфер
/// заполнится и заблокирует любой `eprintln!` в движке.
#[cfg(unix)]
unsafe fn spawn_stderr_capture() {
    use std::io::{BufRead, BufReader};
    use std::os::fd::FromRawFd;

    // сохранить оригинальный stderr (для тиража)
    let orig = libc::dup(libc::STDERR_FILENO);
    if orig < 0 {
        CAPTURE_STARTED.store(false, Ordering::SeqCst);
        return;
    }
    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        libc::close(orig);
        CAPTURE_STARTED.store(false, Ordering::SeqCst);
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);
    if libc::dup2(wr, libc::STDERR_FILENO) < 0 {
        libc::close(orig);
        libc::close(rd);
        libc::close(wr);
        CAPTURE_STARTED.store(false, Ordering::SeqCst);
        return;
    }
    libc::close(wr); // fd 2 теперь и есть write-конец

    let _ = std::thread::Builder::new()
        .name("citadel-logcap".into())
        .spawn(move || {
            let reader = BufReader::new(std::fs::File::from_raw_fd(rd));
            for line in reader.lines() {
                let Ok(line) = line else { break };
                // тираж в оригинальный stderr (консоль/logcat); '\n' восстанавливаем
                let with_nl = format!("{line}\n");
                libc::write(orig, with_nl.as_ptr() as *const libc::c_void, with_nl.len());
                push_line(line);
            }
            libc::close(orig);
        });
}

/// Windows-аналог: подменить `STD_ERROR_HANDLE` на write-конец пайпа. Rust-`std` перечитывает
/// std-handle через `GetStdHandle` на КАЖДЫЙ write, поэтому `eprintln!` движка (все `[citadel-m1:
/// client] …`, паники) после подмены уходят в пайп. Поток-читатель раздаёт строки в шину и (если
/// консоль есть, напр. `flutter run`) тиражирует в исходный stderr. У GUI-процесса без консоли
/// исходный handle null → тираж пропускаем, но захват в UI работает. Пайп никто не закрывает
/// (это process-stderr) → читатель живёт до конца процесса, как unix-версия.
#[cfg(windows)]
unsafe fn spawn_stderr_capture() {
    use std::io::{BufRead, BufReader};
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE};
    use windows_sys::Win32::System::Pipes::CreatePipe;

    // Исходный stderr (для тиража). null/невалидный у GUI-процесса без консоли — тогда тираж no-op.
    let orig: HANDLE = GetStdHandle(STD_ERROR_HANDLE);

    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: read/write — валидные out-указатели; дефолтные атрибуты, дефолтный размер буфера.
    if CreatePipe(&mut read, &mut write, std::ptr::null(), 0) == 0 {
        CAPTURE_STARTED.store(false, Ordering::SeqCst);
        return;
    }
    // Подменить process-stderr на write-конец пайпа. С этого момента eprintln! ядра → пайп.
    if SetStdHandle(STD_ERROR_HANDLE, write) == 0 {
        CloseHandle(read);
        CloseHandle(write);
        CAPTURE_STARTED.store(false, Ordering::SeqCst);
        return;
    }

    // HANDLE (`*mut c_void`) не `Send` → переносим в поток как isize-значения и восстанавливаем.
    let (read_val, orig_val) = (read as isize, orig as isize);
    let _ = std::thread::Builder::new()
        .name("citadel-logcap".into())
        .spawn(move || {
            let read = read_val as HANDLE;
            let orig = orig_val as HANDLE;
            // Владеем read-концом как File (закроется при завершении процесса).
            let reader = BufReader::new(std::fs::File::from_raw_handle(read as _));
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if !orig.is_null() && orig != INVALID_HANDLE_VALUE {
                    // тираж в исходный stderr (консоль); CRLF как принято на Windows-консоли
                    let with_nl = format!("{line}\r\n");
                    let mut wrote = 0u32;
                    let _ = WriteFile(
                        orig,
                        with_nl.as_ptr(),
                        with_nl.len() as u32,
                        &mut wrote,
                        std::ptr::null_mut(),
                    );
                }
                push_line(line);
            }
        });
}

/// Живой хвост логов: подписка на новые строки (после `start_log_capture`). Отдаётся Dart'у
/// как `Stream<String>`. Крутится в отдельном потоке (broadcast::blocking_recv), рвётся когда
/// Dart отписался.
pub fn debug_log_stream(sink: StreamSink<String>) {
    let mut rx = bus().tx.subscribe();
    std::thread::spawn(move || loop {
        match rx.blocking_recv() {
            Ok(line) => {
                if sink.add(line).is_err() {
                    break; // Dart отписался
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue, // пропустили — не страшно
            Err(broadcast::error::RecvError::Closed) => break,
        }
    });
}

/// Снимок кольцевого буфера (история — для прайминга панели и «Копировать»).
#[frb(sync)]
pub fn debug_log_snapshot() -> Vec<String> {
    bus().ring.lock().unwrap().iter().cloned().collect()
}

/// Очистить историю логов.
#[frb(sync)]
pub fn debug_log_clear() {
    bus().ring.lock().unwrap().clear();
}

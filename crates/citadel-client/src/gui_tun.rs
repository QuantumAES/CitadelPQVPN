//! `GuiTunProvider` — `TunProvider` для Linux-desktop GUI (трек C2.3).
//!
//! Привилегированную часть (создание TUN + адрес/маршруты/DNS) делает отдельный процесс
//! `citadel-helper`, запускаемый через **polkit/pkexec**; fd туннеля приходит обратно по
//! `SCM_RIGHTS`, и приложение крутит data-plane без root. См. docs/CLIENT-ARCH.md §4, §7.
//!
//! Поток: app слушает unix-сокет → `pkexec citadel-helper --sock … --addr …` (polkit-диалог)
//! → хелпер (root) создаёт TUN, настраивает сеть, шлёт fd → app оборачивает `Tun::from_raw_fd`.
//! На `Drop` возвращённого туннеля управляющий сокет закрывается → хелпер ловит EOF → сворачивает сеть.

use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use sendfd::RecvWithFd;

use citadel_quic::vpn::{TunParams, TunProvider};
use citadel_tun::{Tun, TunIo};

use crate::winnet;

/// Сколько ждать подключения хелпера (включает время на polkit-аутентификацию).
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

/// Стандартный путь установленного хелпера — совпадает с polkit `.policy` (`exec.path`) и
/// `tools/install-desktop.sh`. Для dev-запуска из build-дерева переопредели `helper_path`.
pub const HELPER_PATH: &str = "/usr/lib/citadel-pqvpn/citadel-helper";

/// `TunProvider` для Linux-desktop: привилегии — через polkit/pkexec + `citadel-helper`.
pub struct GuiTunProvider {
    /// Путь к бинарю `citadel-helper` (для pkexec). По умолчанию ищется в `PATH`.
    pub helper_path: String,
    /// Имя TUN-интерфейса.
    pub tun_name: String,
}

impl Default for GuiTunProvider {
    fn default() -> Self {
        Self {
            helper_path: HELPER_PATH.into(),
            tun_name: "citadel0".into(),
        }
    }
}

impl TunProvider for GuiTunProvider {
    fn configure(&self, p: &TunParams) -> Result<Arc<dyn TunIo>> {
        let sock = control_socket_path();
        let _ = std::fs::remove_file(&sock); // на случай stale-сокета
        let listener = UnixListener::bind(&sock).with_context(|| format!("bind {sock}"))?;
        listener.set_nonblocking(true)?;

        let addr = format!("{}.{}.{}.{}", p.addr[0], p.addr[1], p.addr[2], p.addr[3]);
        // C8.3 split-tunnel по назначению (ось приложений на Linux — позже):
        //   Include → в туннель ТОЛЬКО выбранные CIDR (default остаётся физическим, без IPv6-блока);
        //   Exclude → маршруты ссылки как есть + выбранные CIDR в обход (через физический шлюз);
        //   Off     → как раньше (маршруты ссылки).
        // C8.3 split → (маршруты_в_туннель, CIDR_в_обход): единый источник winnet (Linux+Windows).
        let (routes_vec, bypass_vec) = winnet::split_routes(p.dest_mode, &p.routes, &p.dest_routes);
        let (routes_str, bypass_str) = (routes_vec.join(" "), bypass_vec.join(" "));
        let mut cmd = Command::new("pkexec");
        cmd.arg(&self.helper_path).args([
            "--sock", &sock,
            "--tun", &self.tun_name,
            "--addr", &addr,
            "--prefix", &p.prefix.to_string(),
            "--mtu", &p.mtu,
            "--routes", &routes_str,
        ]);
        if let Some(dns) = &p.dns {
            cmd.args(["--dns", dns]);
        }
        // bypass-маршрут: exit'ы не должны маршрутизироваться в туннель (анти-петля при full-tunnel)
        if !p.exit_ips.is_empty() {
            cmd.args(["--exit-ips", &p.exit_ips.join(" ")]);
        }
        // C8.3 «в обход»: выбранные CIDR назначений роутятся мимо туннеля (напр. локальная подсеть)
        if !bypass_str.is_empty() {
            cmd.args(["--bypass", &bypass_str]);
        }
        // C6/M9 kill-switch: армируем fail-closed firewall в хелпере (снимется только на чистый
        // disconnect через сигнал 'Q' от GuiTun::clean_shutdown).
        if p.killswitch {
            cmd.arg("--killswitch");
        }
        let mut child = cmd.spawn().context("запустить pkexec citadel-helper")?;

        // ждём подключения хелпера (после polkit-auth); ловим отмену/ошибку pkexec
        let stream = accept_with_deadline(&listener, &mut child, HELPER_TIMEOUT)?;
        let _ = std::fs::remove_file(&sock); // путь больше не нужен — соединение установлено

        let fd = recv_fd(&stream).context("принять TUN-fd от citadel-helper")?;
        // SAFETY: fd только что получен от хелпера через SCM_RIGHTS, владеем им единолично.
        let tun = unsafe { Tun::from_raw_fd(fd) };
        Ok(Arc::new(GuiTun {
            tun,
            ctrl: stream,
            _child: child,
        }))
    }
}

/// Путь управляющего сокета (в XDG_RUNTIME_DIR, иначе /tmp); уникален по PID.
fn control_socket_path() -> String {
    let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    format!("{dir}/citadel-helper-{}.sock", std::process::id())
}

/// accept с дедлайном на неблокирующем listener; если pkexec-процесс умер до подключения
/// (отмена polkit / ошибка) — это видно по `try_wait`.
fn accept_with_deadline(
    listener: &UnixListener,
    child: &mut Child,
    timeout: Duration,
) -> Result<UnixStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?; // дальше recv_with_fd — блокирующе
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(status) = child.try_wait()? {
                    bail!("pkexec/citadel-helper завершился до подключения (отменён polkit?): {status}");
                }
                if Instant::now() > deadline {
                    bail!("таймаут ожидания citadel-helper ({}с)", timeout.as_secs());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Принять ровно один fd через SCM_RIGHTS.
fn recv_fd(stream: &UnixStream) -> Result<i32> {
    let mut buf = [0u8; 4];
    let mut fds = [0i32; 1];
    let (_n, fdn) = stream.recv_with_fd(&mut buf, &mut fds).context("recv_with_fd")?;
    if fdn != 1 {
        return Err(anyhow!("citadel-helper не передал ровно один fd (получено {fdn})"));
    }
    Ok(fds[0])
}

/// TUN от хелпера + удержание управляющего сокета и pkexec-процесса. На `Drop` сокет
/// закрывается → хелпер ловит EOF → сворачивает сеть (адрес/маршруты/DNS).
struct GuiTun {
    tun: Tun,
    ctrl: UnixStream,
    _child: Child,
}

impl TunIo for GuiTun {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tun.recv(buf)
    }
    fn send(&self, pkt: &[u8]) -> std::io::Result<usize> {
        self.tun.send(pkt)
    }
    fn raw_fd(&self) -> Option<i32> {
        self.tun.raw_fd()
    }
    /// C6/M9: чистый disconnect → шлём хелперу байт 'Q' ПЕРЕД закрытием сокета, чтобы он снял
    /// kill-switch. Реконнект-разрыв этот метод НЕ зовёт (VpnController) → helper видит EOF без 'Q'
    /// → KS остаётся (fail-closed в разрыве). Пишем в `&UnixStream` (реализует Write).
    fn clean_shutdown(&self) {
        use std::io::Write;
        let _ = (&self.ctrl).write_all(b"Q");
        let _ = (&self.ctrl).flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sendfd::SendWithFd;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    /// `recv_fd` принимает дескриптор через SCM_RIGHTS (зеркало отправки в citadel-helper) —
    /// без root: гоняем pipe-fd через socketpair и проверяем, что принятый fd — та же труба.
    #[test]
    fn recv_fd_gets_passed_descriptor() {
        let (sender, receiver) = UnixStream::pair().unwrap();

        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);

        sender.send_with_fd(b"T", &[r]).unwrap();
        let got = recv_fd(&receiver).unwrap();

        let mut wf = unsafe { std::fs::File::from_raw_fd(w) };
        wf.write_all(b"ok").unwrap();
        let mut rf = unsafe { std::fs::File::from_raw_fd(got) };
        let mut buf = [0u8; 2];
        rf.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");

        unsafe { libc::close(r) };
    }
}

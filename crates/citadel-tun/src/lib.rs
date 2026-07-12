//! CitadelPQVPN — `citadel-tun`: TUN-устройство (Linux).
//!
//! Открывает `/dev/net/tun` и регистрирует интерфейс через `TUNSETIFF`
//! (IFF_TUN | IFF_NO_PI — чистые IP-пакеты без 4-байтового префикса протокола).
//!
//! **Требует CAP_NET_ADMIN** (root или `setcap cap_net_admin+ep`, либо контейнер
//! с `--cap-add=NET_ADMIN --device=/dev/net/tun`). Это привилегированный путь L3.
//!
//! Блокирующий API (`recv`/`send`) — потокобезопасно делится через `Arc<Tun>`:
//! чтение и запись идут как независимые syscalls на одном fd.

/// Абстракция пакетного I/O туннеля (L3): блокирующие `recv`/`send` одного IP-пакета.
///
/// Реализуется `Tun` (Linux `/dev/net/tun`) и платформенными обёртками клиента
/// (Android `VpnService` fd, Windows WinTUN, macOS utun). Data-plane ядра (`pump`)
/// работает поверх `Arc<dyn TunIo>` и не знает конкретной платформы — это и есть
/// граница, через которую ОС отдаёт туннель в движок (трек C*, см. docs/CLIENT-ARCH.md §4.1).
///
/// Блокирующий (не async) намеренно: `pump` уже изолирует чтение TUN в отдельном
/// потоке и мостит в async через канал, поэтому async тут лишний.
pub trait TunIo: Send + Sync + 'static {
    /// Читает один IP-пакет (блокирующе). Возвращает число прочитанных байт.
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Пишет один IP-пакет. Возвращает число записанных байт.
    fn send(&self, pkt: &[u8]) -> std::io::Result<usize>;
    /// Сырой fd туннеля (Unix) — для прерываемого `poll`-чтения в data-plane: позволяет
    /// reader'у выходить по сигналу отмены, а не висеть в блокирующем `recv`, держа
    /// `Arc<dyn TunIo>` (иначе TUN-fd/интерфейс не закрывается → утечка). `None` —
    /// реализация не на основе fd (тогда reader не прерывается через poll).
    fn raw_fd(&self) -> Option<i32> {
        None
    }
    /// Сигнал ЧИСТОГО disconnect (пользователь остановил VPN — НЕ реконнект). Реализации с
    /// привилегированным контроллером (`citadel-helper`) используют это, чтобы снять fail-closed
    /// kill-switch (C6/M9): реконнект-разрыв сигнал НЕ шлёт → KS держится в разрыве (не утекает).
    /// По умолчанию — no-op (для TUN на основе fd, VpnService и т.п.).
    fn clean_shutdown(&self) {}
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; 16],
        flags: libc::c_short,
        _pad: [u8; 22], // sizeof(struct ifreq) == 40 на Linux
    }

    /// Возвращает true, если процесс способен создать TUN (euid==0).
    pub fn has_privileges() -> bool {
        // SAFETY: geteuid не имеет побочных эффектов и всегда безопасен.
        unsafe { libc::geteuid() == 0 }
    }

    pub struct Tun {
        file: File,
        name: String,
    }

    impl Tun {
        /// Создаёт TUN-интерфейс с предложенным именем (например, "Citadel0").
        pub fn create(requested_name: &str) -> io::Result<Tun> {
            let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;

            let mut req = IfReq {
                name: [0; 16],
                flags: IFF_TUN | IFF_NO_PI,
                _pad: [0; 22],
            };
            // максимум 15 байт имени + нулевой терминатор (name: [c_char; 16]).
            for (slot, &b) in req.name.iter_mut().zip(requested_name.as_bytes()).take(15) {
                *slot = b as libc::c_char;
            }

            // SAFETY: fd валиден (только что открыт), req — корректный &mut на ifreq.
            // на bionic (Android) ioctl request — c_int, на glibc — c_ulong: `as _` подберёт тип
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReq) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            // Имя, фактически присвоенное ядром.
            let actual: Vec<u8> = req
                .name
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            let name = String::from_utf8_lossy(&actual).into_owned();
            Ok(Tun { file, name })
        }

        /// Оборачивает уже открытый fd туннеля — например, полученный от Android
        /// `VpnService.establish()`. Там адрес/маршруты/DNS настраивает сама ОС
        /// (`VpnService.Builder`), поэтому именем интерфейса мы не управляем.
        /// **Берёт владение** `fd`: закроет его при `drop`.
        ///
        /// # Safety
        /// `fd` обязан быть валидным открытым дескриптором, которым не владеет
        /// никто другой (иначе double-close / use-after-close).
        pub unsafe fn from_raw_fd(fd: RawFd) -> Tun {
            // SAFETY: контракт делегирован вызывающему (см. # Safety выше).
            // edition 2021: тело unsafe fn уже unsafe-контекст, отдельный блок не нужен.
            let file = File::from_raw_fd(fd);
            Tun {
                file,
                name: format!("tun-fd{fd}"),
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        /// Читает один IP-пакет из интерфейса (блокирующе).
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            (&self.file).read(buf)
        }

        /// Пишет один IP-пакет в интерфейс.
        pub fn send(&self, pkt: &[u8]) -> io::Result<usize> {
            (&self.file).write(pkt)
        }
    }

    impl crate::TunIo for Tun {
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            Tun::recv(self, buf)
        }
        fn send(&self, pkt: &[u8]) -> io::Result<usize> {
            Tun::send(self, pkt)
        }
        fn raw_fd(&self) -> Option<i32> {
            Some(self.file.as_raw_fd())
        }
    }

    /// Доступ к fd туннеля — нужен, чтобы передать его другому процессу через SCM_RIGHTS
    /// (привилегированный `citadel-helper` → непривилегированный GUI, трек C2.3).
    impl AsRawFd for Tun {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn ifreq_abi_size() {
            assert_eq!(std::mem::size_of::<IfReq>(), 40);
        }
        #[test]
        fn privilege_check_runs() {
            // Просто не должно паниковать; значение зависит от окружения.
            let _ = has_privileges();
        }

        /// `from_raw_fd` оборачивает чужой fd, а `recv`/`send` ходят через него —
        /// эмулируем «внешний fd» (как от VpnService) парой связанных сокетов и
        /// гоняем пакет в обе стороны, в т.ч. через трейт-объект `dyn TunIo`.
        #[test]
        fn from_raw_fd_roundtrip_via_socketpair() {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: fds — валидный буфер на 2 int; socketpair их инициализирует.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());

            // SAFETY: fds[0] только что создан socketpair и больше нигде не используется.
            let tun = unsafe { Tun::from_raw_fd(fds[0]) };
            assert_eq!(tun.name(), format!("tun-fd{}", fds[0]));
            // Другой конец — обычный File (берёт владение fds[1]).
            // SAFETY: fds[1] только что создан и принадлежит только нам.
            let mut peer = unsafe { File::from_raw_fd(fds[1]) };

            // Tun::send → читается на другом конце.
            assert_eq!(tun.send(b"ping").unwrap(), 4);
            let mut buf = [0u8; 8];
            let n = peer.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");

            // Запись на другом конце → читается Tun::recv через трейт-объект TunIo.
            peer.write_all(b"pong").unwrap();
            let io: &dyn crate::TunIo = &tun;
            let n = io.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"pong");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use imp::{has_privileges, Tun};

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

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::io::AsRawFd;

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
            let bytes = requested_name.as_bytes();
            let n = bytes.len().min(15);
            for i in 0..n {
                req.name[i] = bytes[i] as libc::c_char;
            }

            // SAFETY: fd валиден (только что открыт), req — корректный &mut на ifreq.
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
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
    }
}

#[cfg(target_os = "linux")]
pub use imp::{has_privileges, Tun};

//! Клиент управляющего сокета `citadel-vpnd`.
//!
//! Все ошибки подключения переводятся в понятные человеку подсказки: «нет прав» здесь почти
//! всегда означает «пользователь не в группе `citadel-vpn`», а «нет файла» — «юнит не запущен».

use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use citadel_vpnd::proto::{read_frame, write_frame, CtlRequest, CtlResponse, StatusInfo};
use citadel_vpnd::{CTL_GROUP, CTL_SOCKET};

/// Таймаут одной операции с демоном (он может выполнять `ip`/`iptables`).
const IO_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Client {
    path: String,
}

impl Default for Client {
    fn default() -> Self {
        // Путь можно переопределить для dev-запуска (демон под другим сокетом).
        Client {
            path: std::env::var("CITADEL_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.to_string()),
        }
    }
}

impl Client {
    pub fn socket_path(&self) -> &str {
        &self.path
    }

    fn connect(&self) -> Result<UnixStream> {
        match UnixStream::connect(&self.path) {
            Ok(s) => {
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                Ok(s)
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(anyhow!(
                "нет доступа к {}: добавьтесь в группу {CTL_GROUP} \
                 (sudo usermod -aG {CTL_GROUP} $USER, затем перелогиньтесь)",
                self.path
            )),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                Err(anyhow!(
                    "демон не отвечает на {}: sudo systemctl start citadel-vpnd",
                    self.path
                ))
            }
            Err(e) => Err(e).with_context(|| format!("подключиться к {}", self.path)),
        }
    }

    /// Одна операция «запрос → ответ».
    fn request(&self, req: CtlRequest) -> Result<CtlResponse> {
        let mut s = self.connect()?;
        write_frame(&mut s, &req)?;
        read_frame(&mut s)?.ok_or_else(|| anyhow!("демон закрыл соединение без ответа"))
    }

    fn expect_ok(&self, req: CtlRequest) -> Result<()> {
        match self.request(req)? {
            CtlResponse::Ok => Ok(()),
            CtlResponse::Err(e) => bail!("{e}"),
            other => bail!("неожиданный ответ демона: {other:?}"),
        }
    }

    pub fn status(&self) -> Result<StatusInfo> {
        match self.request(CtlRequest::Status)? {
            CtlResponse::Status(s) => Ok(s),
            CtlResponse::Err(e) => bail!("{e}"),
            other => bail!("неожиданный ответ демона: {other:?}"),
        }
    }

    pub fn version(&self) -> Result<String> {
        match self.request(CtlRequest::Version)? {
            CtlResponse::Version(v) => Ok(v),
            CtlResponse::Err(e) => bail!("{e}"),
            other => bail!("неожиданный ответ демона: {other:?}"),
        }
    }

    pub fn connect_session(&self, req: citadel_vpnd::proto::ConnectReq) -> Result<()> {
        self.expect_ok(CtlRequest::Connect(req))
    }

    pub fn disconnect(&self) -> Result<()> {
        self.expect_ok(CtlRequest::Disconnect)
    }

    pub fn disarm_killswitch(&self) -> Result<()> {
        self.expect_ok(CtlRequest::DisarmKillswitch)
    }

    /// Открыть поток событий. Читать — [`read_event`]; поток живёт, пока жив сокет.
    pub fn subscribe(&self) -> Result<UnixStream> {
        let mut s = self.connect()?;
        // Событий может не быть долго (сессия стоит) — читатель не должен падать по таймауту.
        s.set_read_timeout(None)?;
        write_frame(&mut s, &CtlRequest::Events)?;
        Ok(s)
    }
}

/// Прочитать очередное событие из потока подписки. `None` — поток закрыт.
pub fn read_event(s: &mut UnixStream) -> Result<Option<citadel_vpnd::proto::EventMsg>> {
    match read_frame::<_, CtlResponse>(s)? {
        Some(CtlResponse::Event(e)) => Ok(Some(e)),
        Some(CtlResponse::Err(e)) => bail!("{e}"),
        Some(_) => Ok(None),
        None => Ok(None),
    }
}

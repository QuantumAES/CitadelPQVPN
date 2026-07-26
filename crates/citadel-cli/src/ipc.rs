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

/// Работает ли демон из устаревшего бинаря: на диске лежит `citadel-vpnd` новее, чем момент
/// старта процесса, который отвечает нам по сокету.
///
/// Зачем это вообще нужно. `systemctl enable --now` НЕ перезапускает уже активный юнит, а
/// `daemon-reload` не перечитывает песочницу работающего процесса. Установщик до этого
/// обновлял файлы и на том останавливался, поэтому после апгрейда в системе продолжал жить
/// прежний демон — со старым кодом и старым `ProtectSystem`. Снаружи это неотличимо от
/// «баг не исправлен»: журнал показывает давно починенную ошибку, а исправление всё это
/// время лежит на диске. Проверка стоит один `stat` и снимает целый класс ложных диагнозов.
///
/// Возвращает `None`, когда сказать нечего: демон старой версии (не присылает время старта),
/// сокет переопределён (dev-запуск — штатный бинарь тогда не имеет отношения к делу), бинаря по
/// штатному пути нет, время недоступно. Подсказка обязана быть либо точной, либо отсутствовать:
/// ложная тревога о «старом демоне» отправила бы человека чинить не то.
pub fn stale_daemon_hint(st: &StatusInfo) -> Option<String> {
    if st.daemon_started_unix == 0 {
        return None; // демон до этой версии — сравнивать не с чем
    }
    if std::env::var_os("CITADEL_CTL_SOCKET").is_some() {
        return None; // говорим не со штатным юнитом — сверять с /usr/lib нечего
    }
    let mtime = std::fs::metadata(citadel_vpnd::DAEMON_PATH)
        .and_then(|m| m.modified())
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    // Запас в минуту: во время установки файл кладётся и юнит перезапускается почти
    // одновременно, и точности секунд тут доверять не стоит.
    if mtime <= st.daemon_started_unix + 60 {
        return None;
    }
    Some(format!(
        "работает УСТАРЕВШИЙ демон: {} на диске новее запущенного процесса.\n\
         \x20 Обновление применится только после перезапуска: sudo systemctl restart citadel-vpnd",
        citadel_vpnd::DAEMON_PATH
    ))
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

//! `AdminDeployer` (трек C4) — разворачивание серверного стека по SSH.
//!
//! SSH-клиент — **russh** (чистый Rust, backend aws-lc-rs; без OpenSSL-C, чтобы не ломать
//! мобильную сборку единым ядром). Admin — десктоп-функция; модуль гейтнут `not(mobile)`
//! в `lib.rs`, на Android/iOS не компилируется (см. Cargo.toml).
//!
//! C4.1 (этот файл): SSH-коннект (пароль/ключ) + **TOFU** по host-key + удалённый `exec`.
//! Дальше: C4.2 провижининг (арка/Docker/заливка бинаря по sftp), C4.3 keygen + `compose` +
//! `docker compose up`, C4.4 чтение pin/pubkeys обратно → минт клиентского бандла.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use russh::client::{self, Config, Handle};
use russh::keys::ssh_key::PublicKey;
use russh::{ChannelMsg, Disconnect};

/// Способ SSH-аутентификации.
pub enum SshAuth {
    /// Пароль (попадёт в `SecretStore` на стороне GUI, не в plain-конфиг).
    Password(String),
    /// Приватный ключ в OpenSSH-PEM (+ опц. passphrase).
    Key {
        private_pem: String,
        passphrase: Option<String>,
    },
}

/// Решение TOFU по предъявленному host-key.
pub enum HostKeyDecision {
    /// Принять (и, как правило, запомнить отпечаток для будущих коннектов).
    Accept,
    /// Отвергнуть — коннект прервётся (несовпадение = возможный MITM при первичном деплое).
    Reject,
}

/// Политика проверки host-key (Trust-On-First-Use). Реализация хранит known-hosts
/// (GUI — в `SecretStore`/файле); вызывается на коннекте с SHA-256-отпечатком сервера.
pub trait HostKeyVerifier: Send {
    /// `fingerprint` — в формате OpenSSH `SHA256:<base64>`.
    fn verify(&mut self, host: &str, fingerprint: &str) -> HostKeyDecision;
}

/// Встроенная TOFU-память: первый отпечаток на хост принимается и запоминается, последующие
/// сверяются (несовпадение → `Reject`). Для GUI персистентность поверх — отдельная реализация.
#[derive(Default)]
pub struct MemoryTofu {
    known: HashMap<String, String>,
}

impl MemoryTofu {
    pub fn new() -> Self {
        Self::default()
    }

    /// Предварительно известный (пиннованный) отпечаток для хоста — несовпадение отвергнётся.
    pub fn with_known(host: &str, fingerprint: &str) -> Self {
        let mut known = HashMap::new();
        known.insert(host.to_string(), fingerprint.to_string());
        Self { known }
    }
}

impl HostKeyVerifier for MemoryTofu {
    fn verify(&mut self, host: &str, fingerprint: &str) -> HostKeyDecision {
        match self.known.get(host) {
            Some(known) if known == fingerprint => HostKeyDecision::Accept,
            Some(_) => HostKeyDecision::Reject,
            None => {
                self.known.insert(host.to_string(), fingerprint.to_string());
                HostKeyDecision::Accept
            }
        }
    }
}

/// Результат удалённой команды.
pub struct CommandOutput {
    /// Код возврата; `-1`, если сервер не прислал exit-status (например, оборвал канал).
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// russh-handler: TOFU-проверка host-key делегируется во [`HostKeyVerifier`].
struct DeployHandler {
    host: String,
    verifier: Box<dyn HostKeyVerifier>,
}

impl client::Handler for DeployHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        // `Fingerprint` Display = `SHA256:<base64-no-pad>` (формат OpenSSH).
        let fp = server_public_key.fingerprint(Default::default()).to_string();
        Ok(match self.verifier.verify(&self.host, &fp) {
            HostKeyDecision::Accept => true,
            HostKeyDecision::Reject => false,
        })
    }
}

/// Хэндл админ-SSH-сессии к серверу. Держит соединение; команды через [`AdminDeployer::run`].
pub struct AdminDeployer {
    session: Handle<DeployHandler>,
}

impl AdminDeployer {
    /// Подключиться и аутентифицироваться. `verifier` решает судьбу host-key (TOFU).
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        auth: SshAuth,
        verifier: Box<dyn HostKeyVerifier>,
    ) -> Result<Self> {
        let config = Arc::new(Config {
            inactivity_timeout: Some(Duration::from_secs(60)),
            ..Default::default()
        });
        let handler = DeployHandler {
            host: host.to_string(),
            verifier,
        };
        let mut session = client::connect(config, (host, port), handler)
            .await
            .with_context(|| format!("SSH-коннект к {host}:{port}"))?;

        let ok = match auth {
            SshAuth::Password(pw) => session.authenticate_password(user, pw).await?.success(),
            SshAuth::Key {
                private_pem,
                passphrase,
            } => {
                let key = russh::keys::decode_secret_key(&private_pem, passphrase.as_deref())
                    .context("разбор приватного SSH-ключа")?;
                let hash = session.best_supported_rsa_hash().await?.flatten();
                session
                    .authenticate_publickey(
                        user,
                        russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await?
                    .success()
            }
        };
        if !ok {
            bail!("SSH-аутентификация отклонена сервером (проверьте логин/пароль/ключ)");
        }
        Ok(Self { session })
    }

    /// Выполнить команду, собрать stdout/stderr/код. Аргументы НЕ экранируются — собирай команду
    /// сам (SSH не поддерживает quoting; пути/значения экранируй на стороне вызова).
    pub async fn run(&self, command: &str) -> Result<CommandOutput> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                // ext == 1 → SSH_EXTENDED_DATA_STDERR
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr.extend_from_slice(data)
                }
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                _ => {}
            }
        }
        Ok(CommandOutput {
            code: code.map(|c| c as i32).unwrap_or(-1),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    /// Как [`run`](Self::run), но непустой код возврата — ошибка (со stderr в тексте). Для шагов
    /// провижининга, где любой сбой команды должен прерывать деплой.
    pub async fn run_checked(&self, command: &str) -> Result<String> {
        let out = self.run(command).await?;
        if out.code != 0 {
            bail!(
                "удалённая команда завершилась с кодом {}: `{command}`\n{}",
                out.code,
                out.stderr.trim()
            );
        }
        Ok(out.stdout)
    }

    /// Корректно закрыть сессию.
    pub async fn close(self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "")
            .await?;
        Ok(())
    }

    // ─────────────────────── C4.2: провижининг сервера ───────────────────────

    /// Префикс привилегий: `""` если SSH-пользователь уже root, иначе `"sudo"`.
    async fn sudo(&self) -> Result<&'static str> {
        Ok(if self.run_checked("id -u").await?.trim() == "0" {
            ""
        } else {
            "sudo"
        })
    }

    /// Арка сервера (`uname -m`) — выбор артефакта `citadel-m1-<suffix>`.
    pub async fn detect_arch(&self) -> Result<ServerArch> {
        let m = self.run_checked("uname -m").await?;
        ServerArch::from_uname(&m)
            .ok_or_else(|| anyhow::anyhow!("неподдерживаемая арка сервера: {}", m.trim()))
    }

    /// Есть ли Docker с compose v2 (`docker compose version` → код 0).
    pub async fn has_docker(&self) -> Result<bool> {
        Ok(self.run("docker compose version").await?.code == 0)
    }

    /// Гарантировать Docker (+ compose v2): если нет — **авто-установка** официальным
    /// `get.docker.com`. Идемпотентно (есть → no-op). Debian/Ubuntu — наша база (надёжно),
    /// прочие дистрибутивы — best-effort: при неуспехе внятная ошибка, не молча.
    pub async fn ensure_docker(&self) -> Result<()> {
        if self.has_docker().await? {
            return Ok(());
        }
        let sudo = self.sudo().await?;
        self.run_checked(&format!("{sudo} sh -c 'curl -fsSL https://get.docker.com | sh'"))
            .await
            .context("авто-установка Docker (get.docker.com)")?;
        // включить службу (на cloud-образах часто не enabled); неуспех не фатален — проверим ниже
        let _ = self.run(&format!("{sudo} systemctl enable --now docker")).await;
        if !self.has_docker().await? {
            bail!("Docker установлен, но `docker compose` недоступен — дистрибутив не поддержан, поставьте Docker Engine + compose-plugin вручную");
        }
        Ok(())
    }

    /// Создать каталоги развёртывания `/opt/citadel/{bin,keys,etc}` (под root).
    pub async fn ensure_dirs(&self) -> Result<()> {
        let sudo = self.sudo().await?;
        self.run_checked(&format!(
            "{sudo} mkdir -p {DEPLOY_DIR}/bin {DEPLOY_DIR}/keys {DEPLOY_DIR}/etc"
        ))
        .await?;
        Ok(())
    }

    // ─────────────── C5.5/Admin: управление Layer-1 реестром абонентов по SSH ───────────────
    // Поверх CLI `citadel-token registry …` (C5.5) над томом issuer'а (`<DEPLOY_DIR>/keys` bind-mount
    // в `/shared` контейнера). Issuer перечитывает реестр на каждый auth ⇒ правки действуют со
    // следующего коннекта абонента. Аргументы ВАЛИДИРУЮТСЯ (hex64 / шаблон) до подстановки в команду —
    // `run` не экранирует, поэтому это защита от инъекции в SSH (S1.2).

    fn registry_cmd(sub: &str) -> String {
        format!("Citadel_TOKEN_DIR={DEPLOY_DIR}/keys {DEPLOY_DIR}/bin/citadel-token registry {sub}")
    }

    /// Зарегистрировать абонента по `client_id` (Ed25519 pub, 64 hex). `valid_until` —
    /// `+<N>d`/`+<N>h`/unix-секунды или `None` (дефолт +365d на сервере).
    pub async fn registry_add(&self, client_id: &str, valid_until: Option<&str>) -> Result<()> {
        let id = validate_hex64(client_id).context("client_id")?;
        let vu = validate_valid_until(valid_until)?;
        let sub = if vu.is_empty() { format!("add {id}") } else { format!("add {id} {vu}") };
        self.run_checked(&Self::registry_cmd(&sub)).await?;
        Ok(())
    }

    /// Отозвать абонента по `client_id` (status=revoked; действует ≤ длины эпохи).
    pub async fn registry_revoke(&self, client_id: &str) -> Result<()> {
        let id = validate_hex64(client_id).context("client_id")?;
        self.run_checked(&Self::registry_cmd(&format!("revoke {id}"))).await?;
        Ok(())
    }

    /// Текущий реестр абонентов (для Admin-UI).
    pub async fn registry_list(&self) -> Result<Vec<RegistryEntry>> {
        let out = self.run_checked(&Self::registry_cmd("list")).await?;
        Ok(parse_registry(&out))
    }
}

/// Запись Layer-1 реестра для Admin-UI: `client_id` (pub hex), срок (unix), статус.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntry {
    pub client_id: String,
    pub valid_until: u64,
    pub status: String,
}

/// Валидация hex64 (32 байта): только `[0-9a-fA-F]{64}` — не пускаем метасимволы в SSH-команду.
fn validate_hex64(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        bail!("ожидался 64-символьный hex (32 байта)")
    }
}

/// Валидация `valid_until`: пусто | unix-секунды | `+<N>d` | `+<N>h`. Возвращает безопасную строку
/// (пусто → CLI подставит дефолт). Анти-инъекция в SSH-команду.
fn validate_valid_until(v: Option<&str>) -> Result<String> {
    let Some(v) = v.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(String::new());
    };
    let core = v.strip_prefix('+').map(|r| r.strip_suffix(['d', 'h']).unwrap_or(r)).unwrap_or(v);
    if !core.is_empty() && core.bytes().all(|b| b.is_ascii_digit()) {
        Ok(v.to_string())
    } else {
        bail!("valid_until: unix-секунды | +<N>d | +<N>h")
    }
}

/// Разобрать вывод `registry list` (строки `<pub> <valid_until> <status>`); мусорные строки — мимо.
fn parse_registry(out: &str) -> Vec<RegistryEntry> {
    out.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            match (it.next(), it.next(), it.next()) {
                (Some(id), Some(vu), Some(st)) if id.len() == 64 => Some(RegistryEntry {
                    client_id: id.to_string(),
                    valid_until: vu.parse().unwrap_or(0),
                    status: st.to_string(),
                }),
                _ => None,
            }
        })
        .collect()
}

/// Корень развёртывания на сервере (бинарь, ключи, compose/entrypoints).
pub const DEPLOY_DIR: &str = "/opt/citadel";

/// Поддерживаемые арки сервера (бинарь `citadel-m1-<suffix>` из Release/заливки).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerArch {
    X86_64,
    Aarch64,
}

impl ServerArch {
    /// Разбор вывода `uname -m` (учитывает синонимы amd64/arm64).
    pub fn from_uname(m: &str) -> Option<Self> {
        match m.trim() {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// Суффикс артефакта (совпадает с матрицей CI `release.yml`, C4.5).
    pub fn artifact_suffix(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

// ─────────────────── C4.3a: артефакты развёртывания (compose / entrypoint) ───────────────────

/// Параметры разворачиваемого exit-сервера (выбор админа). `obfs_psk` — pre-shared: один и тот же
/// кладётся в серверный `Citadel_OBFS_PSK` (hex) и в клиентский бандл (`[u8;32]`, C4.4-минт).
/// Профиль соответствует token-less E2E exit (без issuer/PQ-auth) — простая `citadel://`-ссылка.
pub struct DeployConfig {
    pub container_name: String,
    pub image_tag: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub tun_addr: String,
    pub mtu: u32,
    pub obfs_psk: [u8; 32],
}

impl DeployConfig {
    /// Дефолтный exit со **случайным** obfs-PSK (aws-lc-rs RNG — тот же, что в vault).
    pub fn with_random_psk() -> Result<Self> {
        let mut psk = [0u8; 32];
        SystemRandom::new()
            .fill(&mut psk)
            .map_err(|_| anyhow::anyhow!("RNG"))?;
        Ok(Self {
            container_name: "citadel-exit".into(),
            image_tag: "citadel-pq:latest".into(),
            udp_port: 4433,
            tcp_port: 443,
            tun_addr: "10.7.0.1/16".into(),
            mtu: 1100,
            obfs_psk: psk,
        })
    }

    /// PSK в hex — для `Citadel_OBFS_PSK` (сервер `parse_obfs_psk` понимает hex64) и для минта.
    pub fn obfs_psk_hex(&self) -> String {
        self.obfs_psk.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `docker-compose.yml` exit-узла: сборка из загруженного `Dockerfile`, публикация портов,
    /// bind-mount entrypoint + каталога ключей в `/shared` (туда entrypoint пишет `exit.pin`).
    pub fn render_compose(&self) -> String {
        let tpl = r#"name: citadel
services:
  exit:
    build: { context: ., dockerfile: Dockerfile }
    image: __IMAGE__
    container_name: __NAME__
    entrypoint: ["/usr/local/bin/entrypoint-exit.sh"]
    cap_add: ["NET_ADMIN"]
    devices: ["/dev/net/tun:/dev/net/tun"]
    sysctls: ["net.ipv4.ip_forward=1"]
    restart: unless-stopped
    environment:
      Citadel_OBFS_PSK: "__PSK__"
    ports:
      - "__UDP__:4433/udp"
      - "__TCP__:443/tcp"
    volumes:
      - "__DIR__/keys:/shared"
      - "__DIR__/etc/entrypoint-exit.sh:/usr/local/bin/entrypoint-exit.sh:ro"
"#;
        tpl.replace("__IMAGE__", &self.image_tag)
            .replace("__NAME__", &self.container_name)
            .replace("__PSK__", &self.obfs_psk_hex())
            .replace("__UDP__", &self.udp_port.to_string())
            .replace("__TCP__", &self.tcp_port.to_string())
            .replace("__DIR__", DEPLOY_DIR)
    }

    /// entrypoint exit-узла: token-less (без issuer), без PQ-auth — как `entrypoint-exit-e2e.sh`,
    /// но с параметрами из конфига. PSK приходит из env (его задаёт compose).
    pub fn render_entrypoint(&self) -> String {
        let tpl = r#"#!/usr/bin/env bash
set -e
export Citadel_ROLE=server
export Citadel_LISTEN=0.0.0.0:4433
export Citadel_TUN=Citadel0
export Citadel_TUN_ADDR=__ADDR__
export Citadel_MTU=__MTU__
export Citadel_NAT_SRC=10.7.0.0/16
export Citadel_PIN_FILE=/shared/exit.pin
export Citadel_OBFS_PSK="${Citadel_OBFS_PSK:-}"
export Citadel_TCP_LISTEN=0.0.0.0:443
export Citadel_KX=all
rm -f /shared/exit.pin
echo "[citadel-exit] token-less; listen 4433/udp + 443/tcp"
exec citadel-m1
"#;
        tpl.replace("__ADDR__", &self.tun_addr)
            .replace("__MTU__", &self.mtu.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::server::{self, Auth, Msg, Server as _, Session};
    use russh::{Channel, ChannelId};
    use tokio::net::TcpListener;

    /// Throwaway ed25519 host-key для in-process тест-сервера (НЕ секрет: одноразовый,
    /// слушает только 127.0.0.1:0). Фиксированный → тест детерминирован, без rand-зависимости.
    const TEST_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACB5mWHZ6kP3qltGcxGuqoAk92eJmyZVH+wFKv1WTPXszQAAAJiPR+fJj0fn\n\
yQAAAAtzc2gtZWQyNTUxOQAAACB5mWHZ6kP3qltGcxGuqoAk92eJmyZVH+wFKv1WTPXszQ\n\
AAAEB+jZuAuS+cNiIQXeAJCQmM6QghlQxIZFoJuJkS009yu3mZYdnqQ/eqW0ZzEa6qgCT3\n\
Z4mbJlUf7AUq/VZM9ezNAAAAFGNpdGFkZWwtdGVzdC1ob3N0a2V5AQ==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    // ── In-process SSH-сервер (self-contained: без внешнего sshd / docker / root) ──

    struct TestServer {
        docker: Arc<std::sync::Mutex<bool>>,
    }
    impl server::Server for TestServer {
        type Handler = TestHandler;
        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> TestHandler {
            TestHandler {
                docker: self.docker.clone(),
            }
        }
    }

    struct TestHandler {
        docker: Arc<std::sync::Mutex<bool>>,
    }
    impl server::Handler for TestHandler {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            if user == "admin" && password == "s3cr3t" {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::reject())
            }
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let cmd = String::from_utf8_lossy(data);
            // Эмуляция сервера: root, арка, Docker (stateful — get.docker.com «ставит»), mkdir, эхо.
            let (out, code): (String, u32) = if cmd.contains("id -u") {
                ("0\n".to_string(), 0)
            } else if cmd.contains("uname") {
                ("x86_64\n".to_string(), 0)
            } else if cmd.contains("docker compose version") {
                if *self.docker.lock().unwrap() {
                    ("Docker Compose version v2.30\n".to_string(), 0)
                } else {
                    (String::new(), 1)
                }
            } else if cmd.contains("get.docker.com") {
                *self.docker.lock().unwrap() = true;
                ("# docker installed\n".to_string(), 0)
            } else if cmd.contains("systemctl") || cmd.contains("mkdir") {
                (String::new(), 0)
            } else if cmd.contains("registry list") {
                // эмуляция реестра issuer'а: один active + один revoked
                (format!("{} 2000000000 active\n{} 1000000000 revoked\n", "a".repeat(64), "b".repeat(64)), 0)
            } else if cmd.contains("--bad") {
                ("boom\n".to_string(), 2)
            } else {
                (format!("ok:{cmd}\n"), 0)
            };
            if !out.is_empty() {
                session.data(channel, out.into_bytes())?;
            }
            session.exit_status_request(channel, code)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    /// Поднять тест-сервер на 127.0.0.1:0, вернуть его адрес и SHA-256-отпечаток host-key.
    async fn spawn_server(docker_present: bool) -> (std::net::SocketAddr, String) {
        let key = russh::keys::decode_secret_key(TEST_HOST_KEY, None).unwrap();
        let fingerprint = key.public_key().fingerprint(Default::default()).to_string();
        let config = Arc::new(server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let docker = Arc::new(std::sync::Mutex::new(docker_present));
        tokio::spawn(async move {
            let mut server = TestServer { docker };
            let _ = server.run_on_socket(config, &listener).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (addr, fingerprint)
    }

    /// Хелпер: подключиться как admin/s3cr3t с TOFU-accept (первый коннект).
    async fn connect_admin(addr: &std::net::SocketAddr) -> AdminDeployer {
        AdminDeployer::connect(
            &addr.ip().to_string(),
            addr.port(),
            "admin",
            SshAuth::Password("s3cr3t".into()),
            Box::new(MemoryTofu::new()),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn connect_auth_exec_roundtrip() {
        let (addr, _fp) = spawn_server(true).await;
        let dep = AdminDeployer::connect(
            &addr.ip().to_string(),
            addr.port(),
            "admin",
            SshAuth::Password("s3cr3t".into()),
            Box::new(MemoryTofu::new()), // TOFU: первый коннект принимает host-key
        )
        .await
        .unwrap();

        let out = dep.run("uname -m").await.unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout.trim(), "x86_64");

        // run_checked: ненулевой код → ошибка
        assert!(dep.run_checked("ls --bad").await.is_err());

        dep.close().await.unwrap();
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let (addr, _fp) = spawn_server(true).await;
        let res = AdminDeployer::connect(
            &addr.ip().to_string(),
            addr.port(),
            "admin",
            SshAuth::Password("wrong".into()),
            Box::new(MemoryTofu::new()),
        )
        .await;
        assert!(res.is_err(), "неверный пароль должен отвергаться");
    }

    #[tokio::test]
    async fn host_key_mismatch_rejected() {
        let (addr, _fp) = spawn_server(true).await;
        // пиннуем ЗАВЕДОМО ДРУГОЙ отпечаток → TOFU обязан отвергнуть (имитация MITM)
        let pinned = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let res = AdminDeployer::connect(
            &addr.ip().to_string(),
            addr.port(),
            "admin",
            SshAuth::Password("s3cr3t".into()),
            Box::new(MemoryTofu::with_known(&addr.ip().to_string(), pinned)),
        )
        .await;
        assert!(res.is_err(), "несовпадение host-key должно прерывать коннект");
    }

    // ── C4.2: провижининг ──

    #[tokio::test]
    async fn detect_arch_and_dirs() {
        let (addr, _) = spawn_server(true).await;
        let dep = connect_admin(&addr).await;
        assert_eq!(dep.detect_arch().await.unwrap(), ServerArch::X86_64);
        dep.ensure_dirs().await.unwrap(); // mkdir -p → код 0
        dep.close().await.unwrap();
    }

    #[tokio::test]
    async fn ensure_docker_noop_when_present() {
        let (addr, _) = spawn_server(true).await;
        let dep = connect_admin(&addr).await;
        assert!(dep.has_docker().await.unwrap());
        dep.ensure_docker().await.unwrap(); // присутствует → без установки
        dep.close().await.unwrap();
    }

    #[tokio::test]
    async fn ensure_docker_bootstraps_when_absent() {
        let (addr, _) = spawn_server(false).await; // Docker отсутствует
        let dep = connect_admin(&addr).await;
        assert!(!dep.has_docker().await.unwrap());
        dep.ensure_docker().await.unwrap(); // get.docker.com «ставит» → перепроверка проходит
        assert!(dep.has_docker().await.unwrap());
        dep.close().await.unwrap();
    }

    #[test]
    fn server_arch_parsing() {
        assert_eq!(ServerArch::from_uname("x86_64\n"), Some(ServerArch::X86_64));
        assert_eq!(ServerArch::from_uname("amd64"), Some(ServerArch::X86_64));
        assert_eq!(ServerArch::from_uname("aarch64"), Some(ServerArch::Aarch64));
        assert_eq!(ServerArch::from_uname("arm64"), Some(ServerArch::Aarch64));
        assert_eq!(ServerArch::from_uname("riscv64"), None);
        assert_eq!(ServerArch::X86_64.artifact_suffix(), "x86_64");
        assert_eq!(ServerArch::Aarch64.artifact_suffix(), "aarch64");
    }

    // ── C4.3a: артефакты развёртывания ──

    #[test]
    fn deploy_config_renders() {
        let cfg = DeployConfig::with_random_psk().unwrap();
        let hex = cfg.obfs_psk_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let compose = cfg.render_compose();
        assert!(compose.contains("4433:4433/udp"));
        assert!(compose.contains("443:443/tcp"));
        assert!(compose.contains(&hex), "PSK должен попасть в env compose");
        assert!(compose.contains("container_name: citadel-exit"));
        assert!(compose.contains("/opt/citadel/keys:/shared"));

        let ep = cfg.render_entrypoint();
        assert!(ep.contains("Citadel_ROLE=server"));
        assert!(ep.contains("Citadel_TUN_ADDR=10.7.0.1/16"));
        assert!(ep.ends_with("exec citadel-m1\n"));
    }

    #[test]
    fn obfs_psk_is_random() {
        let a = DeployConfig::with_random_psk().unwrap().obfs_psk;
        let b = DeployConfig::with_random_psk().unwrap().obfs_psk;
        assert_ne!(a, b, "PSK должен быть случайным на каждый деплой");
    }

    /// C5.5/Admin: add/revoke/list реестра по SSH; невалидный/инъекционный ввод отвергается ДО
    /// отправки команды (анти-инъекция).
    #[tokio::test]
    async fn admin_registry_ops() {
        let (addr, _) = spawn_server(true).await;
        let d = connect_admin(&addr).await;
        let id = "a".repeat(64);
        // валидный client_id — add/revoke проходят (тест-сервер эмулирует успех)
        d.registry_add(&id, Some("+30d")).await.unwrap();
        d.registry_add(&id, None).await.unwrap(); // без срока — дефолт на сервере
        d.registry_revoke(&id).await.unwrap();
        // list парсится в записи
        let e = d.registry_list().await.unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].status.as_str(), e[0].valid_until), ("active", 2_000_000_000));
        assert_eq!(e[1].status, "revoked");
        // инъекция / битый ввод — Err ДО SSH (никакой команды не уходит)
        assert!(d.registry_add("bad; rm -rf /", None).await.is_err());
        assert!(d.registry_add(&"a".repeat(63), None).await.is_err()); // не 64
        assert!(d.registry_add(&id, Some("+30d; evil")).await.is_err()); // инъекция в срок
        assert!(d.registry_revoke("$(curl evil)").await.is_err());
        d.close().await.unwrap();
    }

    #[test]
    fn registry_input_validation() {
        assert!(super::validate_hex64(&"A".repeat(64)).is_ok()); // регистр норм → lower
        assert_eq!(super::validate_hex64(&"A".repeat(64)).unwrap(), "a".repeat(64));
        assert!(super::validate_hex64("zz").is_err());
        assert!(super::validate_hex64(&"a".repeat(65)).is_err());
        assert_eq!(super::validate_valid_until(None).unwrap(), "");
        assert_eq!(super::validate_valid_until(Some("+30d")).unwrap(), "+30d");
        assert_eq!(super::validate_valid_until(Some("1700000000")).unwrap(), "1700000000");
        assert!(super::validate_valid_until(Some("+30d; rm")).is_err());
        assert!(super::validate_valid_until(Some("soon")).is_err());
        // парсер реестра отбрасывает мусор и не-64-hex id
        let parsed = super::parse_registry(&format!("{} 5 active\ngarbage\nshort 1 active\n", "c".repeat(64)));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].client_id, "c".repeat(64));
    }
}

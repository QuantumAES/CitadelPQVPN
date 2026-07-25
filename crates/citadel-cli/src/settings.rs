//! Клиентские настройки (не из ссылки): kill-switch и split-tunnel по назначениям.
//!
//! Формат и расположение файлов **намеренно те же**, что у Flutter-клиента
//! (`~/.config/citadel-pqvpn/{vault.bin,killswitch,split}`): консоль и GUI на одной машине
//! работают с одним набором профилей и настроек, а не с двумя разными представлениями о том,
//! включён ли kill-switch.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Каталог данных клиента (тот же, что у GUI).
pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("citadel-pqvpn")
}

pub fn vault_path() -> PathBuf {
    config_dir().join("vault.bin")
}

fn killswitch_file() -> PathBuf {
    config_dir().join("killswitch")
}

fn split_file() -> PathBuf {
    config_dir().join("split")
}

/// Клиентские настройки сессии.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Kill-switch (fail-closed firewall на время сессии).
    pub killswitch: bool,
    /// Режим split по назначениям: `off`|`include`|`exclude`.
    pub dest_mode: String,
    /// Назначения (`domain`|`IP`|`IP/prefix`).
    pub dests: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { killswitch: false, dest_mode: "off".into(), dests: Vec::new() }
    }
}

impl Settings {
    pub fn load() -> Settings {
        let killswitch = std::fs::read_to_string(killswitch_file())
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        let mut s = Settings { killswitch, ..Default::default() };
        if let Ok(text) = std::fs::read_to_string(split_file()) {
            for line in text.lines() {
                let line = line.trim();
                // длинные префиксы раньше коротких (`dest_mode=` до `dest=`)
                if let Some(v) = line.strip_prefix("dest_mode=") {
                    s.dest_mode = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("dest=") {
                    let v = v.trim();
                    if !v.is_empty() {
                        s.dests.push(v.to_string());
                    }
                }
            }
        }
        s
    }

    pub fn save_killswitch(on: bool) -> Result<()> {
        write_file(killswitch_file(), if on { "1" } else { "0" })
    }

    /// Сохранить split, сохранив ось приложений из файла GUI (её на Linux не редактируем, но и
    /// затирать чужую настройку Android/GUI не должны — файл общий).
    pub fn save_split(&self) -> Result<()> {
        let mut preserved = String::new();
        if let Ok(text) = std::fs::read_to_string(split_file()) {
            for line in text.lines() {
                let t = line.trim();
                if t.starts_with("app_mode=") || t.starts_with("app=") {
                    preserved.push_str(t);
                    preserved.push('\n');
                }
            }
        }
        if preserved.is_empty() {
            preserved.push_str("app_mode=off\n");
        }
        let mut out = preserved;
        out.push_str(&format!("dest_mode={}\n", self.dest_mode.trim()));
        for d in &self.dests {
            let d = d.trim();
            if !d.is_empty() {
                out.push_str(&format!("dest={d}\n"));
            }
        }
        write_file(split_file(), &out)
    }
}

/// Записать настройку в приватный файл (0600) — сами по себе они не секрет, но лежат рядом
/// с хранилищем и не должны быть доступны другим пользователям машины.
fn write_file(path: PathBuf, content: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(d) = path.parent() {
        if !d.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(d)
                .with_context(|| format!("создать {}", d.display()))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("записать {}", path.display()))?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

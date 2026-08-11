//! Ввод мастер-пароля и секретов из терминала.
//!
//! Правило (L5): секреты приходят ТОЛЬКО с терминала или stdin — никогда из аргументов командной
//! строки и переменных окружения. `/proc/<pid>/cmdline` читает любой локальный пользователь, а
//! `citadel://`-ссылка и мастер-пароль — bearer-креды: одного `ps aux` хватило бы для угона доступа.
//!
//! Эхо отключается через `termios` напрямую (без внешних крейтов). Исходные настройки терминала
//! восстанавливаются в любом случае — включая ошибку чтения.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// Пароль/секрет, затираемый при выходе из области видимости (крейт `zeroize` пишет volatile —
/// компилятор не имеет права выкинуть затирание как «мёртвую запись»).
pub type Secret = Zeroizing<String>;

/// Прочитать пароль с терминала без эха. Требует tty: скрипты должны передавать секрет иначе
/// (см. [`read_secret_line`]), а не через аргументы.
pub fn read_password(prompt: &str) -> Result<Secret> {
    let mut stdout = std::io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;

    if !std::io::stdin().is_terminal() {
        // Не tty (пайп/скрипт) — читаем строку как есть, эхо и так никуда не пойдёт.
        let s = read_secret_line()?;
        println!();
        return Ok(s);
    }

    let guard = EchoGuard::disable()?;
    let s = read_secret_line();
    drop(guard);
    println!();
    s
}

/// Прочитать строку С ЭХОМ — для значений, которые секретом НЕ являются и которые человек
/// проверяет глазами при вводе. Сейчас это код сверки ссылки (M-9): он публичен по назначению —
/// администратор диктует его голосом, — и прятать его при вводе значило бы мешать сверке.
pub fn read_line(prompt: &str) -> Result<String> {
    let mut stdout = std::io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).context("читать stdin")?;
    if n == 0 {
        bail!("ввод пуст (EOF)");
    }
    Ok(line.trim().to_string())
}

/// Прочитать одну строку со stdin как секрет (без обрезки внутренних пробелов, только `\n`/`\r`).
pub fn read_secret_line() -> Result<Secret> {
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).context("читать stdin")?;
    if n == 0 {
        bail!("ввод пуст (EOF)");
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Zeroizing::new(line))
}

/// Восстановление режима терминала при любом выходе (в т.ч. по ошибке).
struct EchoGuard {
    fd: i32,
    saved: libc::termios,
}

impl EchoGuard {
    fn disable() -> Result<EchoGuard> {
        let fd = 0; // stdin
        // SAFETY: termios заполняется ядром; fd — валидный дескриптор терминала.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                bail!("tcgetattr: {}", std::io::Error::last_os_error());
            }
            let saved = t;
            t.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(fd, libc::TCSAFLUSH, &t) != 0 {
                bail!("tcsetattr: {}", std::io::Error::last_os_error());
            }
            Ok(EchoGuard { fd, saved })
        }
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: возвращаем ровно те настройки, что читали.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
    }
}

/// Пароль с подтверждением (создание хранилища / смена пароля).
pub fn read_new_password(prompt: &str) -> Result<Secret> {
    let a = read_password(prompt)?;
    let b = read_password("Повторите пароль: ")?;
    if *a != *b {
        bail!("пароли не совпадают");
    }
    Ok(a)
}

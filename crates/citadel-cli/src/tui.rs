//! Полноэкранный интерфейс настройки (ratatui + crossterm).
//!
//! Экран разблокировки → список профилей → подключение/настройки. Всё, что приходит извне
//! (имена профилей из чужих ссылок, тексты ошибок сервера, имя exit'а), проходит через
//! `sanitize_text`: ANSI/OSC-последовательность в такой строке иначе перерисовала бы интерфейс
//! или подменила подсказку (L16).
//!
//! Хранилище держится разблокированным только пока идёт работа: при бездействии дольше
//! [`AUTOLOCK`] оно закрывается само (L8 — типичная ситуация «TUI забыт в detached tmux/SSH»).
//! Ссылки профилей на экране по умолчанию скрыты — они bearer-креды и оседают в скролбэке
//! терминала и в записи SSH-сессии (L17).

use std::collections::VecDeque;
use std::io::Stdout;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use zeroize::Zeroizing;

use citadel_client::{Profile, Vault};
use citadel_vpnd::proto::{ConnectReq, EventMsg, StatusInfo};
use citadel_vpnd::valid::sanitize_text;

use crate::ipc::{self, Client};
use crate::settings::{self, Settings};
use crate::state_ru;

/// Хранилище закрывается само после этого времени без нажатий (L8).
const AUTOLOCK: Duration = Duration::from_secs(10 * 60);
/// Как часто опрашивать состояние демона (события приходят сами, это страховка).
const POLL_STATUS: Duration = Duration::from_secs(2);
/// Глубина журнала событий на экране.
const LOG_LINES: usize = 200;

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Что сейчас на экране.
enum Screen {
    /// Ввод мастер-пароля (или создание хранилища).
    Unlock { create: bool, confirm: Option<Zeroizing<String>> },
    /// Основной экран со списком профилей.
    Main,
    /// Ввод новой `citadel://`-ссылки.
    AddLink,
    /// Подтверждение удаления профиля.
    ConfirmRemove { id: String, name: String },
    /// Настройка split-tunnel.
    Split { adding: bool },
    /// Справка по клавишам (`?` или F1). Помнит, откуда её открыли, чтобы вернуть обратно.
    Help { from_split: bool },
}

struct App {
    screen: Screen,
    vault: Option<Vault>,
    profiles: Vec<Profile>,
    list_state: ListState,
    status: StatusInfo,
    settings: Settings,
    log: VecDeque<String>,
    /// Поле ввода текущего экрана (пароль/ссылка/CIDR).
    input: Zeroizing<String>,
    /// Скрывать ли ввод (пароль и ссылка — да; CIDR — нет).
    masked: bool,
    message: String,
    error: bool,
    last_key: Instant,
    client: Client,
    split_sel: usize,
    /// Прокрутка экрана справки (в маленьком терминале она не влезает целиком).
    help_scroll: u16,
    quit: bool,
}

impl App {
    fn new() -> App {
        let create = !Vault::exists(settings::vault_path());
        App {
            screen: Screen::Unlock { create, confirm: None },
            vault: None,
            profiles: Vec::new(),
            list_state: ListState::default(),
            status: StatusInfo { state: "idle".into(), ..Default::default() },
            settings: Settings::load(),
            log: VecDeque::new(),
            input: Zeroizing::new(String::new()),
            masked: true,
            message: String::new(),
            error: false,
            last_key: Instant::now(),
            client: Client::default(),
            split_sel: 0,
            help_scroll: 0,
            quit: false,
        }
    }

    fn note(&mut self, msg: impl Into<String>) {
        self.message = msg.into();
        self.error = false;
    }

    fn fail(&mut self, msg: impl Into<String>) {
        self.message = msg.into();
        self.error = true;
    }

    fn push_log(&mut self, line: String) {
        if self.log.len() >= LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }

    fn selected(&self) -> Option<&Profile> {
        self.list_state.selected().and_then(|i| self.profiles.get(i))
    }

    /// Закрыть хранилище (автолок/явная блокировка): расшифрованные ссылки уходят из памяти.
    fn lock(&mut self) {
        self.vault = None;
        self.profiles.clear();
        self.input = Zeroizing::new(String::new());
        self.screen = Screen::Unlock { create: !Vault::exists(settings::vault_path()), confirm: None };
    }
}

/// Точка входа TUI.
pub fn run() -> Result<()> {
    let mut term = setup_terminal()?;
    let app_result = run_app(&mut term);
    restore_terminal(&mut term)?;
    app_result
}

fn setup_terminal() -> Result<Term> {
    enable_raw_mode().context("включить raw-режим терминала")?;
    let mut out = std::io::stdout();
    execute!(out, EnterAlternateScreen)?;
    // Паника не должна оставить терминал в raw-режиме без курсора — иначе оболочка «сломана».
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        default_hook(info);
    }));
    Ok(Terminal::new(CrosstermBackend::new(out))?)
}

fn restore_terminal(term: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

fn run_app(term: &mut Term) -> Result<()> {
    let mut app = App::new();
    let events = spawn_event_reader();
    let mut last_poll = Instant::now() - POLL_STATUS;

    loop {
        // Состояние демона: события приходят сами, но опрос страхует от пропущенных и
        // подтягивает флаг «kill-switch армирован» (его считает демон, а не движок).
        if last_poll.elapsed() >= POLL_STATUS {
            match app.client.status() {
                Ok(s) => app.status = s,
                Err(e) => {
                    if app.message.is_empty() {
                        app.fail(format!("{e}"));
                    }
                }
            }
            last_poll = Instant::now();
        }
        while let Ok(ev) = events.try_recv() {
            let line = format_event(&ev);
            app.push_log(line);
            if ev.kind == "state" {
                app.status.state = ev.state.clone();
            }
        }
        // Автолок бездействующей сессии.
        if app.vault.is_some() && app.last_key.elapsed() > AUTOLOCK {
            app.lock();
            app.note("Хранилище заблокировано по бездействию");
        }

        term.draw(|f| draw(f, &mut app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.last_key = Instant::now();
                    handle_key(&mut app, key);
                }
            }
        }
        if app.quit {
            return Ok(());
        }
    }
}

/// Фоновая подписка на события демона (переподключается, если демон перезапустили).
fn spawn_event_reader() -> Receiver<EventMsg> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || loop {
        let client = Client::default();
        match client.subscribe() {
            Ok(mut s) => {
                while let Ok(Some(ev)) = ipc::read_event(&mut s) {
                    if tx.send(ev).is_err() {
                        return; // UI закрылся
                    }
                }
            }
            Err(_) => std::thread::sleep(Duration::from_secs(2)),
        }
        std::thread::sleep(Duration::from_millis(500));
    });
    rx
}

fn format_event(ev: &EventMsg) -> String {
    match ev.kind.as_str() {
        "connected" => format!(
            "подключено: {} ({}), адрес {}",
            sanitize_text(&ev.exit, 128),
            sanitize_text(&ev.transport, 32),
            sanitize_text(&ev.cidr, 64)
        ),
        "error" => format!("ошибка: {}", sanitize_text(&ev.error, 512)),
        _ => state_ru(&ev.state).to_string(),
    }
}

// ───────────────────────────── обработка клавиш ─────────────────────────────

fn handle_key(app: &mut App, key: KeyEvent) {
    // Ctrl-C выходит из любого экрана (сессия при этом продолжает жить в демоне — это служба).
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.quit = true;
        return;
    }
    // F1 работает всюду, включая экраны ввода: там символ «?» — часть пароля/ссылки, перехватить
    // его нельзя. На экранах без ввода справку открывает и «?».
    if key.code == KeyCode::F(1) && !matches!(app.screen, Screen::Help { .. }) {
        open_help(app);
        return;
    }
    match &app.screen {
        Screen::Unlock { .. } => key_unlock(app, key),
        Screen::Main => key_main(app, key),
        Screen::AddLink => key_add(app, key),
        Screen::ConfirmRemove { .. } => key_confirm(app, key),
        Screen::Split { .. } => key_split(app, key),
        Screen::Help { .. } => key_help(app, key),
    }
}

/// Открыть справку, запомнив экран возврата.
fn open_help(app: &mut App) {
    let from_split = matches!(app.screen, Screen::Split { .. });
    app.help_scroll = 0;
    app.screen = Screen::Help { from_split };
    app.note("Справка: ↑↓ прокрутка, Esc — назад");
}

fn key_help(app: &mut App, key: KeyEvent) {
    let from_split = matches!(app.screen, Screen::Help { from_split: true });
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => app.help_scroll = app.help_scroll.saturating_add(1),
        KeyCode::Up | KeyCode::Char('k') => app.help_scroll = app.help_scroll.saturating_sub(1),
        // Любая другая клавиша закрывает справку — так её не приходится «искать, чем выйти».
        _ => {
            app.screen = if from_split { Screen::Split { adding: false } } else { Screen::Main };
            app.message.clear();
            app.error = false;
        }
    }
}

fn key_unlock(app: &mut App, key: KeyEvent) {
    let (create, confirm) = match &app.screen {
        Screen::Unlock { create, confirm } => (*create, confirm.clone()),
        _ => return,
    };
    match key.code {
        KeyCode::Esc => app.quit = true,
        KeyCode::Backspace => {
            let mut s = app.input.to_string();
            s.pop();
            app.input = Zeroizing::new(s);
        }
        KeyCode::Char(c) => {
            let mut s = app.input.to_string();
            s.push(c);
            app.input = Zeroizing::new(s);
        }
        KeyCode::Enter => {
            let pass = std::mem::replace(&mut app.input, Zeroizing::new(String::new()));
            let path = settings::vault_path();
            if create {
                match confirm {
                    // первый ввод — просим повтор (защита от опечатки в новом пароле)
                    None => {
                        app.screen = Screen::Unlock { create, confirm: Some(pass) };
                        app.note("Повторите пароль");
                    }
                    Some(first) => {
                        if *first != *pass {
                            app.screen = Screen::Unlock { create, confirm: None };
                            app.fail("Пароли не совпадают — введите заново");
                            return;
                        }
                        match Vault::create(&path, &pass) {
                            Ok(v) => open_ok(app, v),
                            Err(e) => {
                                app.screen = Screen::Unlock { create, confirm: None };
                                app.fail(format!("{e:#}"));
                            }
                        }
                    }
                }
            } else {
                match Vault::open(&path, &pass) {
                    Ok(v) => open_ok(app, v),
                    Err(e) => app.fail(format!("{e:#}")),
                }
            }
        }
        _ => {}
    }
}

fn open_ok(app: &mut App, v: Vault) {
    app.profiles = v.list();
    app.vault = Some(v);
    app.list_state.select(if app.profiles.is_empty() { None } else { Some(0) });
    app.screen = Screen::Main;
    app.note(if app.profiles.is_empty() {
        "Хранилище пусто — нажмите «a», чтобы добавить профиль"
    } else {
        "Хранилище разблокировано"
    });
}

fn key_main(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
        KeyCode::Char('l') => {
            app.lock();
            app.note("Хранилище заблокировано");
        }
        KeyCode::Down | KeyCode::Char('j') => move_sel(app, 1),
        KeyCode::Up | KeyCode::Char('k') => move_sel(app, -1),
        KeyCode::Enter => do_connect(app),
        KeyCode::Char('d') => match app.client.disconnect() {
            Ok(()) => app.note("Отключено, kill-switch снят"),
            Err(e) => app.fail(format!("{e}")),
        },
        KeyCode::Char('a') => {
            app.input = Zeroizing::new(String::new());
            app.masked = true;
            app.screen = Screen::AddLink;
        }
        KeyCode::Char('x') => {
            if let Some(p) = app.selected() {
                app.screen = Screen::ConfirmRemove { id: p.id.clone(), name: p.name.clone() };
            }
        }
        KeyCode::Char('K') => {
            let on = !app.settings.killswitch;
            match Settings::save_killswitch(on) {
                Ok(()) => {
                    app.settings.killswitch = on;
                    app.note(format!(
                        "Kill-switch {} (применится со следующего подключения)",
                        if on { "включён" } else { "выключен" }
                    ));
                }
                Err(e) => app.fail(format!("{e:#}")),
            }
        }
        KeyCode::Char('D') => match app.client.disarm_killswitch() {
            Ok(()) => app.note("Fail-closed правила сняты"),
            Err(e) => app.fail(format!("{e}")),
        },
        KeyCode::Char('s') => {
            app.split_sel = 0;
            app.screen = Screen::Split { adding: false };
        }
        KeyCode::Char('?') | KeyCode::Char('h') => open_help(app),
        _ => {}
    }
}

fn move_sel(app: &mut App, delta: i32) {
    if app.profiles.is_empty() {
        return;
    }
    let cur = app.list_state.selected().unwrap_or(0) as i32;
    let n = app.profiles.len() as i32;
    app.list_state.select(Some(((cur + delta).rem_euclid(n)) as usize));
}

fn do_connect(app: &mut App) {
    let Some(p) = app.selected().cloned() else {
        app.fail("Профиль не выбран");
        return;
    };
    let st = &app.settings;
    let req = ConnectReq {
        link: p.uri.clone(),
        killswitch: st.killswitch,
        split_mode: st.dest_mode.clone(),
        split_dests: st.dests.clone(),
        label: p.name.clone(),
    };
    match app.client.connect_session(req) {
        Ok(()) => app.note(format!("Подключение к «{}»…", sanitize_text(&p.name, 64))),
        Err(e) => app.fail(format!("{e}")),
    }
}

fn key_add(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.input = Zeroizing::new(String::new());
            app.screen = Screen::Main;
        }
        KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Терминал сам вставляет содержимое буфера как обычные символы — отдельная обработка
            // не нужна; перехватываем, чтобы Ctrl-V не попал в поле как управляющий символ.
        }
        KeyCode::Backspace => {
            let mut s = app.input.to_string();
            s.pop();
            app.input = Zeroizing::new(s);
        }
        KeyCode::Char(c) => {
            let mut s = app.input.to_string();
            s.push(c);
            app.input = Zeroizing::new(s);
        }
        KeyCode::Tab => app.masked = !app.masked,
        KeyCode::Enter => {
            let uri = app.input.trim().to_string();
            if !uri.starts_with("citadel://") {
                app.fail("Это не citadel://-ссылка");
                return;
            }
            let added = match app.vault.as_mut() {
                Some(v) => v.add("", &uri),
                None => {
                    app.fail("Хранилище закрыто");
                    return;
                }
            };
            match added {
                Ok(p) => {
                    app.profiles = app.vault.as_ref().map(|v| v.list()).unwrap_or_default();
                    app.list_state.select(Some(app.profiles.len().saturating_sub(1)));
                    app.input = Zeroizing::new(String::new());
                    app.screen = Screen::Main;
                    app.note(format!("Добавлен профиль «{}»", sanitize_text(&p.name, 64)));
                }
                Err(e) => app.fail(format!("{e:#}")),
            }
        }
        _ => {}
    }
}

fn key_confirm(app: &mut App, key: KeyEvent) {
    let id = match &app.screen {
        Screen::ConfirmRemove { id, .. } => id.clone(),
        _ => return,
    };
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let r = app.vault.as_mut().map(|v| v.remove(&id));
            match r {
                Some(Ok(())) => {
                    app.profiles = app.vault.as_ref().map(|v| v.list()).unwrap_or_default();
                    let sel = if app.profiles.is_empty() { None } else { Some(0) };
                    app.list_state.select(sel);
                    app.note("Профиль удалён");
                }
                Some(Err(e)) => app.fail(format!("{e:#}")),
                None => app.fail("Хранилище закрыто"),
            }
            app.screen = Screen::Main;
        }
        _ => app.screen = Screen::Main,
    }
}

fn key_split(app: &mut App, key: KeyEvent) {
    let adding = matches!(app.screen, Screen::Split { adding: true });
    if adding {
        match key.code {
            KeyCode::Esc => {
                app.input = Zeroizing::new(String::new());
                app.screen = Screen::Split { adding: false };
            }
            KeyCode::Backspace => {
                let mut s = app.input.to_string();
                s.pop();
                app.input = Zeroizing::new(s);
            }
            KeyCode::Char(c) => {
                let mut s = app.input.to_string();
                s.push(c);
                app.input = Zeroizing::new(s);
            }
            KeyCode::Enter => {
                let v = app.input.trim().to_string();
                if !v.is_empty() {
                    app.settings.dests.push(v);
                    if let Err(e) = app.settings.save_split() {
                        app.fail(format!("{e:#}"));
                    }
                }
                app.input = Zeroizing::new(String::new());
                app.screen = Screen::Split { adding: false };
            }
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.screen = Screen::Main,
        KeyCode::Char('?') | KeyCode::Char('h') => open_help(app),
        KeyCode::Char('m') => {
            app.settings.dest_mode = match app.settings.dest_mode.as_str() {
                "off" => "exclude".into(),
                "exclude" => "include".into(),
                _ => "off".into(),
            };
            if let Err(e) = app.settings.save_split() {
                app.fail(format!("{e:#}"));
            } else {
                app.note(format!("Режим split: {}", app.settings.dest_mode));
            }
        }
        KeyCode::Char('a') => {
            app.input = Zeroizing::new(String::new());
            app.masked = false;
            app.screen = Screen::Split { adding: true };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.settings.dests.is_empty() {
                app.split_sel = (app.split_sel + 1) % app.settings.dests.len();
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if !app.settings.dests.is_empty() {
                app.split_sel = (app.split_sel + app.settings.dests.len() - 1) % app.settings.dests.len();
            }
        }
        KeyCode::Char('x') if app.split_sel < app.settings.dests.len() => {
            app.settings.dests.remove(app.split_sel);
            app.split_sel = app.split_sel.saturating_sub(1);
            if let Err(e) = app.settings.save_split() {
                app.fail(format!("{e:#}"));
            }
        }
        _ => {}
    }
}

// ───────────────────────────── отрисовка ─────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(6), Constraint::Length(3)])
        .split(area);

    draw_status_bar(f, rows[0], app);
    match &app.screen {
        Screen::Unlock { create, confirm } => draw_unlock(f, rows[1], app, *create, confirm.is_some()),
        Screen::Main => draw_main(f, rows[1], app),
        Screen::AddLink => draw_input(
            f,
            rows[1],
            app,
            "Новая citadel://-ссылка",
            "Вставьте ссылку (Tab — показать/скрыть, Enter — добавить, Esc — отмена)",
        ),
        Screen::ConfirmRemove { name, .. } => {
            let text = format!("Удалить профиль «{}»?  y — да, любая другая — нет", sanitize_text(name, 64));
            f.render_widget(
                Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Подтверждение ")),
                rows[1],
            );
        }
        Screen::Split { adding } => {
            if *adding {
                draw_input(f, rows[1], app, "Назначение split", "IP, CIDR или домен (Enter — добавить, Esc — отмена)");
            } else {
                draw_split(f, rows[1], app);
            }
        }
        Screen::Help { .. } => draw_help(f, rows[1], app),
    }
    draw_footer(f, rows[2], app);
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.status;
    let (state_txt, color) = match s.state.as_str() {
        "up" => ("подключено", Color::Green),
        "connecting" => ("подключение…", Color::Yellow),
        "migrating" => ("восстановление связи…", Color::Yellow),
        _ => ("не подключено", Color::Gray),
    };
    let mut spans = vec![
        Span::styled(format!(" {state_txt} "), Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ];
    if !s.exit.is_empty() && s.state == "up" {
        spans.push(Span::raw(format!(
            "│ exit {} ({}) │ адрес {} ",
            sanitize_text(&s.exit, 64),
            sanitize_text(&s.transport, 24),
            sanitize_text(&s.cidr, 32)
        )));
    }
    spans.push(Span::styled(
        format!("│ kill-switch: {} ", if s.killswitch_armed { "армирован" } else { "снят" }),
        Style::default().fg(if s.killswitch_armed { Color::Green } else { Color::Gray }),
    ));
    if s.killswitch_armed && (s.state == "idle" || s.state == "down") {
        spans.push(Span::styled(
            "(без сессии! «D» — снять) ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).title(" CitadelPQVPN ")),
        area,
    );
}

fn draw_unlock(f: &mut Frame, area: Rect, app: &App, create: bool, second: bool) {
    let title = if create { " Создание хранилища " } else { " Разблокировка хранилища " };
    let prompt = if create {
        if second {
            "Повторите мастер-пароль:"
        } else {
            "Задайте мастер-пароль (минимум 8 символов):"
        }
    } else {
        "Мастер-пароль:"
    };
    let masked: String = "•".repeat(app.input.chars().count());
    let body = vec![
        Line::raw(""),
        Line::raw(format!("  {prompt}")),
        Line::raw(format!("  {masked}▏")),
        Line::raw(""),
        Line::raw(format!("  Хранилище: {}", settings::vault_path().display())),
        Line::raw("  Enter — подтвердить, F1 — справка, Esc — выход"),
    ];
    f.render_widget(
        Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_main(f: &mut Frame, area: Rect, app: &mut App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .map(|p| ListItem::new(sanitize_text(&p.name, 48)))
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Профили "))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▸ ");
    f.render_stateful_widget(list, cols[0], &mut app.list_state);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(3)])
        .split(cols[1]);

    let st = &app.settings;
    let mut info = vec![
        Line::raw(format!(" Kill-switch:  {}", if st.killswitch { "включён" } else { "выключен" })),
        Line::raw(format!(" Split:        {} {}", st.dest_mode, st.dests.join(" "))),
        Line::raw(format!(" Хранилище:    {}", settings::vault_path().display())),
    ];
    // Человеку — что случилось и с чем, а не текст ошибки движка: технические подробности всё
    // равно есть рядом, в журнале сессии (и в `journalctl -u citadel-vpnd`).
    if !app.status.last_error.is_empty() {
        let label = sanitize_text(&app.status.label, 48);
        let what = if label.is_empty() {
            " Сервер недоступен".to_string()
        } else {
            format!(" Сервер недоступен — профиль «{label}»")
        };
        info.push(Line::styled(what, Style::default().fg(Color::Red)));
        info.push(Line::styled(
            " Подробности — в журнале сессии справа",
            Style::default().fg(Color::DarkGray),
        ));
    }
    f.render_widget(
        Paragraph::new(info)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Настройки ")),
        right[0],
    );

    let log: Vec<Line> = app.log.iter().rev().take(50).rev().map(|l| Line::raw(format!(" {l}"))).collect();
    f.render_widget(
        Paragraph::new(log)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Журнал сессии ")),
        right[1],
    );
}

fn draw_split(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::raw(format!(" Режим: {}   (m — переключить: off → exclude → include)", app.settings.dest_mode)),
        Line::raw(""),
    ];
    if app.settings.dests.is_empty() {
        lines.push(Line::raw("  (список пуст — «a» добавить)"));
    }
    for (i, d) in app.settings.dests.iter().enumerate() {
        let marker = if i == app.split_sel { "▸" } else { " " };
        lines.push(Line::raw(format!(" {marker} {}", sanitize_text(d, 64))));
    }
    lines.push(Line::raw(""));
    lines.push(Line::raw(" a — добавить, x — удалить, Esc — назад"));
    lines.push(Line::raw(" exclude: перечисленное идёт мимо туннеля; include: только оно — в туннель"));
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Split-tunnel по назначениям ")),
        area,
    );
}

/// Справка по клавишам (`?`/F1). Отвечает на два вопроса, которые в TUI не видны сами: какая
/// клавиша что делает на КАЖДОМ экране и что происходит с сессией при выходе из интерфейса.
fn draw_help(f: &mut Frame, area: Rect, app: &App) {
    let head = |s: &str| Line::styled(format!(" {s}"), Style::default().add_modifier(Modifier::BOLD));
    let key = |k: &str, what: &str| Line::raw(format!("   {k:<14}{what}"));
    let lines = vec![
        head("Список профилей"),
        key("↑ ↓ / k j", "выбрать профиль"),
        key("Enter", "подключиться к выбранному профилю"),
        key("d", "отключиться (чистый разрыв — kill-switch снимается)"),
        key("a", "добавить профиль из citadel://-ссылки"),
        key("x", "удалить выбранный профиль (спросит подтверждение)"),
        key("s", "split-tunnel: какие назначения идут через туннель"),
        key("K", "kill-switch вкл/выкл (действует со следующего подключения)"),
        key("D", "снять залипшие fail-closed правила (нет сети после краха)"),
        key("l", "закрыть хранилище (профили уйдут из памяти)"),
        key("q / Esc", "выйти из интерфейса"),
        Line::raw(""),
        head("Split-tunnel  (экран «s»)"),
        key("m", "режим: off → exclude → include"),
        key("a / x", "добавить / удалить назначение (IP, CIDR или домен)"),
        key("↑ ↓", "выбрать назначение в списке"),
        key("Esc / q", "назад к профилям"),
        Line::raw("   exclude — перечисленное идёт МИМО туннеля; include — только оно В туннель"),
        Line::raw(""),
        head("Ввод (пароль, ссылка, назначение)"),
        key("Enter", "подтвердить"),
        key("Tab", "показать/скрыть введённое (ссылка — это креды, по умолчанию скрыта)"),
        key("Esc", "отмена (на экране пароля — выход)"),
        Line::raw(""),
        head("Всегда"),
        key("? / h / F1", "эта справка (в поле ввода — только F1)"),
        key("Ctrl-C", "выйти из интерфейса"),
        Line::raw(""),
        head("Что важно понимать"),
        Line::raw("   Выход из интерфейса НЕ разрывает туннель: соединение держит системный"),
        Line::raw("   демон citadel-vpnd. Отключает только «d» (или citadel-cli disconnect)."),
        Line::raw("   Хранилище закрывается само после 10 минут без нажатий."),
        Line::raw("   Подробности ошибок — в журнале сессии справа и в `journalctl -u citadel-vpnd`."),
    ];
    let total = lines.len() as u16;
    // Не даём прокрутить в пустоту: максимум — когда последняя строка у нижней рамки.
    let visible = area.height.saturating_sub(2);
    let scroll = app.help_scroll.min(total.saturating_sub(visible));
    f.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(" Справка по клавишам ")),
        area,
    );
}

fn draw_input(f: &mut Frame, area: Rect, app: &App, title: &str, hint: &str) {
    let shown = if app.masked {
        "•".repeat(app.input.chars().count())
    } else {
        app.input.to_string()
    };
    let body = vec![
        Line::raw(""),
        Line::raw(format!("  {shown}▏")),
        Line::raw(""),
        Line::raw(format!("  {hint}")),
    ];
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(format!(" {title} "))),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let keys = match app.screen {
        Screen::Main => " Enter подключить │ d отключить │ a добавить │ x удалить │ K kill-switch │ D снять защиту │ s split │ l закрыть хранилище │ ? справка │ q выход",
        Screen::Unlock { .. } => " Enter подтвердить │ F1 справка │ Esc выход",
        Screen::AddLink => " Enter добавить │ Tab показать/скрыть │ F1 справка │ Esc отмена",
        Screen::ConfirmRemove { .. } => " y удалить │ любая другая — отмена",
        Screen::Split { .. } => " m режим │ a добавить │ x удалить │ ? справка │ Esc назад",
        Screen::Help { .. } => " ↑↓ прокрутка │ любая клавиша — назад",
    };
    let style = if app.error {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let msg = if app.message.is_empty() { keys.to_string() } else { format!(" {}", app.message) };
    f.render_widget(
        Paragraph::new(Line::styled(msg, style)).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

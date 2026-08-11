//! Разведка: не оставляет ли НЕУДАЧНАЯ попытка подключения работающих ресурсов.
//!
//! Живой симптом (Windows, 2026-08-11): каждая неудачная попытка добавляет процессу постоянную
//! нагрузку на CPU — 15% после первой, ~98% после нескольких, и она НЕ спадает после «Отключить».
//! Значит от попытки остаётся что-то, что продолжает работать. Здесь это воспроизводится в
//! точности той же обстановкой, что у абонента: exit не отвечает по UDP, а TCP-порт соединение
//! ПРИНИМАЕТ и молчит (именно так выглядит и заблокированный UDP, и наш собственный рассинхрон L1).
//!
//! Меряем не «утечку памяти», а потраченное процессом ПРОЦЕССОРНОЕ ВРЕМЯ в простое: после серии
//! неудачных попыток процесс обязан снова стать тихим.

#![cfg(target_os = "linux")]

use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

use citadel_quic::config::{ClientConfig, MldsaSource, PinSource};

/// Процессорное время процесса (utime+stime) в миллисекундах — /proc/self/stat, поля 14 и 15.
fn cpu_ms() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").expect("/proc/self/stat");
    // comm может содержать пробелы и скобки — режем по последней ')'
    let tail = &s[s.rfind(')').expect("stat") + 2..];
    let f: Vec<&str> = tail.split_whitespace().collect();
    let ticks: u64 = f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap();
    let hz = 100; // CLK_TCK на всех наших целях
    ticks * 1000 / hz
}

/// Сколько процессорного времени процесс тратит, пока НИЧЕГО не просят делать.
fn idle_cpu_ms(dur: Duration) -> u64 {
    let a = cpu_ms();
    std::thread::sleep(dur);
    cpu_ms() - a
}

fn cfg(udp: &str, tcp_port: u16) -> ClientConfig {
    ClientConfig {
        servers: vec![udp.to_string()],
        server_name: "citadel.exit".into(),
        // obfs включён, как в боевой ссылке: иначе не пройдём тот же код, что у абонента.
        obfs_psk: Some([0x11; 32]),
        kx_suite: String::new(),
        tcp_port: tcp_port.to_string(),
        routes: String::new(),
        dns: None,
        mtu: "1280".into(),
        token: vec![7u8; 32],
        data_psk: None,
        pin: PinSource::Bytes([0x22; 32]), // pin обязателен (fail-closed), сервера всё равно нет
        mldsa: MldsaSource::None,
        allow_insecure_no_pin: false,
        allow_classical_kx: false,
        require_pq_auth: false,
        killswitch: false,
        split: Default::default(),
        pacing: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
// ~95 с (пять QUIC-попыток по 3 с + obfs-TCP-таймаут на каждую из трёх попыток, плюс замеры
// простоя), поэтому в общий прогон не берём: запускается руками при разборе жалоб на нагрузку —
// `cargo test -p citadel-quic --test failed_attempt_leak -- --ignored --nocapture`.
#[ignore = "долгий (~95 с): инструмент разбора, а не гейт"]
async fn failed_attempts_leave_no_running_work() {
    // «Чёрная дыра»: UDP молчит; TCP принимает соединение и держит его без единого байта.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((s, _)) = tcp.accept() {
            held.push(s); // принимаем и молчим — ровно как порт 443 у абонента
        }
    });

    let cfg = cfg(&udp_addr.to_string(), tcp_port);

    let base = idle_cpu_ms(Duration::from_secs(2));

    // Три неудачные попытки — как три нажатия «Подключиться».
    for i in 1..=3 {
        let r = citadel_quic::client::establish_session(&cfg, false).await;
        assert!(r.is_err(), "попытка {i} обязана провалиться: сервера нет");
        let idle = idle_cpu_ms(Duration::from_secs(2));
        eprintln!("[repro] после попытки {i}: простой стоит {idle} мс CPU (базовый {base} мс)");
    }

    let after = idle_cpu_ms(Duration::from_secs(3));
    // Порог с большим запасом: интересует не дрожание в десятки миллисекунд, а постоянная
    // нагрузка (у абонента — десятки процентов ядра, т.е. сотни мс на каждую секунду простоя).
    assert!(
        after < base + 300,
        "после неудачных попыток процесс продолжает работать: простой стоит {after} мс CPU \
         против {base} мс до попыток"
    );
}

//! Per-client rate-limit на exit (STRIDE D3 / F7): token bucket по байтам.
//!
//! Открытый exit-релей без ограничения скорости → клиент может исчерпать ресурсы/полосу
//! exit и upstream-сети (D3). Каждый pump (= соединение) держит свои bucket'ы, превышение →
//! дроп датаграммы (QUIC это переживает как потерю). Чистая логика без I/O — детерминированно
//! тестируется.
//!
//! **M-3-bis/аудит-4: направлений ДВА.** До этого bucket висел только на `Inbound`, то есть на
//! пути «клиент → интернет» (upload). Обратное направление — то самое, где живёт настоящая
//! нагрузка релея: скачивание торрента, стриминг, а в злоупотреблении — **амплификация**
//! (клиент отправляет мегабайт запросов, получает гигабайты ответов; лимит на upload здесь почти
//! не мешает). Поэтому на exit'е ограничиваются оба направления, независимыми bucket'ами
//! (как «до X Мбит/с вверх и до Y вниз» у любого провайдера), см. [`RateLimits`].

use std::time::Instant;

/// Конфиг лимита: `rate` байт/сек пополнение, `burst` байт — вместимость (допустимый всплеск).
#[derive(Clone, Copy, Debug)]
pub struct RateCfg {
    pub rate: f64,
    pub burst: f64,
}

impl RateCfg {
    /// Из пары переменных: `rate_var` (байт/с; пусто/0/мусор → None = без лимита) +
    /// `burst_var` (байт; default = `rate`, т.е. ~1 секунда всплеска).
    fn from_env_named(rate_var: &str, burst_var: &str) -> Option<Self> {
        let rate: f64 = std::env::var(rate_var).ok()?.trim().parse().ok()?;
        if rate <= 0.0 {
            return None;
        }
        let burst = std::env::var(burst_var)
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|b| *b > 0.0)
            .unwrap_or(rate);
        Some(Self { rate, burst })
    }

    /// Лимит направления «клиент → интернет»: `Citadel_RATE_LIMIT` / `Citadel_RATE_BURST`.
    pub fn from_env() -> Option<Self> {
        Self::from_env_named("Citadel_RATE_LIMIT", "Citadel_RATE_BURST")
    }

    /// M-3-bis: лимит направления «интернет → клиент». `Citadel_RATE_LIMIT_DOWN` /
    /// `Citadel_RATE_BURST_DOWN`; переменная НЕ задана → тот же лимит, что и вверх (симметрия —
    /// разумный дефолт: иначе обновление старого деплоя оставило бы download без ограничения
    /// вообще). Явный `Citadel_RATE_LIMIT_DOWN=0` = «вниз не ограничивать».
    pub fn from_env_down() -> Option<Self> {
        match std::env::var("Citadel_RATE_LIMIT_DOWN") {
            Ok(_) => Self::from_env_named("Citadel_RATE_LIMIT_DOWN", "Citadel_RATE_BURST_DOWN"),
            Err(_) => Self::from_env(),
        }
    }
}

/// Лимиты соединения по направлениям (только exit; на клиенте оба `None`).
#[derive(Clone, Copy, Debug, Default)]
pub struct RateLimits {
    /// Клиент → интернет (проверяется в [`crate::dataplane::Inbound`]).
    pub up: Option<RateCfg>,
    /// Интернет → клиент (проверяется в sender-задаче `pump`, M-3-bis).
    pub down: Option<RateCfg>,
}

impl RateLimits {
    pub fn from_env() -> Self {
        Self { up: RateCfg::from_env(), down: RateCfg::from_env_down() }
    }
}

/// Минимальная «стоимость» пакета в токенах-байтах: чтобы флуд мелких пакетов
/// (PPS-абуз) тоже резался, а не только bandwidth крупными пакетами.
pub const MIN_PACKET_COST: f64 = 64.0;

/// Token bucket: пополняется `rate`/сек до потолка `burst`, списывает `cost` за пакет.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(cfg: RateCfg, now: Instant) -> Self {
        Self { rate: cfg.rate, burst: cfg.burst, tokens: cfg.burst, last: now }
    }

    /// Пополнить по прошедшему времени и попытаться списать `cost`.
    /// `true` — пропустить пакет; `false` — превышение лимита (вызывающий дропает).
    pub fn allow(&mut self, cost: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Стоимость пакета: его размер на проводе, но не меньше `MIN_PACKET_COST`.
    pub fn packet_cost(len: usize) -> f64 {
        (len as f64).max(MIN_PACKET_COST)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allows_within_burst_then_blocks() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(RateCfg { rate: 1000.0, burst: 1000.0 }, t0);
        // burst=1000: ровно 10 пакетов по 100 проходят без подкачки времени, 11-й — нет.
        for _ in 0..10 {
            assert!(b.allow(100.0, t0));
        }
        assert!(!b.allow(100.0, t0));
    }

    #[test]
    fn refills_over_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(RateCfg { rate: 1000.0, burst: 1000.0 }, t0);
        assert!(b.allow(1000.0, t0)); // исчерпали
        assert!(!b.allow(1.0, t0));
        let t1 = t0 + Duration::from_millis(500); // +500 токенов за 0.5с
        assert!(b.allow(500.0, t1));
        assert!(!b.allow(1.0, t1));
    }

    #[test]
    fn refill_capped_at_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(RateCfg { rate: 1000.0, burst: 1000.0 }, t0);
        b.allow(1000.0, t0);
        let t1 = t0 + Duration::from_secs(100); // накопилось бы 100k, но потолок = burst
        assert!(b.allow(1000.0, t1));
        assert!(!b.allow(1.0, t1));
    }

    /// M-3-bis: обратное направление наследует общий лимит (обновление старого деплоя не должно
    /// оставлять download без ограничения), явный `_DOWN` его переопределяет, а `_DOWN=0` —
    /// осознанное «вниз не резать».
    #[test]
    fn down_limit_defaults_to_up_and_can_be_overridden() {
        // SAFETY (тест): переменные F7 не трогает больше никто; убираются в конце.
        std::env::set_var("Citadel_RATE_LIMIT", "1000");
        std::env::remove_var("Citadel_RATE_BURST");
        std::env::remove_var("Citadel_RATE_LIMIT_DOWN");
        let r = RateLimits::from_env();
        assert_eq!(r.up.unwrap().rate, 1000.0);
        assert_eq!(r.down.unwrap().rate, 1000.0, "не задан _DOWN → симметрия, а не «без лимита»");

        std::env::set_var("Citadel_RATE_LIMIT_DOWN", "4000");
        std::env::set_var("Citadel_RATE_BURST_DOWN", "8000");
        let r = RateLimits::from_env();
        assert_eq!((r.up.unwrap().rate, r.down.unwrap().rate), (1000.0, 4000.0));
        assert_eq!(r.down.unwrap().burst, 8000.0);

        std::env::set_var("Citadel_RATE_LIMIT_DOWN", "0");
        assert!(RateLimits::from_env().down.is_none(), "явный 0 = не ограничивать вниз");

        for v in ["Citadel_RATE_LIMIT", "Citadel_RATE_LIMIT_DOWN", "Citadel_RATE_BURST_DOWN"] {
            std::env::remove_var(v);
        }
        let r = RateLimits::from_env();
        assert!(r.up.is_none() && r.down.is_none(), "ничего не задано — лимитов нет");
    }

    #[test]
    fn packet_cost_has_floor() {
        assert_eq!(TokenBucket::packet_cost(10), MIN_PACKET_COST);
        assert_eq!(TokenBucket::packet_cost(1400), 1400.0);
    }
}

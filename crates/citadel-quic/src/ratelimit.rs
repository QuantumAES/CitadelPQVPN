//! Per-client rate-limit на exit (STRIDE D3 / F7): token bucket по байтам.
//!
//! Открытый exit-релей без ограничения скорости → клиент может исчерпать ресурсы/полосу
//! exit и upstream-сети (D3). Лимит — на входящее (от клиента) направление в `pump`:
//! каждый pump (= соединение) держит свой bucket, превышение → дроп датаграммы (QUIC
//! это переживает как потерю). Чистая логика без I/O — детерминированно тестируется.

use std::time::Instant;

/// Конфиг лимита: `rate` байт/сек пополнение, `burst` байт — вместимость (допустимый всплеск).
#[derive(Clone, Copy, Debug)]
pub struct RateCfg {
    pub rate: f64,
    pub burst: f64,
}

impl RateCfg {
    /// Из env: `Citadel_RATE_LIMIT` (байт/с; пусто/0/мусор → None = без лимита) +
    /// `Citadel_RATE_BURST` (байт; default = `rate`, т.е. ~1 секунда всплеска).
    pub fn from_env() -> Option<Self> {
        let rate: f64 = std::env::var("Citadel_RATE_LIMIT").ok()?.trim().parse().ok()?;
        if rate <= 0.0 {
            return None;
        }
        let burst = std::env::var("Citadel_RATE_BURST")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|b| *b > 0.0)
            .unwrap_or(rate);
        Some(Self { rate, burst })
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

    #[test]
    fn packet_cost_has_floor() {
        assert_eq!(TokenBucket::packet_cost(10), MIN_PACKET_COST);
        assert_eq!(TokenBucket::packet_cost(1400), 1400.0);
    }
}

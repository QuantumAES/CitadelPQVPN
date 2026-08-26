//! Дедлайны, переживающие сон устройства.
//!
//! `std::time::Instant` — это `CLOCK_MONOTONIC`, и на Linux (а значит и на Android) он **стоит,
//! пока устройство в suspend**. Телефон с погашенным экраном, тем более в авиарежиме, спит
//! часами: настенные часы уходят вперёд, монотонные — почти нет. Любой срок длиннее пары минут,
//! отмеренный только от `Instant`, на мобилке живёт кратно дольше назначенного.
//!
//! Для L1 это не мелочь, а обрыв связи. Ключ эпохи (H-3) exit принимает ровно две эпохи, судит их
//! по НАСТЕННЫМ часам и всё остальное молча отбрасывает — на проводе это неотличимо от закрытого
//! порта. Кошелёк токенов, считавший свою годность монотонно, после долгого сна отдавал ключ
//! позапрошлой эпохи и был уверен, что тот свежий: и QUIC/UDP, и obfs-TCP умирали одновременно и
//! навсегда, а лечил только перезапуск процесса.
//!
//! [`Deadline`] держит обе шкалы и считается прошедшим по ЛЮБОЙ из них: монотонная не даёт
//! продлить срок переводом системных часов назад, настенная — просыпанием. Обратная сторона —
//! перевод часов вперёд состарит дедлайн раньше времени; для всех наших сроков (пачка токенов,
//! блокировка по квоте, вердикт о QUIC/UDP) это безопасная сторона ошибки: лишний поход к
//! издателю против бесконечного ретрая под мёртвым ключом.

use std::time::{Duration, Instant, SystemTime};

/// Момент в будущем, отмеренный сразу по монотонным и по настенным часам.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    mono: Instant,
    /// `None` — настенные часы не смогли отмерить срок (переполнение `SystemTime`): остаётся
    /// монотонная половина, это не повод считать дедлайн прошедшим.
    wall: Option<SystemTime>,
}

impl Deadline {
    /// Дедлайн через `d` от «сейчас».
    pub fn after(d: Duration) -> Self {
        Self { mono: Instant::now() + d, wall: SystemTime::now().checked_add(d) }
    }

    /// Собрать из готовых половин. Публично не только ради тестов: этим же конструктором
    /// задаётся срок, у которого настенная граница известна точнее, чем «сейчас + столько-то»
    /// (конец эпохи издателя), — и им же в тестах моделируется сон устройства, когда монотонная
    /// половина ещё не прошла, а настенная уже.
    pub fn from_parts(mono: Instant, wall: Option<SystemTime>) -> Self {
        Self { mono, wall }
    }

    /// Сколько осталось по ближайшей из двух шкал. `None` — срок вышел хотя бы по одной.
    pub fn remaining(&self) -> Option<Duration> {
        let mono = self.mono.checked_duration_since(Instant::now())?;
        match self.wall {
            // `duration_since` отдаёт `Err`, когда момент уже позади, — это и есть «вышел».
            Some(w) => Some(mono.min(w.duration_since(SystemTime::now()).ok()?)),
            None => Some(mono),
        }
    }

    /// Прошёл ли срок (по любой из шкал).
    pub fn passed(&self) -> bool {
        self.remaining().is_none_or(|left| left.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_deadline_is_not_passed_and_reports_time_left() {
        let d = Deadline::after(Duration::from_secs(60));
        assert!(!d.passed());
        assert!(d.remaining().expect("срок не вышел") > Duration::from_secs(50));
    }

    #[test]
    fn zero_and_past_deadlines_are_passed() {
        assert!(Deadline::after(Duration::ZERO).passed());
        let past = Deadline::from_parts(
            Instant::now() - Duration::from_secs(1),
            SystemTime::now().checked_sub(Duration::from_secs(1)),
        );
        assert!(past.passed() && past.remaining().is_none());
    }

    /// Ради чего всё и затевалось: устройство проспало срок целиком. Монотонные часы во время
    /// suspend стоят, поэтому их половина ещё «не вышла» — а настенные ушли вперёд, и дедлайн
    /// обязан считаться прошедшим. Раньше здесь была бы «свежая» пачка с ключом мёртвой эпохи.
    #[test]
    fn wall_clock_expiry_wins_over_frozen_monotonic() {
        let slept = Deadline::from_parts(
            Instant::now() + Duration::from_secs(3600), // монотонные часы «проспали» час
            SystemTime::now().checked_sub(Duration::from_secs(1)), // настенные — прошли
        );
        assert!(slept.passed(), "дедлайн проспан по настенным часам, но выглядит свежим");
        assert!(slept.remaining().is_none());
    }

    /// И симметрично: перевод системных часов НАЗАД не продлевает срок — монотонная половина
    /// отработает сама. Это исходный инвариант, который нельзя было потерять ради первого.
    #[test]
    fn monotonic_expiry_survives_wall_clock_rollback() {
        let tampered = Deadline::from_parts(
            Instant::now() - Duration::from_secs(1),        // монотонные — вышли
            SystemTime::now().checked_add(Duration::from_secs(86_400)), // часы «отмотали назад»
        );
        assert!(tampered.passed(), "перевод часов назад не должен продлевать срок");
    }

    /// Остаток — по ближайшей шкале, а не по той, что удобнее.
    #[test]
    fn remaining_takes_the_nearer_scale() {
        let d = Deadline::from_parts(
            Instant::now() + Duration::from_secs(3600),
            SystemTime::now().checked_add(Duration::from_secs(60)),
        );
        assert!(d.remaining().expect("срок не вышел") <= Duration::from_secs(60));
    }
}

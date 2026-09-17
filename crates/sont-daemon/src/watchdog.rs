//! Сторож главного цикла: замечает, что демон перестал работать, и перезапускает
//! его.
//!
//! # Зачем
//!
//! Упавший процесс перезапускает диспетчер служб. Зависший — никто: процесс
//! жив, служба «работает», а соединения нет и не будет. У пользователя так и
//! случилось. Машина ушла в режим ожидания посреди переподключения, демон
//! замер — и почти сутки не писал в журнал, не отвечал окну и не пытался
//! подключиться снова. Окно, запущенное утром, повисло на рукопожатии, а сеть
//! всё это время шла напрямую.
//!
//! # Как
//!
//! Главный цикл отмечается каждую секунду. Сторож живёт в собственном потоке
//! операционной системы, а не в рантайме, — иначе он замер бы вместе с тем, за
//! чем следит. Цикл молчит дольше [`HANG_LIMIT`] — сторож пишет причину в
//! журнал и завершает процесс. Для диспетчера служб это сбой, и он поднимает
//! службу заново: TUN-адаптер и сессионные фильтры уходят вместе с процессом,
//! новый демон начинает с чистого листа.
//!
//! # Сон машины — не зависание
//!
//! В режиме ожидания Windows придерживает таймеры: проверки, идущие раз в
//! пятнадцать секунд, у пользователя приходили раз в четыре минуты. Сторож
//! видит это по себе — просыпается намного позже, чем просил, — и в такие
//! промежутки молчание цикла не засчитывает. Срок набирается только из времени,
//! когда машина работала в полную силу, а цикл при этом молчал.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Сколько молчания рабочего времени считать зависанием.
///
/// Полторы минуты. Главный цикл отмечается раз в секунду, а самая долгая
/// синхронная работа в нём — перестановка фильтров — занимает доли секунды.
/// Запас огромный, и он нужен: ложное срабатывание рвёт рабочее соединение.
pub const HANG_LIMIT: Duration = Duration::from_secs(90);

/// Как часто сторож проверяет отметки.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// Во сколько раз сторож может проспать дольше заказанного, прежде чем
/// промежуток перестанет считаться рабочим.
const LATE_FACTOR: u32 = 3;

// Главный цикл отмечается раз в секунду — срок обязан быть на порядки больше,
// а одна поздняя проверка не должна его исчерпывать.
const _: () = assert!(HANG_LIMIT.as_secs() >= 60);
const _: () = assert!(CHECK_EVERY.as_secs() * LATE_FACTOR as u64 * 2 < HANG_LIMIT.as_secs());

/// Отметка «главный цикл жив».
#[derive(Clone, Default)]
pub struct Heartbeat(Arc<AtomicU64>);

impl Heartbeat {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn beat(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Учёт молчания — без потоков и часов, чтобы его можно было проверить.
#[derive(Debug, Default)]
struct Stall {
    last_beat: u64,
    silent: Duration,
}

impl Stall {
    /// Принимает очередное наблюдение и отвечает, пора ли признать зависание.
    ///
    /// `slept` — сколько на самом деле прошло с прошлого наблюдения.
    fn observe(&mut self, beat: u64, slept: Duration) -> Option<Duration> {
        if beat != self.last_beat {
            self.last_beat = beat;
            self.silent = Duration::ZERO;
            return None;
        }

        // Проспали сильно дольше заказанного — машина спала или придерживала
        // таймеры. Цикл мог молчать по той же причине, и винить его не в чем:
        // отсчёт начинается заново.
        if slept > CHECK_EVERY * LATE_FACTOR {
            self.silent = Duration::ZERO;
            return None;
        }

        self.silent += slept;
        (self.silent >= HANG_LIMIT).then_some(self.silent)
    }
}

/// Запускает сторожа.
///
/// Отключается переменной `SONT_NO_WATCHDOG` — для отладчика, где остановка на
/// точке останова выглядит точно как зависание.
pub fn spawn(heartbeat: Heartbeat) {
    if std::env::var_os("SONT_NO_WATCHDOG").is_some() {
        tracing::warn!("сторож главного цикла отключён переменной SONT_NO_WATCHDOG");
        return;
    }

    let spawned = std::thread::Builder::new()
        .name("sont-watchdog".into())
        .spawn(move || {
            let mut stall = Stall {
                last_beat: heartbeat.count(),
                silent: Duration::ZERO,
            };
            let mut prev = Instant::now();
            let mut prev_wall = SystemTime::now();

            loop {
                std::thread::sleep(CHECK_EVERY);

                // Смотрим на оба источника времени: монотонные часы на части
                // машин не идут во сне, а системные — идут всегда.
                let now = Instant::now();
                let wall = SystemTime::now();
                let slept = now
                    .duration_since(prev)
                    .max(wall.duration_since(prev_wall).unwrap_or_default());
                prev = now;
                prev_wall = wall;

                if let Some(silent) = stall.observe(heartbeat.count(), slept) {
                    die(&format!(
                        "главный цикл демона не отвечает {} с — перезапускаю службу",
                        silent.as_secs()
                    ));
                }
            }
        });

    if let Err(e) = spawned {
        tracing::error!(error = %e, "не удалось запустить сторожа главного цикла");
    }
}

/// Завершает процесс так, чтобы диспетчер служб поднял его заново.
///
/// Именно завершение, а не штатная остановка: штатная пошла бы через тот же
/// замерший или погибший цикл. А внезапный выход диспетчер считает сбоем и
/// применяет к нему настроенный перезапуск.
pub fn die(reason: &str) -> ! {
    tracing::error!("{reason}");
    // Журнал пишется отдельным потоком. Даём ему донести последнюю строку —
    // ради неё всё и затевалось.
    std::thread::sleep(Duration::from_millis(500));
    std::process::exit(70);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_loop_on_an_awake_machine_is_a_hang() {
        let mut stall = Stall::default();
        let mut verdict = None;
        let mut elapsed = Duration::ZERO;
        while verdict.is_none() {
            elapsed += CHECK_EVERY;
            verdict = stall.observe(0, CHECK_EVERY);
            assert!(elapsed <= HANG_LIMIT, "сторож обязан сработать к сроку");
        }
        assert_eq!(elapsed, HANG_LIMIT);
    }

    #[test]
    fn every_beat_starts_the_count_over() {
        // Цикл, отмечающийся хоть изредка, жив — сколько бы времени ни прошло
        // в сумме.
        let mut stall = Stall::default();
        let mut beat = 0;
        for _ in 0..1000 {
            assert!(stall.observe(beat, CHECK_EVERY).is_none());
            if stall.silent >= HANG_LIMIT - CHECK_EVERY {
                beat += 1;
            }
        }
    }

    #[test]
    fn a_sleeping_machine_is_not_a_hung_daemon() {
        // Ровно то, что было у пользователя: ноутбук в режиме ожидания,
        // таймеры придержаны, цикл молчит часами. Убить демон за это значило
        // бы рвать соединение при каждом открытии крышки.
        let mut stall = Stall::default();
        for _ in 0..10_000 {
            assert!(stall.observe(0, Duration::from_secs(240)).is_none());
        }
    }

    #[test]
    fn waking_up_restarts_the_count() {
        // После пробуждения цикл вправе догонять. Молчание до сна не должно
        // складываться с молчанием после.
        let mut stall = Stall::default();
        for _ in 0..17 {
            assert!(stall.observe(0, CHECK_EVERY).is_none());
        }
        assert!(stall.observe(0, Duration::from_secs(3600)).is_none());
        assert_eq!(stall.silent, Duration::ZERO);

        for _ in 0..17 {
            assert!(stall.observe(0, CHECK_EVERY).is_none());
        }
        assert!(stall.observe(0, CHECK_EVERY).is_some(), "бодрствующая машина — срок истёк");
    }

    #[test]
    fn a_slightly_late_check_still_counts() {
        // Небольшие опоздания обычны и под нагрузкой. Не засчитывай их — и
        // занятый, но зависший демон не был бы пойман никогда.
        let mut stall = Stall::default();
        let late = CHECK_EVERY * 2;
        let mut rounds = 0;
        while stall.observe(0, late).is_none() {
            rounds += 1;
            assert!(rounds < 100);
        }
    }
}

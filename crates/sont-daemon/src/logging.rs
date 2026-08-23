//! Логирование демона и кольцевой буфер для экрана «Логи» в UI.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Сколько последних строк держим в памяти.
///
/// Буфер нужен, чтобы UI мог показать хвост журнала, не читая файлы из
/// системного каталога — у непривилегированного tray туда доступа нет.
const CAPACITY: usize = 1000;

/// Разделяемый кольцевой буфер строк.
#[derive(Clone, Default)]
pub struct LogBuffer {
    inner: Arc<Mutex<VecDeque<String>>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(CAPACITY))),
        }
    }

    fn push(&self, line: String) {
        // Отравленный mutex не повод ронять демон: журнал — вспомогательная
        // функция, и её отказ не должен уносить с собой VPN-соединение.
        let Ok(mut buf) = self.inner.lock() else {
            return;
        };
        if buf.len() == CAPACITY {
            buf.pop_front();
        }
        buf.push_back(line);
    }

    /// Последние `n` строк, от старых к новым.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let Ok(buf) = self.inner.lock() else {
            return Vec::new();
        };
        let skip = buf.len().saturating_sub(n);
        buf.iter().skip(skip).cloned().collect()
    }
}

/// Слой tracing, складывающий события в [`LogBuffer`].
struct RingLayer {
    buffer: LogBuffer,
}

impl<S: tracing::Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);

        let meta = event.metadata();
        let mut line = String::with_capacity(96);
        let _ = write!(
            line,
            "{} {:>5} {}: {}",
            utc_time_of_day(),
            meta.level(),
            meta.target(),
            visitor.message
        );
        for (k, v) in &visitor.fields {
            let _ = write!(line, " {k}={v}");
        }

        self.buffer.push(line);
    }
}

/// Достаёт из события сообщение и остальные поля.
#[derive(Default)]
struct LineVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visit for LineVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            self.fields.push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            self.fields.push((field.name().to_owned(), value.to_owned()));
        }
    }
}

/// Время суток по UTC как `ЧЧ:ММ:СС`.
///
/// Полноценная работа с календарём здесь не нужна: строки живут минуты и
/// служат для сопоставления событий между собой, а не для отчётности. Ради
/// этого тянуть зависимость с базой часовых поясов незачем.
fn utc_time_of_day() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Настраивает вывод в консоль и кольцевой буфер.
///
/// Уровень берётся из `SONT_LOG`, иначе из переданного значения.
pub fn init(default_level: &str) -> LogBuffer {
    let buffer = LogBuffer::new();

    let registry = tracing_subscriber::registry()
        .with(filter(default_level))
        .with(tracing_subscriber::fmt::layer().with_target(true).with_ansi(false))
        .with(RingLayer {
            buffer: buffer.clone(),
        });

    // Повторная инициализация в тестах — не ошибка, просто игнорируем.
    let _ = registry.try_init();

    buffer
}

/// Настраивает вывод в файл — для работы службой.
///
/// У службы нет консоли: без файла она становится неотлаживаемой, и любая
/// проблема у пользователя превращается в гадание. Файлы посуточные, чтобы
/// журнал не рос без предела.
///
/// Возвращаемый страж обязан жить всё время работы демона: его уничтожение
/// закрывает поток записи, и последние строки — как раз те, что объясняют
/// падение, — теряются.
pub fn init_to_file(default_level: &str, dir: &std::path::Path) -> (LogBuffer, WorkerGuard) {
    let buffer = LogBuffer::new();

    let appender = tracing_appender::rolling::daily(dir, "sontd.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);

    let registry = tracing_subscriber::registry()
        .with(filter(default_level))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_writer(writer),
        )
        .with(RingLayer {
            buffer: buffer.clone(),
        });

    let _ = registry.try_init();

    (buffer, guard)
}

/// Сетевой слой пишет строку на каждое соединение — это надо приглушить.
///
/// `tun2proxy` и его `ipstack` сообщают о начале и конце **каждой** сессии, а
/// сессией у них считается и одиночный UDP-пакет. За сутки это дало сорок три
/// мегабайта журнала, в которых утонуло всё остальное: чтобы найти в нём
/// причину отказа, пришлось отфильтровывать девяносто девять процентов строк.
/// Журнал, в котором нельзя ничего найти, не выполняет своего единственного
/// назначения.
///
/// Их собственная настройка подробности тут не помогает: они пишут через
/// `tracing`, и уровень им задаёт наш подписчик, а не переданный им аргумент.
///
/// Предупреждения и ошибки остаются: именно они и нужны.
const NOISY: [&str; 2] = ["tun2proxy=warn", "ipstack=warn"];

fn filter(default_level: &str) -> EnvFilter {
    // Своё значение из переменной окружения уважаем целиком: если человек
    // просит подробностей от сетевого слоя, он их и получает.
    if let Ok(explicit) = EnvFilter::try_from_env("SONT_LOG") {
        return explicit;
    }

    let mut filter = EnvFilter::new(default_level);
    for directive in NOISY {
        // Разбор константы не может не удаться, но паниковать из-за журнала
        // всё равно незачем.
        if let Ok(parsed) = directive.parse() {
            filter = filter.add_directive(parsed);
        }
    }
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_returns_newest_lines_in_order() {
        let buf = LogBuffer::new();
        for i in 0..10 {
            buf.push(format!("строка {i}"));
        }
        let tail = buf.tail(3);
        assert_eq!(tail, vec!["строка 7", "строка 8", "строка 9"]);
    }

    #[test]
    fn buffer_is_bounded() {
        let buf = LogBuffer::new();
        for i in 0..(CAPACITY + 500) {
            buf.push(format!("{i}"));
        }
        assert_eq!(buf.tail(usize::MAX).len(), CAPACITY);
        // Самые старые строки должны быть вытеснены.
        assert_eq!(buf.tail(1), vec![format!("{}", CAPACITY + 499)]);
    }

    #[test]
    fn tail_larger_than_content_is_fine() {
        let buf = LogBuffer::new();
        buf.push("одна".into());
        assert_eq!(buf.tail(100), vec!["одна"]);
    }

    #[test]
    fn empty_buffer_yields_nothing() {
        assert!(LogBuffer::new().tail(10).is_empty());
    }

    #[test]
    fn time_of_day_is_well_formed() {
        let t = utc_time_of_day();
        assert_eq!(t.len(), 8, "неожиданный формат: {t}");
        let parts: Vec<&str> = t.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].parse::<u32>().unwrap() < 24);
        assert!(parts[1].parse::<u32>().unwrap() < 60);
        assert!(parts[2].parse::<u32>().unwrap() < 60);
    }
}

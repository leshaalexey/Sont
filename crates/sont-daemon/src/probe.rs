//! Замер задержки до серверов подписки.
//!
//! # Чем меряем
//!
//! Временем установления TCP-соединения с эндпоинтом сервера. Не ICMP: `ping`
//! требует сырого сокета, то есть прав администратора, а клиенты Sont их
//! принципиально не имеют, да и провайдеры ICMP регулярно режут — сервер
//! оказался бы «недоступен», прекрасно принимая TCP.
//!
//! Не через ядро: замер нужен и тогда, когда ядро не запущено, — например,
//! чтобы выбрать сервер до первого подключения.
//!
//! # Что этот замер значит, а что нет
//!
//! Это задержка до входа сервера, а не скорость канала и не задержка до сайта,
//! который откроет пользователь. Для выбора «на какой сервер идти» этого
//! достаточно: разница между 30 мс и 250 мс определяет ощущение от работы, а
//! точное значение — нет.
//!
//! Важная оговорка про режим туннеля: пока туннель поднят, соединение к
//! **чужому** серверу идёт сквозь него, и замер показывает сумму двух путей.
//! Сравнивать такие числа между собой можно, с прямыми замерами — нет. Для
//! переключения при падении это безвредно: там туннель уже не работает, и
//! замер получается прямым.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sont_core::{ProbeResult, ServerProfile};

/// Сколько раз подключаемся к одному серверу.
///
/// Один замер ловит случайную задержку планировщика или переполненный буфер и
/// выдаёт её за свойство сервера. Три дают медиану, устойчивую к одному
/// выбросу, и при этом не превращают замер всей подписки в минутное занятие.
const ATTEMPTS: usize = 3;

/// Сколько ждём одну попытку.
///
/// Сервер, который не отвечает две секунды, для выбора уже проиграл: даже
/// дождавшись, мы поставили бы его в конец списка. А ждать дольше значит
/// растянуть замер подписки из полусотни серверов до неприличия.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Сколько серверов меряем одновременно.
///
/// Больше — быстрее, но полсотни одновременных соединений с одного адреса
/// выглядят для промежуточного оборудования как сканирование портов, а на
/// домашнем роутере ещё и переполняют таблицу NAT.
const CONCURRENCY: usize = 8;

/// Пауза между попытками к одному серверу.
///
/// Без неё три попытки уходят одним пакетным залпом и меряют одно и то же
/// состояние сети — то есть не дают ничего сверх одной попытки.
const BETWEEN_ATTEMPTS: Duration = Duration::from_millis(120);

/// Меряет один сервер.
///
/// Возвращает результат всегда: недоступность — это тоже измерение, и молчание
/// вместо него заставило бы вызывающего гадать, то ли сервер плох, то ли
/// замер не состоялся.
pub async fn one(profile: &ServerProfile) -> ProbeResult {
    let host = profile.endpoint.host.clone();
    let port = profile.endpoint.port;

    // Имя разрешаем один раз и дальше подключаемся по адресу: иначе первая
    // попытка включала бы в себя работу резолвера, а следующие — нет, и
    // медиана считалась бы по разнородным величинам.
    let addrs = resolve(&host, port).await;

    let mut rtts: Vec<u32> = Vec::with_capacity(ATTEMPTS);
    let mut failures = 0usize;

    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(BETWEEN_ATTEMPTS).await;
        }
        match connect_once(&addrs).await {
            Some(rtt) => rtts.push(rtt),
            None => failures += 1,
        }
    }

    ProbeResult {
        server: profile.id.clone(),
        rtt_ms: median(&mut rtts),
        loss_percent: percent(failures, ATTEMPTS),
        measured_at_unix_ms: crate::supervisor::now_unix_ms(),
    }
}

/// Меряет несколько серверов, ограничивая одновременность.
pub async fn many(profiles: Vec<ServerProfile>) -> Vec<ProbeResult> {
    use futures_util::stream::{self, StreamExt};

    stream::iter(profiles)
        .map(|profile| async move { one(&profile).await })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await
}

async fn resolve(host: &str, port: u16) -> Vec<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }

    match tokio::time::timeout(ATTEMPT_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => addrs.collect(),
        // Имя не разрешилось — сервер недоступен, и это законный результат
        // замера. Пустой список приведёт к нулю удачных попыток.
        _ => Vec::new(),
    }
}

/// Одна попытка: сколько миллисекунд занял приём соединения.
async fn connect_once(addrs: &[SocketAddr]) -> Option<u32> {
    let addr = *addrs.first()?;
    let started = Instant::now();

    match tokio::time::timeout(ATTEMPT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Закрываем сразу: держать соединение незачем, а сервер не должен
            // копить наши висящие сессии.
            drop(stream);
            Some(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32)
        }
        // И отказ, и таймаут — неудачная попытка. Различать их незачем:
        // пользователю важно, что сервер не отвечает.
        _ => None,
    }
}

/// Медиана удачных попыток.
///
/// Именно медиана, а не среднее: одна попытка, попавшая в таймаут соседнего
/// процесса, сдвигает среднее так, что хороший сервер уезжает в конец списка.
fn median(values: &mut [u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

fn percent(part: usize, whole: usize) -> u8 {
    if whole == 0 {
        return 0;
    }
    ((part * 100) / whole).min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_ignores_a_single_outlier() {
        // Ради этого медиана и выбрана: одна попытка, попавшая под нагрузку,
        // не должна решать судьбу сервера.
        assert_eq!(median(&mut [30, 32, 2000]), Some(32));
        assert_eq!(median(&mut [50]), Some(50));
    }

    #[test]
    fn no_successful_attempts_means_unreachable() {
        assert_eq!(median(&mut []), None);
    }

    #[test]
    fn loss_is_a_percentage_of_all_attempts() {
        assert_eq!(percent(0, 3), 0);
        assert_eq!(percent(1, 3), 33);
        assert_eq!(percent(3, 3), 100);
        // Делить на ноль незачем, но и падать тут не за что.
        assert_eq!(percent(1, 0), 0);
    }

    #[tokio::test]
    async fn closed_port_is_reported_as_unreachable_not_as_absence_of_result() {
        // Недоступность — это результат замера. Вернув «ничего», мы заставили
        // бы автовыбор считать сервер неизмеренным, то есть предпочесть его
        // измеренному и заведомо рабочему.
        let profile = unreachable_profile();
        let result = one(&profile).await;

        assert_eq!(result.server, profile.id);
        assert!(!result.is_reachable());
        assert_eq!(result.loss_percent, 100);
        assert_eq!(result.score(), u32::MAX);
    }

    #[tokio::test]
    async fn a_listening_port_answers_with_a_latency() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Принимаем всё, что придёт: замеряется именно приём соединения.
            while listener.accept().await.is_ok() {}
        });

        let profile = profile_at("127.0.0.1", port);
        let result = one(&profile).await;

        assert!(result.is_reachable(), "локальный слушатель обязан ответить");
        assert_eq!(result.loss_percent, 0);
    }

    fn profile_at(host: &str, port: u16) -> ServerProfile {
        use sont_core::{Endpoint, Secret, Security, Stream, SubscriptionId, Transport};

        ServerProfile::new(
            "проверочный",
            Endpoint::new(host, port),
            Transport::Vless(sont_core::transport::Vless {
                uuid: Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: None,
                stream: Stream::Tcp,
                security: Security::None,
            }),
            SubscriptionId::from_url("https://panel.example/sub"),
        )
    }

    fn unreachable_profile() -> ServerProfile {
        // Порт 9 — discard: на localhost его почти наверняка никто не слушает.
        profile_at("127.0.0.1", 9)
    }
}

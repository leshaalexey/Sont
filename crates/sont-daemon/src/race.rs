//! Гонка серверов: кто первым проведёт настоящий запрос, тот и рабочий.
//!
//! # Зачем
//!
//! Демон обязан подключаться к серверу, который работает, а не к тому, который
//! отвечает. Разница не тонкая: у сервера с истёкшим ключом, сломанной
//! конфигурацией или снятым ядром вход по-прежнему принимает соединения, а у
//! Reality он ещё и отвечает настоящим рукопожатием TLS — он для того и
//! устроен, чтобы выглядеть обычным сайтом. Ни замер задержки, ни рукопожатие
//! такой сервер от исправного не отличают.
//!
//! Отличает его ровно одно: попытка провести через него запрос. Раньше эта
//! попытка была подключением — с созданием адаптера, правкой маршрутов и полным
//! сроком ожидания, и стоила она секунд десять на каждый негодный сервер.
//! Отсюда и брались минуты «подключаюсь» на плохой сети: демон перебирал
//! серверы по одному, и каждый следующий обходился так же дорого, как
//! предыдущий.
//!
//! Здесь та же проверка стоит один запуск ядра на всех: у каждого кандидата своя
//! дорожка — локальный вход, свой выход и правило между ними, — и все дорожки
//! проверяются одновременно. Побеждает та, что первой довела запрос до конца.
//!
//! # Почему победитель — это ещё и лучший
//!
//! Гонка меряет то, ради чего сервер и нужен: время до ответа настоящего сайта
//! через настоящий туннель. Замер задержки меряет путь до входной двери, и
//! между этими величинами нет ничего общего — перегруженный сервер с быстрым
//! пингом проигрывает дальнему и свободному. Первый пришедший ответ и есть
//! лучший из работающих, причём измеренный сейчас, а не пять минут назад.

use std::path::Path;
use std::time::{Duration, Instant};

use sont_core::{ProfileId, ServerProfile};

use crate::core::CoreLauncher;

/// Сколько серверов участвуют в гонке.
///
/// Восемь. Дорожки идут одновременно, поэтому их число почти не влияет на
/// время; влияет оно на вес конфигурации и на число одновременных исходящих
/// соединений. Восьми хватает с запасом: если не отозвался ни один из восьми
/// лучших серверов подписки, дело не в серверах, и перебор тут не поможет.
pub const LANES: usize = 8;

/// Предел всей гонки.
///
/// Пять секунд. Живой сервер отвечает за доли секунды — этот срок нужен не ему,
/// а на запуск ядра и на медленную мобильную сеть. Ждать дольше незачем: гонка
/// проверяет восьмерых сразу, и если за пять секунд не отозвался никто, лишнее
/// ожидание ничего не добавит.
const RACE_TIMEOUT: Duration = Duration::from_secs(5);

/// Предел одной попытки на дорожке.
///
/// Короче общего срока: зависший запрос не должен занимать дорожку целиком,
/// иначе за отведённое время она сделает одну попытку вместо нескольких.
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(2500);

/// Пауза между попытками на одной дорожке.
///
/// Ядро поднимает входы не мгновенно, и первые попытки упираются в закрытый
/// порт. Частый опрос localhost ничего не стоит, а выигрыш прямой: гонка
/// заканчивается ровно тогда, когда ответил первый сервер.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Итог гонки.
pub struct Winner {
    pub server: ProfileId,
    /// Сколько заняло прохождение запроса, мс. Не задержка до сервера, а время
    /// до ответа настоящего сайта через туннель.
    pub elapsed_ms: u32,
}

/// Находит среди кандидатов сервер, который действительно проводит трафик.
///
/// `None` — не отозвался никто. Это не значит, что все серверы негодны: так же
/// выглядит и пропавшая сеть, и не запустившееся ядро. Вызывающий обязан
/// трактовать это как «выбирай сам», а не как отказ.
pub async fn fastest_working(
    launcher: &CoreLauncher,
    candidates: &[ServerProfile],
    config_path: &Path,
    log_level: &str,
) -> Option<Winner> {
    if candidates.len() < 2 {
        // Выбирать не из чего: гонка из одного участника стоит запуска ядра и
        // не отвечает ни на один вопрос, которого не задаст само подключение.
        return None;
    }

    let lanes: Vec<(&ServerProfile, u16)> = candidates
        .iter()
        .take(LANES)
        .map(|server| (server, crate::supervisor::pick_free_port()))
        .collect();

    let config = match sont_xray::build_race(&lanes, log_level) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!(error = %e, "не удалось собрать конфигурацию проверки");
            return None;
        }
    };

    if let Err(e) = crate::supervisor::write_core_config(config_path, &config) {
        tracing::warn!(error = %e, "не удалось записать конфигурацию проверки");
        return None;
    }

    let mut core = match launcher.spawn(config_path).await {
        Ok(core) => core,
        Err(e) => {
            tracing::warn!(error = %e, "не удалось запустить проверку серверов");
            return None;
        }
    };

    let started = Instant::now();
    let outcome = tokio::select! {
        winner = first_to_answer(&lanes) => winner,
        // Ядро умерло вместе со всеми дорожками — ждать их по отдельности уже
        // нечего.
        _ = core.wait_exit() => {
            tracing::warn!(output = %core.recent_output(), "ядро проверки завершилось");
            None
        }
    };

    core.shutdown().await;

    // Файл содержит учётные данные всех проверенных серверов и больше не нужен.
    // Лишняя копия ключей на диске — это лишняя копия ключей на диске, даже в
    // каталоге демона.
    let _ = std::fs::remove_file(config_path);

    match &outcome {
        Some(winner) => tracing::info!(
            server = %winner.server,
            elapsed_ms = winner.elapsed_ms,
            checked = lanes.len(),
            spent_ms = started.elapsed().as_millis(),
            "проверка серверов: подключаюсь к тому, который отозвался первым"
        ),
        None => tracing::warn!(
            checked = lanes.len(),
            spent_ms = started.elapsed().as_millis(),
            "проверку не прошёл ни один сервер"
        ),
    }

    outcome
}

/// Ждёт первую дорожку, которая доведёт запрос до конца.
async fn first_to_answer(lanes: &[(&ServerProfile, u16)]) -> Option<Winner> {
    use futures_util::stream::{FuturesUnordered, StreamExt};

    let deadline = Instant::now() + RACE_TIMEOUT;
    let mut running: FuturesUnordered<_> = lanes
        .iter()
        .map(|(server, port)| run_lane(&server.id, *port, deadline))
        .collect();

    // Именно первый удачный, а не первый завершившийся: дорожка, упавшая через
    // сто миллисекунд, не должна отменять гонку для тех, кто ещё идёт.
    while let Some(result) = running.next().await {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Одна дорожка: повторяет запрос через свой локальный вход до победы или срока.
async fn run_lane(server: &ProfileId, port: u16, deadline: Instant) -> Option<Winner> {
    let proxy = reqwest::Proxy::all(format!("socks5://127.0.0.1:{port}")).ok()?;
    let client = reqwest::Client::builder()
        .timeout(ATTEMPT_TIMEOUT)
        .proxy(proxy)
        // Каждая попытка обязана открывать новое соединение: пока ядро не
        // подняло вход, попытка упирается в закрытый порт, и переиспользованное
        // из пула «соединение» здесь только запутает.
        .pool_max_idle_per_host(0)
        .build()
        .ok()?;

    let started = Instant::now();

    while Instant::now() < deadline {
        // Ответ читаем целиком: успехом считается доведённый до конца запрос, а
        // не заголовки. Соединение, которое рвётся на теле ответа, — это ровно
        // тот случай, ради которого проверка и заведена.
        let answered = match client.get(sont_xray::config::HEALTH_CHECK_URL).send().await {
            Ok(r) if r.status().is_success() => r.text().await.is_ok_and(|b| !b.is_empty()),
            _ => false,
        };

        if answered {
            return Some(Winner {
                server: server.clone(),
                elapsed_ms: started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
            });
        }

        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::{Endpoint, Secret, Security, Stream, SubscriptionId, Transport};

    fn profile(name: &str) -> ServerProfile {
        ServerProfile::new(
            name,
            Endpoint::new("203.0.113.7", 443),
            Transport::Vless(sont_core::transport::Vless {
                uuid: Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: None,
                stream: Stream::Tcp,
                security: Security::None,
            }),
            SubscriptionId::from_url("https://panel.example/sub"),
        )
    }

    #[tokio::test]
    async fn a_single_candidate_is_not_worth_a_race() {
        // Запуск ядра ради вопроса «идти ли туда, куда всё равно больше некуда»
        // — это чистая задержка перед подключением.
        let launcher = CoreLauncher::new("не-существует");
        let dir = tempfile::tempdir().unwrap();

        let outcome = fastest_working(
            &launcher,
            &[profile("единственный")],
            &dir.path().join("race.json"),
            "warning",
        )
        .await;

        assert!(outcome.is_none());
    }

    #[tokio::test]
    async fn a_missing_core_does_not_take_the_decision_away() {
        // Ядро не запустилось — про серверы это не говорит ничего. Ответить
        // «никто не годится» значило бы подменить причину отказа.
        let launcher = CoreLauncher::new("не-существует");
        let dir = tempfile::tempdir().unwrap();

        let outcome = fastest_working(
            &launcher,
            &[profile("первый"), profile("второй")],
            &dir.path().join("race.json"),
            "warning",
        )
        .await;

        assert!(outcome.is_none());
    }

    #[tokio::test]
    async fn a_lane_that_never_answers_gives_up_at_the_deadline() {
        // Порт 9 никто не слушает: так выглядит дорожка, чьё ядро не поднялось.
        let id = ProfileId::from_raw("молчун");
        let deadline = Instant::now() + Duration::from_millis(300);

        let outcome = run_lane(&id, 9, deadline).await;

        assert!(outcome.is_none());
        assert!(
            Instant::now() >= deadline,
            "дорожка обязана идти до срока, а не сдаваться на первой неудаче"
        );
    }
}

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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sont_core::{ProfileId, ServerProfile};
use tokio_util::sync::CancellationToken;

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
/// Двенадцать секунд — одна полная попытка на дорожку и запас на повтор.
/// Победитель от срока не зависит: гонка кончается на первом ответе. Срок
/// решает другое — когда объявить, что не ответил никто. Объявить это раньше,
/// чем успевает прийти ответ медленного, но живого пути, значит соврать, и
/// именно так гонка говорила «у машины нет пути наружу» при исправных серверах.
const RACE_TIMEOUT: Duration = Duration::from_secs(12);

/// Жёсткий предел всей гонки, включая запуск и остановку ядра.
///
/// С запасом над рабочим сроком: в него обязаны уложиться и запуск ядра, и
/// дорожки, и остановка. Это предохранитель, а не расписание, — он не должен
/// срабатывать вместо внутренних сроков, иначе подменит их причину.
pub(crate) const RACE_HARD_LIMIT: Duration = Duration::from_secs(18);

/// Предел одной попытки на дорожке.
///
/// Десять секунд. Попытка дорожки — это холодное соединение через всю цепочку,
/// а замер через рабочий туннель дал такие от 0,6 до 6,3 с. Здесь стояло
/// сначала две с половиной, потом шесть — и оба раза лучший сервер в медленную
/// минуту не мог победить: каждая попытка начинала рукопожатие заново и снова
/// обрывалась за миг до ответа.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Пауза между попытками на одной дорожке.
///
/// Ядро поднимает входы не мгновенно, и первые попытки упираются в закрытый
/// порт. Частый опрос localhost ничего не стоит, а выигрыш прямой: гонка
/// заканчивается ровно тогда, когда ответил первый сервер.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Чем кончилась гонка.
///
/// Три исхода, а не два, и различать их обязательно. «Не отозвался никто» и
/// «гонка не состоялась» ведут к прямо противоположным выводам: в первом
/// случае про серверы известно всё — восемь штук одновременно не отказывают,
/// значит дело в машине; во втором не известно ничего.
pub enum Outcome {
    /// Кто-то провёл запрос до конца — вот он.
    Winner(Winner),

    /// Гонка состоялась, и не отозвался никто.
    ///
    /// Так выглядит машина без пути наружу: маршрут по умолчанию ведёт в
    /// погашенный туннель, не поднялся адаптер, пропал Wi-Fi. Винить в этом
    /// серверы нельзя — на любом другом повторится то же самое.
    NobodyAnswered {
        /// Серверы отвечали — но не нам, а сайтом, за который себя выдают.
        ///
        /// Это совсем другой отказ, чем молчание. Reality узнаёт своего
        /// клиента по ключу, и чужого — например, с устаревшим ключом —
        /// честно отдаёт настоящему сайту маскировки. Ядро видит его подлинный
        /// сертификат и отказывается идти дальше. Сеть при этом в полном
        /// порядке, а лечится всё обновлением подписки: провайдер сменил
        /// ключи, а у нас остались прежние.
        rejected: bool,
    },

    /// Гонки не было: проверять было нечего или ядро для неё не запустилось.
    ///
    /// Про серверы это не говорит ничего, и трактовать это как отказ — значит
    /// выдумывать.
    NotRun,
}

/// Отверг ли сервер наш ключ Reality — по выводу ядра.
///
/// Xray пишет об этом прямо: получил настоящий сертификат вместо ответа
/// своего сервера. Иначе этот отказ от молчания не отличить — снаружи оба
/// выглядят как «запрос не прошёл», а лечатся противоположно: молчание —
/// ожиданием сети, отказ — обновлением ключей.
pub fn reality_rejected(core_output: &str) -> bool {
    core_output.contains("received real certificate")
}

/// Отдельный файл конфигурации на каждую гонку.
///
/// Общий файл делили две гонки подряд: вытесненная доигрывала свою и в конце
/// удаляла файл — а новая в эту секунду как раз из него читала. В журнале это
/// «xray-config.race.json: The system cannot find the file specified», и
/// гонка объявлялась несостоявшейся, не успев начаться.
fn unique_config(base: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("race");
    base.with_file_name(format!("{stem}-{n}.json"))
}

/// Победитель гонки.
pub struct Winner {
    pub server: ProfileId,
    /// Сколько заняло прохождение запроса, мс. Не задержка до сервера, а время
    /// до ответа настоящего сайта через туннель.
    pub elapsed_ms: u32,
}

/// Находит среди кандидатов сервер, который действительно проводит трафик.
pub async fn fastest_working(
    launcher: &CoreLauncher,
    candidates: &[ServerProfile],
    config_base: &Path,
    log_level: &str,
    cancel: &CancellationToken,
) -> Outcome {
    if candidates.len() < 2 {
        // Выбирать не из чего: гонка из одного участника стоит запуска ядра и
        // не отвечает ни на один вопрос, которого не задаст само подключение.
        return Outcome::NotRun;
    }

    let config_path = unique_config(config_base);
    let config_path = config_path.as_path();

    let lanes: Vec<(&ServerProfile, u16)> = candidates
        .iter()
        .take(LANES)
        .map(|server| (server, crate::supervisor::pick_free_port()))
        .collect();

    let config = match sont_xray::build_race(&lanes, log_level) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!(error = %e, "не удалось собрать конфигурацию проверки");
            return Outcome::NotRun;
        }
    };

    if let Err(e) = crate::supervisor::write_core_config(config_path, &config) {
        tracing::warn!(error = %e, "не удалось записать конфигурацию проверки");
        return Outcome::NotRun;
    }

    let mut core = match launcher.spawn(config_path).await {
        Ok(core) => core,
        Err(e) => {
            tracing::warn!(error = %e, "не удалось запустить проверку серверов");
            return Outcome::NotRun;
        }
    };

    let started = Instant::now();

    // Смерть ядра проверки — не «никто не отозвался», а «спросить не вышло».
    //
    // Разница та же, что между молчанием и отсутствием вопроса: во втором
    // случае про серверы по-прежнему не известно ничего, и объявлять сеть
    // недоступной по этому поводу нельзя.
    let mut asked = true;
    let mut reasons: Vec<String> = Vec::new();
    let racing = async {
        tokio::select! {
            result = first_to_answer(&lanes) => match result {
                Ok(winner) => Some(winner),
                Err(failures) => {
                    reasons = failures;
                    None
                }
            },
            _ = core.wait_exit() => {
                tracing::warn!(output = %core.recent_output(), "ядро проверки завершилось");
                asked = false;
                None
            }
        }
    };

    // Жёсткий предел поверх всех внутренних сроков.
    //
    // Внутри каждая дорожка укладывается в срок сама, но гонка — единственный
    // этап подключения, не накрытый общим предохранителем: `CONNECT_TIMEOUT`
    // начинается после неё. Зависни здесь что-нибудь стороннее — и демон
    // остался бы в «восстанавливаю» без единого способа это прервать.
    // Вытесненная гонка уступает сразу, а не доигрывает рядом с новой: две
    // гонки разом — это два ядра, делящие случайные порты, и в журнале ровно
    // такое «127.0.0.1:35509: Only one usage of each socket address».
    let raced = tokio::select! {
        raced = tokio::time::timeout(RACE_HARD_LIMIT, racing) => Some(raced),
        _ = cancel.cancelled() => None,
    };
    let cancelled = raced.is_none();
    let winner = match raced {
        Some(Ok(winner)) => winner,
        Some(Err(_)) => {
            tracing::warn!(
                seconds = RACE_HARD_LIMIT.as_secs(),
                "проверка серверов не уложилась в срок"
            );
            None
        }
        None => None,
    };

    // Отказ Reality читается по выводу ядра, пока ядро живо: после остановки
    // смотреть будет не у кого.
    let rejected = winner.is_none() && reality_rejected(&core.recent_output());

    core.shutdown().await;

    // Файл содержит учётные данные всех проверенных серверов и больше не нужен.
    // Лишняя копия ключей на диске — это лишняя копия ключей на диске, даже в
    // каталоге демона.
    let _ = std::fs::remove_file(config_path);

    // Отменённая гонка молчит: её попытку уже сменила другая, и вывод этой
    // никому не нужен — хуже того, «никто не ответил» от прерванной гонки был
    // бы неправдой.
    if cancelled {
        return Outcome::NotRun;
    }

    match winner {
        Some(winner) => {
            tracing::info!(
                server = %winner.server,
                elapsed_ms = winner.elapsed_ms,
                checked = lanes.len(),
                spent_ms = started.elapsed().as_millis(),
                "проверка серверов: подключаюсь к тому, который отозвался первым"
            );
            Outcome::Winner(winner)
        }
        None if asked => {
            if rejected {
                tracing::warn!(
                    checked = lanes.len(),
                    spent_ms = started.elapsed().as_millis(),
                    "серверы отвечают, но не узнают ключ Reality — похоже, подписка устарела"
                );
            } else {
                tracing::warn!(
                    checked = lanes.len(),
                    spent_ms = started.elapsed().as_millis(),
                    "не отозвался ни один сервер — похоже, у машины нет пути наружу"
                );
            }
            // Причины — отдельными строками, по одной на дорожку. Вывод
            // «никто не ответил» без них не проверить: ровно такие выводы
            // прежде и складывались в круги подключения, которые нечем было
            // объяснить.
            for reason in &reasons {
                tracing::warn!(%reason, "дорожка гонки не дождалась ответа");
            }
            Outcome::NobodyAnswered { rejected }
        }
        None => Outcome::NotRun,
    }
}

/// Ждёт первую дорожку, которая доведёт запрос до конца.
///
/// Не дождавшись никого, отдаёт причины, по которым отказали дорожки: без них
/// «никто не ответил» — это вывод без доказательств, а именно из таких
/// выводов и складывались круги подключения, которые нечем было объяснить.
async fn first_to_answer(lanes: &[(&ServerProfile, u16)]) -> Result<Winner, Vec<String>> {
    use futures_util::stream::{FuturesUnordered, StreamExt};

    let deadline = Instant::now() + RACE_TIMEOUT;
    let mut running: FuturesUnordered<_> = lanes
        .iter()
        .map(|(server, port)| run_lane(&server.id, *port, deadline))
        .collect();

    // Именно первый удачный, а не первый завершившийся: дорожка, упавшая через
    // сто миллисекунд, не должна отменять гонку для тех, кто ещё идёт.
    let mut failures = Vec::with_capacity(lanes.len());
    while let Some(result) = running.next().await {
        match result {
            Ok(winner) => return Ok(winner),
            Err(reason) => failures.push(reason),
        }
    }
    Err(failures)
}

/// Одна дорожка: повторяет запрос через свой локальный вход до победы или срока.
///
/// Не дождавшись ответа, отдаёт причину последней неудачи — см.
/// [`first_to_answer`].
async fn run_lane(server: &ProfileId, port: u16, deadline: Instant) -> Result<Winner, String> {
    let proxy = reqwest::Proxy::all(format!("socks5://127.0.0.1:{port}"))
        .map_err(|e| format!("{server}: прокси дорожки не настроился: {e}"))?;
    let client = reqwest::Client::builder()
        .timeout(ATTEMPT_TIMEOUT)
        .proxy(proxy)
        // Каждая попытка обязана открывать новое соединение: пока ядро не
        // подняло вход, попытка упирается в закрытый порт, и переиспользованное
        // из пула «соединение» здесь только запутает.
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| format!("{server}: клиент дорожки не собрался: {e}"))?;

    let started = Instant::now();
    let mut last = String::from("ни одной попытки");

    loop {
        // Попытка не имеет права пережить общий срок.
        //
        // Раньше цикл проверял срок только перед началом попытки, а сама она
        // жила своим таймаутом. Начатая за миг до срока, она растягивала гонку
        // сверх обещанного. Здесь остаток срока и есть предел попытки, и гонка
        // кончается тогда, когда обещала.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("{server}: {last}"));
        }

        // Ответ читаем целиком: успехом считается доведённый до конца запрос, а
        // не заголовки. Соединение, которое рвётся на теле ответа, — это ровно
        // тот случай, ради которого проверка и заведена.
        let attempt = async {
            let response = client
                .get(sont_xray::config::HEALTH_CHECK_URL)
                .send()
                .await
                .map_err(crate::supervisor::describe)?;
            if !response.status().is_success() {
                return Err(format!("код ответа {}", response.status().as_u16()));
            }
            let body = response.text().await.map_err(crate::supervisor::describe)?;
            if body.is_empty() {
                return Err("пустой ответ".to_owned());
            }
            Ok(())
        };

        let limit = left.min(ATTEMPT_TIMEOUT);
        match tokio::time::timeout(limit, attempt).await {
            Ok(Ok(())) => {
                return Ok(Winner {
                    server: server.clone(),
                    elapsed_ms: started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
                });
            }
            Ok(Err(reason)) => last = reason,
            Err(_) => last = format!("нет ответа за {:.1} с", limit.as_secs_f32()),
        }

        // Пауза тоже не должна выводить за срок.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("{server}: {last}"));
        }
        tokio::time::sleep(RETRY_INTERVAL.min(left)).await;
    }
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

    #[test]
    fn a_rejected_reality_key_is_told_apart_from_silence() {
        // Ровно та строка, что стояла в журнале, пока Sont не подключался ни к
        // чему: сервер отдал нас сайту маскировки, а не принял. Лечится это
        // обновлением ключей, а не ожиданием сети.
        let rejected = "2026/09/13 11:32:41.533613 [Error] [1446194704] \
                        transport/internet/reality: REALITY: received real \
                        certificate (potential MITM or redirection)";
        assert!(reality_rejected(rejected));

        // Молчание и прочие отказы — не про ключ.
        assert!(!reality_rejected("dial tcp 155.117.137.56:443: i/o timeout"));
        assert!(!reality_rejected(""));
    }

    #[test]
    fn every_race_writes_its_own_config() {
        // Общий файл удаляла вытесненная гонка — ровно тогда, когда новая из
        // него читала. В журнале: «The system cannot find the file specified».
        let base = std::path::Path::new(r"C:\ProgramData\Sont\xray-config.race.json");
        let first = unique_config(base);
        let second = unique_config(base);

        assert_ne!(first, second);
        assert_eq!(first.parent(), base.parent(), "файл обязан лежать в каталоге демона");
        assert_eq!(first.extension().and_then(|e| e.to_str()), Some("json"));
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
            &CancellationToken::new(),
        )
        .await;

        assert!(matches!(outcome, Outcome::NotRun));
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
            &CancellationToken::new(),
        )
        .await;

        // Именно `NotRun`, а не «никто не отозвался»: спросить не вышло, и
        // выдавать это за отказ серверов нельзя — по такому выводу демон решил
        // бы, что у машины нет сети.
        assert!(matches!(outcome, Outcome::NotRun));
    }

    #[tokio::test]
    async fn a_lane_that_never_answers_gives_up_at_the_deadline() {
        // Порт 9 никто не слушает: так выглядит дорожка, чьё ядро не поднялось.
        let id = ProfileId::from_raw("молчун");
        let deadline = Instant::now() + Duration::from_millis(300);

        let outcome = run_lane(&id, 9, deadline).await;

        assert!(
            Instant::now() >= deadline,
            "дорожка обязана идти до срока, а не сдаваться на первой неудаче"
        );

        // И отказ обязан назвать и дорожку, и причину — иначе вывод «никто не
        // ответил» не проверить.
        let reason = outcome.err().expect("молчащая дорожка не может победить");
        assert!(reason.starts_with("молчун: "), "причина без имени дорожки: {reason}");
        assert!(reason.len() > "молчун: ".len(), "имя дорожки без причины");
    }

    #[test]
    fn a_slow_but_living_server_can_still_win() {
        // Самый долгий запрос через цепочку серверов в журнале пользователя —
        // 4,7 с, и это у лучшего из восьми. Попытка на две с половиной секунды
        // обрывала такой путь каждый раз заново: сервер был жив, а победить не
        // мог никогда, и гонка объявляла, что у машины нет пути наружу.
        let slowest_seen = Duration::from_millis(4_700);
        assert!(ATTEMPT_TIMEOUT > slowest_seen);
        assert!(RACE_TIMEOUT > ATTEMPT_TIMEOUT, "гонка обязана вмещать хотя бы одну полную попытку");
        assert!(RACE_HARD_LIMIT > RACE_TIMEOUT, "предохранитель не должен срабатывать вместо срока");
    }
}

//! Конечный автомат соединения — единственный владелец состояния демона.
//!
//! Всё, что меняет состояние, проходит через `run`: команды по IPC и
//! внутренние сообщения от фоновых задач. Никаких `Arc<Mutex<GlobalState>>` —
//! состояние живёт в одной задаче, и «кто его сейчас меняет» не бывает
//! вопросом.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sont_core::{
    DisconnectReason, ProbeResult, ProfileId, ReconnectCause, Secret, ServerProfile, Settings,
    SettingsPatch, Stats, SubscriptionId, SubscriptionInfo, TunInfo, TunnelError, TunnelState,
};
use sont_ipc::protocol::{
    DaemonInfo, Event, IpcError, Request, Response, ServerView, StatusSnapshot, SubscriptionStatus,
};
use sont_ipc::server::Command;
use tokio::sync::{broadcast, mpsc};

use crate::core::{CoreLauncher, CoreProcess};
use crate::logging::LogBuffer;
use crate::subscription::{FetchError, Fetched, SubscriptionClient};
use crate::{demo, secrets, store};

/// Предельное время всей последовательности подключения.
///
/// Меньше, чем ждёт CLI: пользователь должен получить причину от демона, а не
/// собственный таймаут клиента, из которого ничего не понятно.
///
/// # Почему пятьдесят
///
/// Это предохранитель, а не рабочий срок: он обязан быть длиннее суммы этапов
/// ([`READY_TIMEOUT`] плюс [`ROUTING_TIMEOUT`] плюс запуск ядра), иначе
/// сработает раньше них и подменит точную причину отказа общим «не успело».
/// Этапы подняли до двадцати секунд каждый — по две полные попытки запроса
/// через медленную цепочку реле, — и предохранитель поднят вслед за ними.
///
/// Он был урезан до пятнадцати вместе со сроками этапов — и в журнале видно,
/// чем это кончилось. Первый этап прошёл, адаптер поднялся, до «Подключено»
/// оставалась одна проверка маршрутов — и предохранитель оборвал её на
/// середине, выбросив всю уже сделанную работу. Сумма этапов превышала его,
/// а тест, который должен был это ловить, не учитывал запуск ядра.
///
/// Дожидаться этого срока пользователю почти не приходится: сервер, до
/// которого нет пути, отсеивается проверкой перед запуском ядра (см.
/// [`choose_working`]), а живой отвечает за секунду-другую.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(50);

/// Сколько отводим запуску ядра и фоновым разрешениям до первого этапа.
///
/// Нужна только для того, чтобы сумма сроков, из которых складывается
/// [`CONNECT_TIMEOUT`], была честной: запуск процесса ядра и чтение им
/// конфигурации — тоже время, и без него предохранитель срабатывал раньше
/// этапов, которые обязан был лишь подстраховывать.
const CORE_STARTUP_ALLOWANCE: Duration = Duration::from_secs(3);

// Предохранитель обязан пережить этапы, которые подстраховывает.
//
// Проверяется при сборке, а не только тестом. Тест здесь уже был — и не
// учитывал запуск ядра, поэтому пропустил ровно ту поломку, ради которой
// заведён: урезанный предохранитель срабатывал раньше этапов и обрывал
// подключение за шаг до «Подключено». Поменять один срок, забыв про
// остальные, теперь нельзя: сборка не пройдёт.
const _: () = assert!(
    CONNECT_TIMEOUT.as_millis()
        > READY_TIMEOUT.as_millis()
            + SETTLE_GRACE.as_millis()
            + ROUTING_TIMEOUT.as_millis()
            + CORE_STARTUP_ALLOWANCE.as_millis(),
    "CONNECT_TIMEOUT короче суммы этапов подключения"
);

/// Период публикации статистики и проверки живости ядра.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// Как часто проверяем, что туннель ещё проводит трафик.
///
/// Ядро может остаться живым процессом, а соединение с сервером при этом
/// оборваться — упавший процесс мы замечаем сразу, а вот молчащий туннель
/// виден только по проверке.
///
/// Пятнадцать секунд, а не тридцать: обрыв подтверждается только второй
/// неудачной проверкой подряд, то есть с прежним интервалом пользователь сидел
/// без сети до минуты, ничего об этом не зная. Один запрос через уже поднятый
/// локальный SOCKS раз в четверть минуты не стоит ничего.
const HEALTH_INTERVAL: Duration = Duration::from_secs(15);

/// Сколько неудачных проверок подряд считаем обрывом.
///
/// Одна неудача — это чаще всего мигнувший Wi-Fi, и переподключаться из-за
/// неё значит рвать рабочее соединение на ровном месте.
const HEALTH_FAILURES_BEFORE_RECONNECT: u32 = 2;

/// Сколько даётся одной проверке живости.
///
/// Двадцать секунд — две полные попытки запроса. Проверка ходит холодным
/// соединением через всю цепочку, и одно такое у пользователя однажды
/// провисело пятнадцать секунд, при исправном туннеле. Одна попытка на
/// проверку означала бы, что одна такая заминка — уже половина пути к обрыву.
const HEALTH_PROBE_BUDGET: Duration = Duration::from_secs(20);

/// Как часто демон возвращается к соединению, которого добивается, но не имеет.
///
/// Пять секунд: достаточно редко, чтобы не долбиться в заведомо
/// неподнимающийся туннель, и достаточно часто, чтобы пользователь, добавивший
/// ключ или починивший сеть, не успел заметить паузу. Прежние пятнадцать были
/// расчётом на то, что каждая попытка стоит полминуты; с проверкой кандидатов
/// перед запуском неудачная попытка стала дешёвой, и ждать столько незачем.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// Потолок паузы между попытками переподключения.
///
/// Пятнадцать секунд. Пауза приходится на состояние «восстанавливаю», а
/// примиритель в него не вмешивается — считает, что попытка уже идёт. Значит,
/// потолок это и есть время, которое пользователь просидит без сети после того,
/// как сеть у него уже появилась.
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(15);

/// Как часто перемеряем задержку до серверов в фоне.
///
/// Замер нужен не сам по себе, а чтобы было на чём основать выбор сервера в
/// момент падения текущего. Мерить тогда уже поздно: пользователь сидит без
/// сети и ждёт. Поэтому меряем заранее и регулярно — TCP-соединение к каждому
/// серверу раз в несколько минут не стоит ничего.
const PROBE_INTERVAL: Duration = Duration::from_secs(300);

/// Как часто повторяем замер сервера текущего соединения, пока задержка до
/// него не известна.
///
/// Пять секунд. Это один сервер и одно TCP-соединение — повторять его часто
/// ничего не стоит, а тире в шапке при исправном соединении видно сразу. Как
/// только замер удался, повторы прекращаются сами: дальше сервер меряется
/// общим кругом.
const CURRENT_PROBE_RETRY: Duration = Duration::from_secs(5);

/// Как часто можно обновлять подписки внепланово — после гонки, в которой не
/// отозвался ни один сервер.
///
/// Две минуты. Первое такое обновление уходит сразу, и если дело было в
/// устаревших ключах, оно всё и исправит. Если же у машины просто нет сети,
/// гонка будет молчать раз за разом, и без предела каждый круг оборачивался бы
/// ещё и запросом к панели.
const SILENCE_REFRESH_MIN: Duration = Duration::from_secs(120);

/// Сколько упавший сервер не рассматривается при выборе замены.
///
/// Без этого срока переключение вырождается в возврат: сервер лёг, мы ушли на
/// второй, второй оказался медленнее — и «лучший по пингу» снова показывает на
/// первый, который всё ещё лежит. Замер этого не покажет: TCP-соединение к
/// упавшему VLESS-серверу устанавливается прекрасно, отказывает уже туннель.
const FAILED_SERVER_COOLDOWN: Duration = Duration::from_secs(600);

/// С чего начинается удвоение пауз.
///
/// Четверть секунды, а не целая. Первая пауза — это то, что видит человек,
/// глядя на «восстанавливаю»: короткий обрыв должен закрыться незаметно, а
/// секунда простоя уже читается как «зависло». Удвоение всё равно быстро
/// уводит паузу вверх, если недоступность оказалась настоящей.
const RECONNECT_BASE_DELAY: Duration = Duration::from_millis(250);

/// Сколько ждём, пока машина прибёрет за неудачной попыткой.
///
/// Секунда. Столько уходит у Windows на снятие TUN-адаптера и возврат маршрута
/// по умолчанию на физический интерфейс. Ждать меньше — начать следующую
/// попытку в тот момент, когда весь исходящий трафик ещё уходит в погашенный
/// туннель; ждать больше незачем.
///
/// Это не наказание за отказ, а признание того, что снятие сетевого слоя не
/// мгновенно. Поэтому и применяется только там, где слой действительно
/// снимали, — см. [`Supervisor::begin_reconnect`].
const SETTLE_AFTER_TEARDOWN: Duration = Duration::from_secs(1);

/// После какого молчания попытка считается потерянной.
///
/// Две минуты — заведомо больше самой длинной законной попытки: пауза перед
/// ней, гонка со своим жёстким пределом и полная последовательность
/// подключения под [`CONNECT_TIMEOUT`]. Запас здесь важнее точности: сторож,
/// срабатывающий на живой работе, рвёт подключение вместо того, чтобы его
/// спасать.
///
/// Здесь стояла минута — пока сроки этапов были короче. Их подняли под
/// медленную цепочку реле, и сумма перевалила за неё: сторож начал бы обрывать
/// попытку, которая вот-вот должна была закончиться. Теперь соотношение
/// проверяется при сборке.
const STALLED_ATTEMPT: Duration = Duration::from_secs(120);

// Сторож обязан пережить самую длинную законную попытку.
const _: () = assert!(
    STALLED_ATTEMPT.as_millis()
        > RECONNECT_MAX_DELAY.as_millis()
            + SETTLE_AFTER_TEARDOWN.as_millis()
            + crate::race::RACE_HARD_LIMIT.as_millis()
            + CONNECT_TIMEOUT.as_millis(),
    "STALLED_ATTEMPT короче самой длинной законной попытки"
);

/// Пауза перед попыткой номер `attempt`.
///
/// # Почему первая попытка идёт без паузы
///
/// Восстановление обязано начинаться так же быстро, как подключение по кнопке.
/// Пользователю разницы между ними нет: и там, и там он смотрит на окно и ждёт
/// сети. Пауза перед первой же попыткой делала восстановление заведомо
/// медленнее — на ровном месте, потому что обрыв и повтор разделяет ещё и
/// проверка кандидатов, которая сама по себе занимает время.
///
/// Дальше — удвоение с потолком: если не вышло и со второго раза, дело не в
/// случайности, и непрерывный поток запросов к серверу её не исправит.
fn reconnect_delay(attempt: u32) -> Duration {
    if attempt <= 1 {
        return Duration::ZERO;
    }
    let factor = 1u32.checked_shl(attempt - 2).unwrap_or(u32::MAX);
    RECONNECT_BASE_DELAY
        .saturating_mul(factor)
        .min(RECONNECT_MAX_DELAY)
}

/// Пауза перед конкретной попыткой восстановления.
///
/// Решает не то, сменился ли адрес, а то, кто отказал.
///
/// Виноват сервер — паузы нет: мы уходим с него на другой, и тот ни в чём не
/// провинился. Ждать перед ним значит держать пользователя без сети ровно
/// столько, сколько накопил счётчик неудач предыдущего.
///
/// Виновата машина — пауза есть, и не зависит от того, на какой сервер мы
/// нацелились. Прежде условие смотрело на смену адреса, и из этого выходила
/// поломка: перебирая серверы на отказе машины, демон каждый раз получал
/// «адрес сменился», обнулял паузу и крутил гонку каждые семь секунд, пока не
/// вернётся сеть.
///
/// Нижняя граница паузы — время, за которое Windows снимает TUN-адаптер и
/// возвращает маршрут по умолчанию. Не выждав его, следующая гонка уходит
/// трафиком в погашенный туннель и впустую тратит свои пять секунд.
fn reconnect_delay_for(attempt: u32, server_at_fault: bool) -> Duration {
    if server_at_fault {
        Duration::ZERO
    } else {
        reconnect_delay(attempt).max(SETTLE_AFTER_TEARDOWN)
    }
}

/// Вправе ли гонка поправить выбор сервера перед запуском.
///
/// Разница не в том, хочется ли проверить сервер, а в том, есть ли у демона
/// право его сменить. Смена настроек и переход на найденный более быстрый
/// сервер — это решения, уже принятые по своим основаниям: гонка там не
/// проверяла бы выбор, а отменяла бы его, попутно возвращая пользователя на тот
/// самый сервер, с которого его только что решили увести.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selection {
    /// Сервер назван ранжированием — гонка вправе назвать другой.
    Race,
    /// Сервер выбран по отдельному основанию и подмене не подлежит.
    Fixed,
}

/// Чего добивается демон, независимо от того, что происходит сейчас.
///
/// Без этого разделения оркестратор не может отличить обрыв от намеренного
/// отключения: и там, и там состояние становится «не подключено», но в первом
/// случае надо восстанавливать соединение, а во втором — ни в коем случае.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Desired {
    /// Соединение нужно. `server` задан, если пользователь выбрал конкретный.
    Connected { server: Option<ProfileId> },
    /// Соединения быть не должно.
    Disconnected,
}

pub struct SupervisorConfig {
    /// Наполнить список серверов демонстрационным набором.
    pub demo_servers: bool,
    pub settings_path: PathBuf,
    pub favorites_path: PathBuf,
    /// Все подписки одним зашифрованным файлом.
    pub subscriptions_path: PathBuf,
    /// Файлы прежней, одноподписочной раскладки.
    ///
    /// Читаются при первом запуске новой версии и после переноса удаляются.
    pub legacy_subscription_path: PathBuf,
    pub legacy_servers_cache_path: PathBuf,
    /// Путь к бинарю ядра Xray.
    pub core_binary: PathBuf,
    /// Куда пишется сгенерированная конфигурация ядра.
    pub core_config_path: PathBuf,
}

/// Сообщения от фоновых задач самому supervisor.
///
/// Без `Debug`: внутри переносится дескриптор процесса ядра, который печатать
/// незачем.
pub enum Internal {
    /// Гонка не нашла ни одного отзывающегося сервера.
    ///
    /// Приходит раньше отказа самой попытки: это повод обновить подписку, и
    /// чем раньше демон о нём узнает, тем раньше придут свежие ключи.
    ServersSilent {
        /// Серверы не молчали, а отвергали ключ Reality.
        rejected: bool,
    },
    /// Проверка перед запуском увела попытку на другой сервер.
    ///
    /// Отдельным сообщением, а не полем в `CoreStarted`: состояние обязано
    /// показать новый сервер сразу, а не через весь срок подключения к нему.
    ServerChosen { generation: u64, server: ProfileId },
    /// Ядро и сетевой слой подняты, связность подтверждена.
    CoreStarted {
        generation: u64,
        /// Ручалась ли за сервер гонка перед запуском.
        ///
        /// Нужно для разбора неудачи. Сервер, через который секунду назад
        /// прошёл настоящий запрос, не может быть виноват в том, что туннель
        /// не поднялся, — виновата машина, и записывать его в отказавшие
        /// значит выбрасывать заведомо рабочий сервер на десять минут.
        vouched: bool,
        /// В коробке: `Started` несёт дескриптор процесса ядра и задачу
        /// сетевого слоя и весит сотни байт. Без неё этот вес лежал бы в
        /// каждом сообщении канала, включая односложные.
        result: Box<Result<Started, TunnelError>>,
    },
    DisconnectFinished {
        generation: u64,
    },
    SubscriptionFetched {
        id: SubscriptionId,
        result: Result<Fetched, FetchError>,
    },
    /// Версия ядра, полученная при старте.
    CoreVersion(Option<String>),
    /// Показания счётчиков ядра.
    CoreStats(sont_xray::metrics::Counters),
    /// Результат проверки живости туннеля.
    HealthChecked {
        generation: u64,
        alive: bool,
        /// Сколько байт ядро получило от сервера к концу проверки — всего за
        /// сеанс. `None` — счётчики прочитать не вышло.
        downlink: Option<u64>,
    },
    /// Результаты замера задержки до серверов.
    Probed(Vec<ProbeResult>),
}

/// Одна подписка со всем, что о ней известно.
///
/// Разобранные серверы лежат здесь же, а не отдельным кэшем: без них после
/// каждого перезапуска демона пришлось бы ждать ответа панели, а если панель
/// недоступна — оставаться без серверов, хотя ключ никуда не делся.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SubscriptionEntry {
    id: SubscriptionId,
    /// Ключ подписки. Наружу не отдаётся никогда — ни в ответах, ни в событиях.
    secret: Secret,
    masked_url: String,
    profiles: Vec<ServerProfile>,
    info: SubscriptionInfo,
}

impl SubscriptionEntry {
    fn status(&self) -> SubscriptionStatus {
        SubscriptionStatus {
            id: self.id.clone(),
            masked_url: self.masked_url.clone(),
            info: self.info.clone(),
        }
    }
}

/// Кэш разобранной подписки в раскладке до появления списка.
///
/// Нужен ровно для одного: прочитать то, что осталось от прежней версии, и
/// перенести. Пользователь не должен вводить ключ заново из-за того, что у нас
/// поменялась структура файлов.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LegacyCachedSubscription {
    id: SubscriptionId,
    masked_url: String,
    profiles: Vec<ServerProfile>,
    info: SubscriptionInfo,
}

pub struct Supervisor {
    state: TunnelState,
    settings: Settings,
    servers: Vec<ServerProfile>,
    probes: HashMap<ProfileId, ProbeResult>,
    favorites: HashSet<ProfileId>,
    stats: Stats,
    /// Подписки пользователя вместе с ключами и разобранными серверами.
    ///
    /// Порядок задаёт пользователь порядком добавления, и он же разрешает
    /// столкновения: один и тот же сервер, пришедший из двух подписок, берётся
    /// из первой. Иначе в списке была бы пара близнецов с одним id, и
    /// избранное с закреплением перестали бы означать что-то определённое.
    subscriptions: Vec<SubscriptionEntry>,

    events: broadcast::Sender<Event>,
    internal_tx: mpsc::Sender<Internal>,
    internal_rx: mpsc::Receiver<Internal>,
    logs: LogBuffer,
    config: SupervisorConfig,
    started_at: Instant,

    /// Запущенные ядро и сетевой слой, если соединение поднято.
    active: Option<Started>,
    launcher: Arc<CoreLauncher>,
    core_version: Option<String>,
    /// Адрес служебного порта запущенного ядра.
    metrics_url: Option<String>,
    /// Адреса локальных прокси, пока соединение поднято.
    proxy: Option<sont_ipc::ProxyEndpoints>,
    /// Предыдущие показания счётчиков и момент их снятия — для вычисления
    /// скорости. Ядро отдаёт накопительные значения, а не мгновенные.
    last_counters: Option<(sont_xray::metrics::Counters, Instant)>,

    http: Option<Arc<SubscriptionClient>>,
    /// Идёт ли обновление подписки прямо сейчас.
    ///
    /// Защита от накопления параллельных запросов, если пользователь нажимает
    /// «Обновить» несколько раз подряд.
    fetching: HashSet<SubscriptionId>,
    /// Когда демон в последний раз сам обновлял подписки.
    ///
    /// От неё отсчитывается и плановое обновление, и внеплановое — после
    /// гонки, в которой не отозвался никто. См. [`Supervisor::tick_subscriptions`].
    last_subscription_fetch: Instant,

    /// Адрес, объявленный машинной настройке WinHTTP, если он объявлен.
    ///
    /// Держим отдельно от `proxy`, потому что это не то же самое: `proxy` —
    /// что подняло ядро, а здесь — что мы успели сообщить системе. Сравнение
    /// двух значений и не даёт дёргать настройку на каждой смене состояния.
    machine_proxy: Option<String>,

    /// Серверы, на которых соединение недавно развалилось, и когда это было.
    ///
    /// Замер задержки такие серверы не отличает: до упавшего VLESS TCP доходит
    /// прекрасно, не работает уже туннель поверх него. Без этой памяти выбор
    /// «лучшего по пингу» немедленно вернул бы нас на тот же сервер.
    failed_servers: HashMap<ProfileId, Instant>,

    /// Идёт ли замер задержки прямо сейчас.
    probing: bool,
    /// Когда замер выполнялся в последний раз.
    ///
    /// Задержка — величина скоропортящаяся: маршрут меняется при переходе с
    /// Wi-Fi на кабель, а сервер, вчера бывший лучшим, сегодня может лежать.
    /// Выбирать по замеру недельной давности значит выбирать наугад.
    last_probe: Instant,
    /// Когда в последний раз отдельно мерили сервер текущего соединения.
    ///
    /// Свои часы, а не общие: этот замер повторяется часто, пока задержка до
    /// сервера не известна, и на общих часах он отодвигал бы очередной круг
    /// по всем серверам — см. [`Supervisor::tick_probe`].
    last_current_probe: Instant,

    /// Номер текущего «намерения» пользователя.
    ///
    /// Отложенные задачи (поднятие туннеля, его снятие) несут номер, под
    /// которым были запущены, и игнорируются, если он устарел. Без этого
    /// быстрая последовательность «подключить → отключить» приводит к тому,
    /// что запоздавшее «подключение готово» воскрешает уже отменённый сеанс.
    generation: u64,

    /// Причина отключения, запомненная на время перехода `Disconnecting`.
    ///
    /// Отдельным полем, а не внутри состояния: `Disconnecting` — это ровно то,
    /// что видит UI, и класть туда служебные подробности незачем.
    pending_reason: Option<DisconnectReason>,

    /// Чего добивается демон. Основа всей автономной работы.
    desired: Desired,
    /// Номер текущей попытки восстановления. Ноль — соединение стабильно.
    reconnect_attempt: u32,
    /// Сколько проверок живости подряд не прошли.
    health_failures: u32,
    /// Сколько байт ядро получило от сервера к прошлой проверке живости.
    ///
    /// Рост между проверками — то, чем туннель доказывает, что жив, даже когда
    /// проверочный запрос не уложился в срок. См. [`Supervisor::apply_health`].
    last_health_downlink: Option<u64>,
    /// Идёт ли проверка живости прямо сейчас.
    health_in_flight: bool,
    /// Когда в последний раз проверяли живость.
    last_health_check: Instant,

    /// Когда демон в последний раз пробовал поднять соединение.
    ///
    /// Нужно примирителю: без отметки он бился бы в неподнимающийся туннель
    /// каждую секунду.
    last_attempt: Instant,

    /// Отмена попытки подключения, которая идёт прямо сейчас.
    ///
    /// Новая попытка вытесняет прежнюю, но номер поколения отбрасывает лишь её
    /// результат — сама она продолжала работать: держала ядро, порт, а дойдя
    /// до второго этапа, ещё и TUN-адаптер с маршрутами. Две попытки с одними
    /// и теми же предпочитаемыми портами и двумя адаптерами разом — это и
    /// «порт занят» у новой, и маршрут по умолчанию, за который они спорят.
    in_flight: Option<tokio_util::sync::CancellationToken>,

    /// Поднятая блокировка трафика, если kill-switch включён.
    ///
    /// Наличие значения — единственный источник правды для поля `blocked` в
    /// состоянии. Выводить его из настройки нельзя: настройка говорит, чего
    /// хочет пользователь, а фильтры могли не поставиться — например, у
    /// демона не хватило прав.
    firewall: Option<crate::firewall::Firewall>,
}

impl Supervisor {
    pub fn new(config: SupervisorConfig, events: broadcast::Sender<Event>, logs: LogBuffer) -> Self {
        let settings: Settings = store::load_or_default(&config.settings_path);
        let favorites: HashSet<ProfileId> = store::load_or_default(&config.favorites_path);

        let (subscriptions, servers, probes) = if config.demo_servers {
            tracing::warn!("включён демонстрационный набор серверов — подключение не выполняется");
            let servers = demo::servers();
            let probes = servers
                .iter()
                .map(|s| {
                    (
                        s.id.clone(),
                        ProbeResult {
                            server: s.id.clone(),
                            rtt_ms: Some(demo::fake_rtt(&s.id)),
                            loss_percent: 0,
                            measured_at_unix_ms: now_unix_ms(),
                        },
                    )
                })
                .collect();
            (Vec::new(), servers, probes)
        } else {
            let subscriptions = load_subscriptions(&config);
            // Работаем на сохранённом разборе, пока не придёт свежий ответ
            // панели: иначе после перезапуска демона пользователь остаётся без
            // серверов, хотя ключи на месте.
            let servers = merge_servers(&subscriptions);
            if !subscriptions.is_empty() {
                tracing::info!(
                    subscriptions = subscriptions.len(),
                    servers = servers.len(),
                    "загружены сохранённые подписки"
                );
            }
            (subscriptions, servers, HashMap::new())
        };

        let http = match SubscriptionClient::new() {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                // Без HTTP-клиента демон всё ещё полезен: он умеет работать
                // на кэше. Но обновить подписку не сможет, и знать об этом
                // нужно сразу.
                tracing::error!(error = %e, "HTTP-клиент недоступен, обновление подписки отключено");
                None
            }
        };

        let launcher = Arc::new(CoreLauncher::new(config.core_binary.clone()));
        match launcher.verify() {
            Ok(()) => tracing::info!(binary = %config.core_binary.display(), "ядро найдено"),
            Err(e) => tracing::warn!(error = %e, "ядро недоступно, подключение работать не будет"),
        }

        // Постоянные фильтры от прошлого запуска.
        //
        // Пережить демона они могли только в режиме lockdown — там это по
        // договору. Но если пользователь с тех пор блокировку выключил,
        // снять их некому: новый демон о них ничего не знает и молча оставил
        // бы машину без сети до `sontd firewall reset`.
        if !settings.firewall.survives_daemon_crash() {
            if let Err(e) = crate::firewall::reset() {
                tracing::warn!(error = %e, "не удалось прибрать фильтры прошлого запуска");
            }
        }

        let (internal_tx, internal_rx) = mpsc::channel(16);

        Self {
            active: None,
            launcher,
            core_version: None,
            metrics_url: None,
            proxy: None,
            last_counters: None,
            state: TunnelState::default(),
            settings,
            servers,
            probes,
            favorites,
            stats: Stats::default(),
            subscriptions,
            events,
            internal_tx,
            internal_rx,
            logs,
            config,
            started_at: Instant::now(),
            http,
            fetching: HashSet::new(),
            // Далеко в прошлом: первое обновление — на первом же тике после
            // запуска. Демон мог простоять выключенным сколько угодно, и
            // сохранённые ключи к этому времени могли устареть.
            last_subscription_fetch: Instant::now()
                .checked_sub(Duration::from_secs(365 * 24 * 3600))
                .unwrap_or_else(Instant::now),
            // Не `None`, а то, что реально стоит в системе.
            //
            // Прошлый запуск демона мог закончиться падением или жёсткой
            // остановкой службы прямо в режиме прокси. Считая, что ничего не
            // применял, новый запуск не стал бы снимать оставшийся адрес — и
            // тот висел бы, пока пользователь не догадается про `netsh`.
            machine_proxy: crate::winhttp::ours_if_any(),
            failed_servers: HashMap::new(),
            probing: false,
            // Так, чтобы первый замер случился сразу, а не через интервал:
            // выбирать сервер по пингу можно только имея пинг.
            last_probe: Instant::now()
                .checked_sub(PROBE_INTERVAL)
                .unwrap_or_else(Instant::now),
            // В прошлом — чтобы первая же нужда в замере не ждала паузу.
            last_current_probe: Instant::now()
                .checked_sub(CURRENT_PROBE_RETRY)
                .unwrap_or_else(Instant::now),
            generation: 0,
            pending_reason: None,
            desired: Desired::Disconnected,
            reconnect_attempt: 0,
            health_failures: 0,
            last_health_downlink: None,
            health_in_flight: false,
            last_health_check: Instant::now(),
            // В прошлом, чтобы первая же попытка примирителя не ждала паузу.
            last_attempt: Instant::now() - RECONCILE_INTERVAL,
            in_flight: None,
            firewall: None,
        }
    }

    /// Основной цикл.
    /// Основной цикл.
    ///
    /// Завершается либо по закрытию канала команд, либо по сигналу остановки.
    /// Второе нужно службе: при остановке она обязана снять туннель, а не
    /// просто исчезнуть, оставив систему с маршрутами в никуда.
    pub async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        shutdown: tokio::sync::oneshot::Receiver<()>,
        heartbeat: crate::watchdog::Heartbeat,
    ) {
        tokio::pin!(shutdown);
        let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("supervisor запущен");

        // Приводим машинную настройку в соответствие сразу, не дожидаясь
        // первой смены состояния: если её вообще не будет — автоподключение
        // выключено, пользователь ничего не нажимает, — оставшийся от прошлого
        // запуска адрес провисел бы до перезагрузки.
        self.sync_machine_proxy();

        // Версию ядра узнаём в фоне: запуск демона не должен зависеть от
        // того, как быстро отвечает сторонний процесс.
        {
            let launcher = Arc::clone(&self.launcher);
            let tx = self.internal_tx.clone();
            tokio::spawn(async move {
                let version = launcher.version().await.ok().filter(|v| !v.is_empty());
                let _ = tx.send(Internal::CoreVersion(version)).await;
            });
        }

        // Автоподключение при старте — то, ради чего демон вообще работает в
        // фоне: пользователь включил машину и уже под защитой, ничего не
        // нажимая.
        if self.settings.auto_connect {
            match self.begin_connect(None) {
                Ok(()) => tracing::info!("автоподключение при старте"),
                Err(e) => tracing::warn!(error = %e, "автоподключение невозможно"),
            }
        }

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("получен сигнал остановки");
                    break;
                }

                command = commands.recv() => {
                    let Some(command) = command else {
                        tracing::info!("канал команд закрыт, supervisor останавливается");
                        break;
                    };
                    let response = self.handle(command.request);
                    // Клиент мог отвалиться, пока мы обрабатывали запрос —
                    // это не ошибка.
                    let _ = command.reply.send(response);
                }

                internal = self.internal_rx.recv() => {
                    if let Some(msg) = internal {
                        self.handle_internal(msg);
                    }
                }

                _ = stats_tick.tick() => {
                    // Отметка для сторожа — см. `crate::watchdog`. Ставится в
                    // тике, а не на каждой ветке: молчащий демон без команд и
                    // событий так же жив, как занятый.
                    heartbeat.beat();

                    // Надзор идёт первым: статистику упавшего ядра собирать
                    // незачем, а состояние надо поправить немедленно.
                    self.supervise();
                    self.tick_stats();
                    self.tick_probe();
                    self.tick_subscriptions();
                    // Примиритель последним: ему нужно уже поправленное
                    // надзором состояние, иначе он полезет поднимать то, что
                    // как раз восстанавливается.
                    self.tick_reconcile();
                }
            }
        }

        // Демон останавливается — за собой надо прибрать. Оставленное ядро
        // продолжит держать маршруты и TUN, и пользователь получит машину
        // без сети и без способа это исправить.
        if let Some(active) = self.active.take() {
            tracing::info!("останавливаю туннель перед выходом");
            shutdown_started(active).await;
        }

        // То же самое и по той же причине — с машинной настройкой прокси.
        // Оставленный адрес, за которым больше никого нет, ломает обновления
        // системы, и связать это с выключенным вчера VPN пользователь не
        // сможет. Снять её после нашего выхода будет некому.
        if self.machine_proxy.is_some() {
            if let Err(e) = crate::winhttp::clear() {
                tracing::error!(error = %e, "не удалось снять машинный прокси при выходе");
            } else {
                tracing::info!("машинный прокси WinHTTP снят перед выходом");
            }
        }
    }

    // ─────────────────────────── запросы ───────────────────────────

    fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::GetStatus => Response::Status(self.snapshot()),

            // Подписку обрабатывает сам IPC-сервер: ему нужно завести
            // получателя событий именно в этот момент.
            Request::SubscribeEvents => Response::Accepted,

            Request::Connect { server } => match self.begin_connect(server) {
                Ok(()) => Response::Accepted,
                Err(e) => Response::Error(IpcError::Tunnel(e)),
            },

            Request::Disconnect => {
                self.begin_disconnect(DisconnectReason::UserRequest);
                Response::Accepted
            }

            Request::AddSubscription { url } => self.add_subscription(url),

            Request::RemoveSubscription { id } => self.remove_subscription(&id),

            Request::ListSubscriptions => Response::Subscriptions(self.subscription_statuses()),

            Request::RevealSubscription { id } => match self
                .subscriptions
                .iter()
                .find(|e| e.id == id)
            {
                // Намеренно без записи в журнал: ключ не должен оказаться в
                // файле из-за того, что пользователь нажал «скопировать».
                Some(entry) => Response::SubscriptionSecret(entry.secret.clone()),
                None => Response::Error(IpcError::InvalidRequest {
                    detail: format!("подписка {id} не найдена"),
                }),
            },

            Request::ClearSubscription => {
                self.subscriptions.clear();
                self.servers.clear();
                self.probes.clear();
                self.persist_subscriptions();

                if let Err(e) = secrets::clear(&self.config.subscriptions_path) {
                    tracing::error!(error = %e, "не удалось удалить подписки");
                }

                self.emit(Event::ServerListUpdated { count: 0 });
                // Оставлять поднятый туннель без подписки бессмысленно.
                if !matches!(self.state, TunnelState::Disconnected { .. }) {
                    self.begin_disconnect(DisconnectReason::Reconfigured);
                }
                Response::Accepted
            }

            Request::RefreshSubscription { id } => match self.begin_fetch(id.as_ref()) {
                Ok(()) => Response::Accepted,
                Err(e) => Response::Error(e),
            },

            Request::ListServers => Response::Servers(self.server_views()),

            Request::ProbeServers { servers } => {
                if self.servers.is_empty() {
                    return Response::Error(IpcError::Tunnel(TunnelError::NoUsableServers));
                }
                self.begin_probe(servers);
                Response::Accepted
            }

            Request::ProxyAnnounced => {
                self.reset_connections_after_announcement();
                Response::Accepted
            }

            Request::GetSettings => Response::Settings(self.settings.clone()),

            Request::PatchSettings { patch } => self.patch_settings(patch),

            Request::GetLogs { tail } => Response::Logs(self.logs.tail(tail as usize)),

            Request::CollectDiagnostics => Response::Error(IpcError::Internal {
                detail: "сбор диагностики ещё не реализован".into(),
            }),

            Request::DaemonInfo => Response::DaemonInfo(DaemonInfo {
                daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: sont_core::PROTOCOL_VERSION,
                core_version: self.core_version.clone(),
                platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                uptime_secs: self.started_at.elapsed().as_secs(),
            }),
        }
    }

    fn subscription_statuses(&self) -> Vec<SubscriptionStatus> {
        self.subscriptions.iter().map(SubscriptionEntry::status).collect()
    }

    /// Сохраняет список подписок на диск.
    ///
    /// Отдельным методом, потому что вызывается из каждой операции над
    /// списком: пропусти один вызов — и подписка исчезнет при перезапуске
    /// демона, причём заметит это пользователь далеко не сразу.
    fn persist_subscriptions(&self) {
        if self.config.demo_servers {
            // Демонстрационный набор ничей: записав его на диск, мы затёрли бы
            // настоящие подписки пользователя, случайно запустившего демон с
            // этим флагом.
            return;
        }
        if let Err(e) = secrets::store_json(&self.config.subscriptions_path, &self.subscriptions) {
            tracing::error!(error = %e, "не удалось сохранить подписки");
        }
    }

    /// Пересобирает общий список серверов и выбрасывает замеры исчезнувших.
    fn rebuild_servers(&mut self) {
        self.servers = merge_servers(&self.subscriptions);

        // Замеры серверов, которых больше нет, только занимают место и путают
        // автовыбор: он предпочтёт «известный быстрый» сервер, которого уже
        // не существует.
        let live: HashSet<ProfileId> = self.servers.iter().map(|s| s.id.clone()).collect();
        self.probes.retain(|id, _| live.contains(id));
    }

    fn add_subscription(&mut self, url: Secret) -> Response {
        let raw = url.expose();
        if !(raw.starts_with("https://") || raw.starts_with("http://")) {
            return Response::Error(IpcError::InvalidRequest {
                detail: "ссылка подписки должна начинаться с http:// или https://".into(),
            });
        }
        if raw.starts_with("http://") {
            // Не отказ: некоторые панели до сих пор работают без TLS, и
            // запрет оставил бы пользователя без доступа. Но предупредить
            // обязаны — по этой ссылке уходят учётные данные.
            tracing::warn!("подписка получается по незашифрованному http");
        }

        let id = SubscriptionId::from_url(raw);

        // Повторное добавление той же ссылки — обновление, а не дубликат.
        // Пользователь, вставивший её дважды, ожидает одну подписку, а не две
        // одинаковые, из которых серверы потом придут парами.
        let existing = self.subscriptions.iter().position(|e| e.id == id);

        match existing {
            Some(i) => {
                tracing::info!("подписка уже добавлена, ключ обновлён");
                self.subscriptions[i].masked_url = url.masked();
                self.subscriptions[i].secret = url;
            }
            None => {
                self.subscriptions.push(SubscriptionEntry {
                    id: id.clone(),
                    masked_url: url.masked(),
                    secret: url,
                    profiles: Vec::new(),
                    info: SubscriptionInfo::default(),
                });
                tracing::info!(total = self.subscriptions.len(), "подписка добавлена");
            }
        }

        self.persist_subscriptions();

        // Событие `SubscriptionUpdated` намеренно не публикуем здесь: оно
        // означает «подписка прочитана» и должно нести настоящие данные.
        // Сообщив о сохранении ключа тем же событием с пустыми показателями,
        // мы заставили бы подписчиков принять заглушку за результат загрузки.

        // Сразу пробуем прочитать: пользователь должен увидеть результат
        // ввода ключа, а не пустой список с предложением что-то обновить.
        if let Err(e) = self.begin_fetch(Some(&id)) {
            return Response::Error(e);
        }

        Response::Accepted
    }

    fn remove_subscription(&mut self, id: &SubscriptionId) -> Response {
        let Some(i) = self.subscriptions.iter().position(|e| &e.id == id) else {
            return Response::Error(IpcError::InvalidRequest {
                detail: format!("подписка {id} не найдена"),
            });
        };

        let removed = self.subscriptions.remove(i);
        tracing::info!(
            servers = removed.profiles.len(),
            left = self.subscriptions.len(),
            "подписка удалена"
        );

        let current = self.state.server().cloned();
        self.rebuild_servers();
        self.persist_subscriptions();

        self.emit(Event::ServerListUpdated {
            count: self.servers.len() as u32,
        });

        // Если соединение держалось на сервере из удалённой подписки, его
        // нельзя оставить: пользователь считает, что доступа к ней больше нет,
        // а трафик продолжал бы идти через её сервер.
        let lost = current.is_some_and(|id| !self.servers.iter().any(|s| s.id == id));
        if lost && !matches!(self.state, TunnelState::Disconnected { .. }) {
            tracing::info!("текущий сервер пришёл из удалённой подписки, переподключаюсь");
            if self.servers.is_empty() {
                self.begin_disconnect(DisconnectReason::Reconfigured);
            } else {
                self.begin_reconnect(ReconnectCause::ServerSwitched);
            }
        }

        Response::Accepted
    }

    /// Перемеряет задержку, если прошлый замер устарел.
    ///
    /// Замер идёт и при поднятом соединении. Числа при этом получаются
    /// завышенными — до чужого сервера мы идём сквозь туннель, — но сравнимыми
    /// между собой, а для выбора «куда переключиться» важен именно порядок.
    fn tick_probe(&mut self) {
        if self.servers.is_empty() {
            return;
        }

        let interval = Duration::from_secs(u64::from(self.settings.probe_interval_secs));
        if self.last_probe.elapsed() >= interval {
            self.begin_probe(None);
            return;
        }

        // Соединение есть, а задержки до его сервера нет — меряем его одного, и
        // часто.
        //
        // Так бывает сразу после подключения, пока общий замер ещё не прошёл,
        // и после провала сети: замер, попавший на обрыв, записал сервер
        // недоступным, туннель давно поднялся, а следующий общий замер — через
        // пять минут. Всё это время в шапке окна стояло тире, хотя трафик шёл.
        if let Some(server) = self.connected_server_without_rtt() {
            if self.last_current_probe.elapsed() >= CURRENT_PROBE_RETRY {
                self.last_current_probe = Instant::now();
                self.begin_probe(Some(vec![server]));
            }
        }
    }

    /// Сервер текущего соединения, если задержка до него не известна.
    fn connected_server_without_rtt(&self) -> Option<ProfileId> {
        if !self.state.is_connected() {
            return None;
        }
        let server = self.state.server()?;
        let known = self.probes.get(server).is_some_and(ProbeResult::is_reachable);
        (!known).then(|| server.clone())
    }

    /// Запускает фоновый замер задержки.
    ///
    /// `None` — мерить все известные серверы.
    ///
    /// Молча ничего не делает, если замер уже идёт: пользователь может нажать
    /// «обновить» несколько раз подряд, и превращать это в десяток параллельных
    /// заходов на каждый сервер подписки незачем.
    fn begin_probe(&mut self, only: Option<Vec<ProfileId>>) {
        if self.probing {
            return;
        }

        let targets: Vec<ServerProfile> = match &only {
            Some(ids) => self
                .servers
                .iter()
                .filter(|s| ids.contains(&s.id))
                .cloned()
                .collect(),
            None => self.servers.clone(),
        };

        if targets.is_empty() {
            return;
        }

        self.probing = true;
        // Общие часы замеров сдвигает только общий замер. Замер одного сервера
        // — ради шапки окна или по просьбе пользователя — откладывал бы
        // очередной круг по всем, и при частых повторах тот не наступил бы
        // вовсе.
        if only.is_none() {
            self.last_probe = Instant::now();
        }

        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let results = crate::probe::many(targets).await;
            let _ = tx.send(Internal::Probed(results)).await;
        });
    }

    /// Переходит ли демон на сервер, который оказался заметно быстрее.
    ///
    /// Проверяется после каждого замера. Смена сервера рвёт все соединения,
    /// поэтому порог здесь не украшение, а условие осмысленности: без него
    /// демон переподключался бы на каждом дрожании замера, и пользователь
    /// получал бы обрывы вместо выигрыша в десяток миллисекунд.
    fn consider_better_server(&mut self) {
        if !self.settings.auto_switch || !self.state.is_connected() {
            return;
        }
        // Пользователь закрепил сервер сам — не спорим с ним.
        if !self.settings.auto_select_server {
            return;
        }

        let Some(current) = self.state.server().cloned() else {
            return;
        };
        let Some(current_rtt) = self.probes.get(&current).and_then(|p| p.rtt_ms) else {
            // Текущий сервер не измерен: сравнивать не с чем, а менять его
            // «вслепую» — это не улучшение, а лотерея.
            return;
        };

        let Some(candidate) = self.best_by_probe(Some(&current)) else {
            return;
        };
        let Some(candidate_rtt) = self.probes.get(&candidate).and_then(|p| p.rtt_ms) else {
            return;
        };

        let gain = current_rtt.saturating_sub(candidate_rtt);
        if gain < self.settings.switch_threshold_ms {
            return;
        }

        tracing::info!(
            from = %current,
            to = %candidate,
            gain_ms = gain,
            "нашёлся сервер быстрее, перехожу"
        );
        self.begin_switch(candidate, ReconnectCause::BetterServerFound { gain_ms: gain });
    }

    /// Переходит на другой сервер по собственному решению демона.
    ///
    /// Отличается от восстановления тем, что ничего не сломалось: паузы перед
    /// попыткой нет, счётчик неудач не растёт, а прежний сервер не попадает в
    /// штрафной ящик — он исправен, просто нашёлся быстрее.
    fn begin_switch(&mut self, target: ProfileId, cause: ReconnectCause) {
        if !matches!(self.desired, Desired::Connected { .. }) {
            return;
        }

        self.set_state(TunnelState::Reconnecting {
            server: target.clone(),
            cause,
            attempt: 1,
        });

        let previous = self.active.take();
        if let Err(e) = self.launch(target, previous, Duration::ZERO, Selection::Fixed) {
            tracing::error!(error = %e, "не удалось перейти на другой сервер");
            self.fail(e);
        }
    }

    /// Принимает результаты замера.
    fn apply_probes(&mut self, results: Vec<ProbeResult>) {
        self.probing = false;

        let reachable = results.iter().filter(|p| p.is_reachable()).count();
        tracing::info!(
            measured = results.len(),
            reachable,
            "замер задержки завершён"
        );

        let connected_to = self
            .state
            .is_connected()
            .then(|| self.state.server().cloned())
            .flatten();

        for probe in results {
            // Неудачный замер сервера, через который прямо сейчас идёт трафик,
            // не отменяет удачного.
            //
            // Про этот сервер известно больше, чем может сказать замер: туннель
            // через него работает, и проверка живости это подтверждает. Промах
            // TCP в такой момент — дрожь сети, а не свойство сервера. Раньше он
            // стирал задержку, и в шапке окна до следующего замера — пять минут
            // — стояло тире при исправном соединении.
            let keep_previous = !probe.is_reachable()
                && connected_to.as_ref() == Some(&probe.server)
                && self
                    .probes
                    .get(&probe.server)
                    .is_some_and(ProbeResult::is_reachable);
            if keep_previous {
                tracing::debug!(server = %probe.server, "замер подключённого сервера не прошёл, оставляю прежний");
                continue;
            }

            self.probes.insert(probe.server.clone(), probe.clone());
            self.emit(Event::Probe(probe));
        }

        // Свежие числа — единственный момент, когда решение о переходе на
        // более быстрый сервер вообще обосновано.
        self.consider_better_server();
    }

    /// Запускает фоновое получение подписок.
    ///
    /// `None` — перечитать все. Каждая читается своей задачей: одна недоступная
    /// панель не должна задерживать остальные, а тем более отменять их.
    /// Обновляет подписки по расписанию — и сразу после запуска демона.
    ///
    /// # Чего не было
    ///
    /// Настройка «обновлять раз в двенадцать часов» существовала, сохранялась
    /// и показывалась — и не делала ничего. Подписка читалась ровно два раза:
    /// когда её добавляли и когда пользователь сам нажимал «Обновить». Всё
    /// остальное время демон работал на разборе, сохранённом в день
    /// добавления.
    ///
    /// Пока провайдер ничего не менял, этого не было видно. Когда он сменил
    /// ключи Reality, серверы перестали узнавать Sont: каждое соединение
    /// получало настоящий сертификат сайта маскировки, гонка объявляла, что
    /// «у машины нет пути наружу», и подключиться не выходило ни к чему. Happ
    /// с той же подпиской при этом работал — он её обновлял.
    fn tick_subscriptions(&mut self) {
        if self.subscriptions.is_empty() || !self.fetching.is_empty() {
            return;
        }
        let hours = u64::from(self.settings.subscription_refresh_hours.max(1));
        if self.last_subscription_fetch.elapsed() < Duration::from_secs(hours * 3600) {
            return;
        }
        self.refresh_subscriptions("по расписанию");
    }

    /// Обновляет подписки, когда гонка не нашла ни одного живого сервера.
    ///
    /// Молчат все восемь — значит, либо у машины нет сети, либо у нас
    /// устаревшие ключи. В первом случае обновление безвредно: запрос к панели
    /// просто не пройдёт. Во втором — это единственное, что вообще поможет, и
    /// ждать до планового обновления значило бы оставить пользователя без
    /// связи на полдня.
    ///
    /// Не чаще раза в [`SILENCE_REFRESH_MIN`]: пока сети нет, гонка не
    /// отзывается раз за разом, и превращать это в поток запросов к панели
    /// незачем.
    fn refresh_after_silence(&mut self, rejected: bool) {
        if rejected {
            tracing::warn!("серверы не узнают ключ Reality — обновляю подписки");
        }
        if self.subscriptions.is_empty()
            || !self.fetching.is_empty()
            || self.last_subscription_fetch.elapsed() < SILENCE_REFRESH_MIN
        {
            return;
        }
        self.refresh_subscriptions(if rejected {
            "серверы отвергают ключ"
        } else {
            "ни один сервер не отозвался"
        });
    }

    fn refresh_subscriptions(&mut self, reason: &str) {
        self.last_subscription_fetch = Instant::now();
        tracing::info!(reason, "обновляю подписки");
        if let Err(e) = self.begin_fetch(None) {
            tracing::warn!(error = ?e, "обновить подписки не вышло");
        }
    }

    fn begin_fetch(&mut self, only: Option<&SubscriptionId>) -> Result<(), IpcError> {
        if self.subscriptions.is_empty() {
            return Err(IpcError::Tunnel(TunnelError::NoSubscription));
        }
        let Some(http) = self.http.clone() else {
            return Err(IpcError::Internal {
                detail: "HTTP-клиент недоступен".into(),
            });
        };

        let targets: Vec<(SubscriptionId, Secret)> = self
            .subscriptions
            .iter()
            .filter(|e| only.is_none_or(|id| &e.id == id))
            // Уже идущий запрос не дублируем: пользователь может нажать
            // «обновить» несколько раз подряд, и превращать это в поток
            // запросов к панели незачем.
            .filter(|e| !self.fetching.contains(&e.id))
            .map(|e| (e.id.clone(), e.secret.clone()))
            .collect();

        if let Some(id) = only {
            if !self.subscriptions.iter().any(|e| &e.id == id) {
                return Err(IpcError::InvalidRequest {
                    detail: format!("подписка {id} не найдена"),
                });
            }
        }

        for (id, secret) in targets {
            self.fetching.insert(id.clone());
            let http = http.clone();
            let tx = self.internal_tx.clone();
            tokio::spawn(async move {
                let result = http.fetch(&secret).await;
                let _ = tx.send(Internal::SubscriptionFetched { id, result }).await;
            });
        }

        Ok(())
    }

    /// Применяет результат получения одной подписки.
    fn apply_fetched(&mut self, id: SubscriptionId, result: Result<Fetched, FetchError>) {
        self.fetching.remove(&id);

        // Подписку могли удалить, пока запрос был в пути. Тогда результат
        // относится к тому, чего уже нет, и применять его нельзя — иначе
        // удалённая подписка вернулась бы сама собой.
        let Some(index) = self.subscriptions.iter().position(|e| e.id == id) else {
            tracing::debug!(%id, "ответ панели относится к удалённой подписке, отброшен");
            return;
        };

        let fetched = match result {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(%id, error = %e, "не удалось обновить подписку");
                // Прежние серверы этой подписки остаются в силе: недоступность
                // панели не повод лишать пользователя работающих серверов. Тем
                // более что остальные подписки при этом не пострадали.
                self.emit(Event::Error(IpcError::Tunnel(
                    TunnelError::SubscriptionUnavailable {
                        detail: e.to_string(),
                    },
                )));
                return;
            }
        };

        if fetched.skipped > 0 {
            tracing::warn!(
                %id,
                skipped = fetched.skipped,
                "часть строк подписки не разобрана"
            );
        }
        tracing::info!(%id, count = fetched.profiles.len(), "подписка обновлена");

        // Профиль, который текущее ядро не потянет, лучше отметить сразу:
        // иначе пользователь упрётся в непонятную ошибку при подключении.
        let needs_xray = fetched.profiles.iter().filter(|p| p.transport.requires_xray()).count();
        if needs_xray > 0 {
            tracing::warn!(
                count = needs_xray,
                "серверов с транспортом XHTTP: он поддерживается только ядром Xray"
            );
        }

        let mut info = fetched.info;
        info.server_count = fetched.profiles.len() as u32;

        // Сравниваются профили целиком, а не номера серверов: номер считается
        // от адреса и UUID, а ключ Reality в него не входит. Панель, сменившая
        // только ключ, дала бы те же номера — и обречённая попытка со старым
        // ключом продолжилась бы.
        let changed = self.subscriptions[index].profiles != fetched.profiles;
        self.subscriptions[index].profiles = fetched.profiles;
        self.subscriptions[index].info = info;

        self.rebuild_servers();
        self.persist_subscriptions();

        self.emit(Event::SubscriptionUpdated(self.subscriptions[index].status()));
        self.emit(Event::ServerListUpdated {
            count: self.servers.len() as u32,
        });

        // Список изменился — прежние замеры описывают уже не его. Меряем
        // сразу, а не через интервал: автовыбор и переключение при падении
        // без свежих чисел работают вслепую.
        self.begin_probe(None);

        // Соединения нет, а оно нужно, и идёт попытка — начинаем её заново, по
        // свежему списку.
        //
        // Идущая попытка несёт профиль с прежними ключами: она была заведена
        // до обновления. Если обновление принесло новые ключи — а ради этого
        // оно часто и затевалось, после гонки, где серверы отвергали старые, —
        // эта попытка обречена. Дожидаться её отказа значит потерять ещё круг
        // с паузой до пятнадцати секунд, хотя всё нужное уже на руках.
        let waiting = self.state.holds_a_route() && !self.state.is_connected();
        if waiting && matches!(self.desired, Desired::Connected { .. }) {
            // Панель вернула то же самое — идущая попытка несёт те же ключи и
            // ничем не обречена. Начать её заново значит выбросить сделанную
            // работу: в журнале у пользователя так оборвалась гонка, которой до
            // ответа оставались секунды, и всё пошло по новому кругу.
            if !changed {
                return;
            }
            tracing::info!("подписка обновлена посреди подключения — начинаю его заново");
            let pinned = match &self.desired {
                Desired::Connected { server } => server.clone(),
                Desired::Disconnected => None,
            };
            if let Err(e) = self.begin_connect(pinned) {
                tracing::warn!(error = %e, "начать заново не вышло, вернусь позже");
            }
            return;
        }

        // Серверы появились там, где их не было. Если демон всё это время
        // добивался соединения — а он добивается, когда включено
        // автоподключение, — поднимать его надо сейчас, а не через паузу
        // примирителя: пользователь только что вставил ключ и смотрит на окно.
        self.last_attempt = Instant::now() - RECONCILE_INTERVAL;
        self.tick_reconcile();
    }

    fn patch_settings(&mut self, patch: SettingsPatch) -> Response {
        let firewall_before = self.settings.firewall;
        let outcome = patch.apply(&mut self.settings);

        if let Err(e) = store::save(&self.config.settings_path, &self.settings) {
            tracing::error!(error = %e, "не удалось сохранить настройки");
            return Response::Error(IpcError::Internal {
                detail: format!("не удалось сохранить настройки: {e}"),
            });
        }

        // Смена режима состояние не меняет, поэтому машинную настройку надо
        // поправить здесь: переключение на прокси должно объявить адрес сразу,
        // а не после переподключения. Иначе между сменой режима и подъёмом
        // нового ядра остаётся окно, в которое приложения уходят напрямую.
        self.sync_machine_proxy();

        // Настройка, требующая новой конфигурации ядра, применяется сама.
        //
        // Раньше здесь стояла только запись в журнал, и это была ловушка:
        // пользователь переключал режим или DNS, видел новое значение в
        // интерфейсе — и продолжал работать по старой конфигурации, пока не
        // догадается переподключиться вручную. Настройка, которая показывает
        // одно, а делает другое, хуже отсутствующей.
        if outcome.needs_core_restart && self.state.holds_a_route() {
            tracing::info!("настройки требуют новой конфигурации ядра, пересобираю соединение");
            self.reconfigure();
        }
        // Kill-switch следует за настройкой сразу, а не со следующего
        // подключения: пользователь, включивший блокировку, ожидает её
        // прямо сейчас, а выключивший — ждёт, что интернет вернётся.
        let firewall_changed = self.settings.firewall != firewall_before;
        // Смена Auto на Lockdown и обратно меняет саму сессию WFP: у одной
        // фильтры динамические, у другой постоянные. Переставить правила на
        // месте нельзя, нужно снять и поднять заново.
        if firewall_changed {
            self.disengage_firewall();
        }
        if outcome.needs_firewall_reapply || firewall_changed {
            let luid = match &self.state {
                TunnelState::Connected { tun, .. } => tun.luid,
                _ => None,
            };
            // Ставим только при живом намерении: включать блокировку у
            // отключённого пользователя значит отрезать ему сеть настройкой,
            // которая должна была её всего лишь защитить.
            if matches!(self.desired, Desired::Connected { .. }) {
                self.sync_firewall(luid);
            } else {
                self.disengage_firewall();
            }
            self.refresh_blocked();
        }

        Response::Settings(self.settings.clone())
    }

    // ─────────────────────────── переходы ───────────────────────────

    fn begin_connect(&mut self, explicit: Option<ProfileId>) -> Result<(), TunnelError> {
        let selected = self.select_server(explicit.clone());

        // Намерение пользователя запоминаем до всех проверок — и даже когда
        // проверка не прошла.
        //
        // Серверов может не быть прямо сейчас: демон только запустился, ключ
        // ещё не введён. Сдаться в этот момент значит остаться отключённым
        // навсегда, пока пользователь не нажмёт кнопку — а он уже сказал, чего
        // хочет, включив автоподключение. С сохранённым намерением соединение
        // поднимется само, как только появится на чём.
        //
        // Исключение — несуществующий сервер: добиваться того, чего нет в
        // списке, демон будет вечно и безрезультатно.
        if !matches!(selected, Err(TunnelError::UnknownServer { .. })) {
            self.desired = Desired::Connected {
                server: explicit.clone(),
            };
            self.reconnect_attempt = 0;
            self.last_attempt = Instant::now();
        }

        let id = selected?;

        self.set_state(TunnelState::Connecting {
            server: id.clone(),
            attempt: 1,
        });

        // Если пользователь просит подключиться, уже будучи подключённым
        // (типично — чтобы применить смену режима), прежнюю сессию нельзя
        // просто отбросить: `CoreProcess` и `Tunnel` не останавливаются в
        // `Drop`, и забытый `Started` оставляет висеть процесс ядра и
        // TUN-адаптер, за которым больше никто не следит и который нечем
        // будет отключить.
        let previous = self.active.take();
        self.launch(id, previous, Duration::ZERO, Selection::Race)
    }

    // ─────────────────────────── kill-switch ───────────────────────────

    /// Что выпускается наружу мимо запрета при текущих настройках.
    fn allowances(&self, tunnel_luid: Option<u64>) -> crate::firewall::Allowances {
        // Ядро и сам демон — без них блокировка не даст подняться туннелю,
        // который её же и оправдывает.
        let mut apps = vec![self.config.core_binary.clone()];
        if let Ok(exe) = std::env::current_exe() {
            apps.push(exe);
        }

        // Только адреса-литералы: имя сервера ещё нужно разрешить, а
        // резолвер в этот момент уже закрыт нашим же запретом. Разрешение
        // имени делает ядро, и ему выход открыт по имени файла.
        let servers = self
            .servers
            .iter()
            .filter_map(|s| s.endpoint.host.parse::<std::net::IpAddr>().ok())
            .collect();

        crate::firewall::Allowances {
            tunnel_luid,
            apps,
            servers,
            allow_lan: self.settings.allow_lan,
        }
    }

    /// Приводит блокировку в соответствие настройке и состоянию.
    ///
    /// Одна точка входа на все случаи: включили настройку, сменили
    /// разрешения, поднялся туннель со своим LUID. Разведи это по трём
    /// местам — и одно из них рано или поздно останется со старым набором
    /// правил.
    fn sync_firewall(&mut self, tunnel_luid: Option<u64>) {
        if !self.settings.firewall.is_enabled() {
            self.disengage_firewall();
            return;
        }

        let allow = self.allowances(tunnel_luid);

        if let Some(firewall) = self.firewall.as_ref() {
            if let Err(e) = firewall.update(&allow) {
                tracing::error!(error = %e, "не удалось переставить правила kill-switch");
            }
            return;
        }

        match crate::firewall::Firewall::engage(self.settings.firewall, &allow) {
            Ok(firewall) => self.firewall = Some(firewall),
            Err(e) => {
                // Не подняли — значит не подняли: соврать `blocked: true`
                // означало бы обещать защиту, которой нет.
                tracing::error!(error = %e, "не удалось включить kill-switch");
            }
        }
    }

    fn disengage_firewall(&mut self) {
        if let Some(firewall) = self.firewall.take() {
            if let Err(e) = firewall.disengage() {
                tracing::error!(error = %e, "не удалось снять kill-switch");
            }
        }
    }

    /// Приводит поле `blocked` в состоянии к тому, что на самом деле с
    /// фильтрами.
    ///
    /// Нужно там, где блокировка меняется, а состояние — нет: пользователь
    /// отключён и включает kill-switch. Само по себе «отключено» осталось
    /// прежним, но интернет пропал, и молчание здесь оставило бы это без
    /// объяснения.
    fn refresh_blocked(&mut self) {
        let blocked = self.firewall.is_some();
        let updated = match &self.state {
            TunnelState::Disconnected { reason, .. } => TunnelState::Disconnected {
                reason: reason.clone(),
                blocked,
            },
            TunnelState::Failed { error, .. } => TunnelState::Failed {
                error: error.clone(),
                blocked,
            },
            // В остальных состояниях `is_blocked` выводится из самого
            // состояния и отдельного поля не имеет.
            _ => return,
        };
        self.set_state(updated);
    }

    /// Запускает ядро и сетевой слой для выбранного сервера.
    ///
    /// Общий путь для первого подключения и для восстановления: разойдись они,
    /// и восстановление рано или поздно начнёт отличаться от подключения в
    /// мелочах, которые всплывут только у пользователя.
    ///
    /// При `Selection::Race` названный сервер — предпочтение, а не приговор: он
    /// вместе с лучшими из остальных участвует в гонке, и подключение уходит к
    /// тому, кто первым проведёт настоящий запрос. См. [`choose_working`].
    fn launch(
        &mut self,
        id: ProfileId,
        previous: Option<Started>,
        delay: Duration,
        selection: Selection,
    ) -> Result<(), TunnelError> {
        let profile = self
            .servers
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .ok_or_else(|| TunnelError::UnknownServer { id: id.to_string() })?;

        // Проверяем пригодность до запуска: показать «подключаюсь», а через
        // секунду сообщить, что протокол вообще не поддерживается, — худший
        // из возможных вариантов.
        if let Some(reason) = sont_xray::unsupported_reason(&profile.transport) {
            // Навсегда: этот профиль ядру не по зубам, и следующая попытка
            // упрётся в то же самое. Автовыбор до сюда не доходит — такие
            // серверы отсеиваются ещё в `candidates`.
            return Err(TunnelError::CoreStartFailed {
                detail: reason.to_owned(),
                permanent: true,
            });
        }

        let race_pool = match selection {
            Selection::Race => self.race_pool(&profile),
            Selection::Fixed => Vec::new(),
        };

        self.generation += 1;
        let generation = self.generation;

        // Отметка живости попытки: по ней примиритель отличает идущую работу
        // от задачи, которая замолчала и больше не отчитается.
        self.last_attempt = Instant::now();

        // Прежняя попытка обязана уступить, а не доработать до конца.
        let cancel = self.supersede_in_flight();

        // Блокировку ставим до того, как гасится прежний туннель, и без
        // ссылки на новый: он ещё не существует. Иначе между снятием старого
        // маршрута и появлением нового трафик уходит напрямую — то самое
        // окно, ради которого kill-switch и заводят.
        self.sync_firewall(None);

        // Служебный порт статистики обнуляем: читать счётчики уже не у кого.
        self.metrics_url = None;

        // А вот адреса прокси держим прежними, хотя ядро ещё не поднялось.
        //
        // Они почти наверняка те же: порты предпочитаемые и постоянные. Но
        // дело даже не в этом, а в том, что альтернатива — снять объявление на
        // время переподключения, то есть открыть окно, в которое приложения
        // уйдут напрямую. Пусть лучше несколько секунд получают отказ.
        self.last_counters = None;
        self.stats = Stats::default();
        self.health_failures = 0;
        self.last_health_check = Instant::now();
        // Новое ядро — новые счётчики: они начинаются с нуля, и сравнивать их с
        // прошлым сеансом нельзя. А незаконченная проверка прошлого сеанса
        // своё отчитает — и будет отброшена по поколению.
        self.last_health_downlink = None;
        self.health_in_flight = false;

        let tx = self.internal_tx.clone();
        let launcher = Arc::clone(&self.launcher);
        let settings = self.settings.clone();
        let config_path = self.config.core_config_path.clone();
        // Адреса всех серверов подписки: в режиме туннеля они обязаны идти мимо
        // него, а не только тот, к которому подключаемся, — см. `start_core`.
        let peers: Vec<String> = self
            .servers
            .iter()
            .map(|s| s.endpoint.host.clone())
            .collect();
        // Конфигурация гонки живёт отдельным файлом рядом с основной: она
        // содержит учётные данные всех проверяемых серверов, и класть её на
        // место рабочей значит терять рабочую при каждой проверке.
        let race_config = config_path.with_extension("race.json");

        tokio::spawn(async move {
            // Прежний сеанс гасим до паузы, а не после: он держит маршруты и
            // TUN-адаптер, и оставлять их на время ожидания незачем.
            // Уборка прежнего сеанса идёт всегда, даже если нашу попытку уже
            // отменили: это его ядро и адаптер, и кроме нас их погасить некому.
            if let Some(previous) = previous {
                shutdown_started(previous).await;
            }

            // Отменённая попытка молчит, а не отчитывается: её поколение уже
            // устарело, и ответ всё равно был бы отброшен.
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = cancel.cancelled() => return,
            }

            // Кого поднимать, решается в последний момент и по настоящей
            // проверке.
            //
            // Ранжирование по замерам отвечает на вопрос «какой сервер ближе»,
            // но не на вопрос «работает ли он»: до сервера с истёкшим ключом
            // TCP доходит прекрасно, и рукопожатие Reality он проводит честно.
            // Раньше это выяснялось запуском ядра на каждом кандидате по
            // очереди — то есть ценой полной последовательности подключения за
            // каждый негодный сервер. Здесь все кандидаты проверяются разом.
            let (profile, vouched) =
                match choose_working(&launcher, race_pool, &settings, &race_config, &cancel).await {
                    Chosen::Vouched(winner) => (*winner, true),
                    // Проверка ничего не показала — ни про один сервер. Идём
                    // туда, куда указало ранжирование: другого основания нет.
                    Chosen::Unknown => (profile, false),

                    // А здесь она показала главное: пути наружу нет.
                    //
                    // Запускать ядро и ждать рукопожатие незачем — это ещё
                    // десяток секунд на выяснение того, что уже выяснено. И
                    // назвать причину надо честно, иначе демон запишет в
                    // отказавшие исправный сервер и уйдёт перебирать остальные,
                    // получая на каждом то же самое.
                    Chosen::NoWayOut { rejected } => {
                        // Сперва — о том, что серверы молчат: демону это повод
                        // обновить подписку, и тем раньше, чем быстрее он
                        // узнает.
                        let _ = tx.send(Internal::ServersSilent { rejected }).await;
                        let _ = tx
                            .send(Internal::CoreStarted {
                                generation,
                                vouched: false,
                                result: Box::new(Err(TunnelError::NetworkSetupFailed {
                                    detail: "ни один сервер не отозвался: у машины нет пути наружу"
                                        .to_owned(),
                                })),
                            })
                            .await;
                        return;
                    }
                };

            // Пока шла гонка, нас могли вытеснить. Поднимать ядро после этого —
            // значит занять порты и адаптер, которые уже нужны новой попытке.
            if cancel.is_cancelled() {
                return;
            }

            if profile.id != id {
                let _ = tx
                    .send(Internal::ServerChosen {
                        generation,
                        server: profile.id.clone(),
                    })
                    .await;
            }

            // Порты выбираем только теперь.
            //
            // Раньше это делалось при постановке задачи — то есть пока прежнее
            // ядро ещё держало сокеты. Предпочитаемый порт оказывался занят
            // нами же, и локальный прокси уезжал на случайный номер при каждом
            // переподключении. Для режима прокси это прямая поломка: адрес
            // прописан в настройках системы, и переподключение по инициативе
            // демона (упавшее ядро, неудачная проверка связи) оставляло эти
            // настройки указывать на порт, где уже никого нет.
            let runtime = runtime_info(&settings);

            // Общий предохранитель на всю последовательность.
            //
            // Внутри у каждого этапа свой срок, но сторонний код может
            // заблокироваться так, что до проверки дело не дойдёт. Тогда
            // пользователь остаётся с вечным «подключаюсь» и без единого
            // способа это прервать. Лучше сдаться с внятной причиной.
            let result = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                start_core(&launcher, &profile, &peers, &settings, &runtime, &config_path, &cancel),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    tracing::error!(
                        seconds = CONNECT_TIMEOUT.as_secs(),
                        "последовательность подключения не завершилась за отведённое время"
                    );
                    Err(TunnelError::HandshakeTimeout {
                        seconds: CONNECT_TIMEOUT.as_secs(),
                    })
                }
            };
            let _ = tx
                .send(Internal::CoreStarted {
                    generation,
                    vouched,
                    result: Box::new(result),
                })
                .await;
        });

        Ok(())
    }

    /// Останавливает идущую попытку и заводит отмену для новой.
    ///
    /// Отмена кооперативная: попытка сама проверяет её между этапами и сама
    /// прибирает то, что успела поднять. Бросить её на полпути нельзя —
    /// `CoreProcess` и `Tunnel` не гасятся в `Drop`, и брошенная задача
    /// оставила бы после себя живое ядро и адаптер, за которыми никто не
    /// следит.
    fn supersede_in_flight(&mut self) -> tokio_util::sync::CancellationToken {
        if let Some(previous) = self.in_flight.take() {
            previous.cancel();
        }
        let token = tokio_util::sync::CancellationToken::new();
        self.in_flight = Some(token.clone());
        token
    }

    /// Кандидаты, между которыми разыгрывается право на подключение.
    ///
    /// Первым идёт выбранный ранжированием сервер, дальше — лучшие из
    /// оставшихся. Порядок здесь не решающий (побеждает тот, кто первым
    /// проведёт запрос), но он определяет, кто вообще попадёт в гонку.
    ///
    /// Пусто, когда сервер выбран не демоном: закреплённый пользователем сервер
    /// подменять нельзя даже молчащим. Пользователь просил именно его и должен
    /// увидеть именно его отказ, а не молча оказаться в другой стране.
    ///
    /// Недавно упавшие в гонку допускаются, но идут после остальных: дорожки
    /// сначала достаются серверам без чёрной отметки.
    ///
    /// Раньше их не пускали вовсе — и так на десять минут терялся рабочий
    /// сервер. В журнале у пользователя это выглядит так: гонка выбрала сервер,
    /// через минуту проверка живости (тогда ещё с шестисекундным пределом)
    /// ложно сочла туннель мёртвым, сервер ушёл в штрафной ящик — а он был
    /// единственным рабочим в подписке. Восемь минут гонка за гонкой гоняла
    /// оставшиеся, не отвечавшие; стоило штрафу истечь, как первая же гонка
    /// выбрала отлучённый сервер за шесть секунд.
    ///
    /// Гонка — это настоящий запрос через сервер, а не догадка по пингу.
    /// Ответил — значит, работает сейчас, что бы ни было минуту назад; и
    /// удачное подключение само снимет с него отметку. Штрафной ящик остаётся
    /// там, где проверки нет: при выборе по одному лишь замеру.
    ///
    /// В самый конец идут серверы, до которых не дошёл даже замер: TCP к ним
    /// не устанавливается, и дорожку лучше отдать тому, у кого шанс есть.
    ///
    /// Серверы, которых не умеет ядро, исключаются: они не могут стать
    /// дорожкой, а один такой в списке отменил бы сборку всей конфигурации
    /// проверки.
    fn race_pool(&self, primary: &ServerProfile) -> Vec<ServerProfile> {
        if !self.picks_the_server_itself() || !sont_xray::supports(&primary.transport) {
            return Vec::new();
        }

        let mut ranked: Vec<&ServerProfile> = self
            .candidates()
            .filter(|s| s.id != primary.id)
            .filter(|s| sont_xray::supports(&s.transport))
            .collect();

        ranked.sort_by_key(|s| {
            let probe = self.probes.get(&s.id);
            let silent = probe.is_some_and(|p| !p.is_reachable());
            (
                silent,
                self.recently_failed(&s.id),
                probe.map_or(u32::MAX - 1, ProbeResult::score),
            )
        });
        ranked.truncate(crate::race::LANES.saturating_sub(1));

        std::iter::once(primary.clone())
            .chain(ranked.into_iter().cloned())
            .collect()
    }

    /// Волен ли демон сам решать, на какой сервер идти.
    fn picks_the_server_itself(&self) -> bool {
        match &self.desired {
            // Пользователь назвал сервер в самой команде подключения.
            Desired::Connected { server: Some(_) } => false,
            Desired::Connected { server: None } => {
                self.settings.auto_select_server || self.settings.pinned_server.is_none()
            }
            Desired::Disconnected => false,
        }
    }

    /// Гонка увела попытку на другой сервер.
    ///
    /// Состояние обязано это отразить сразу: иначе пользователь смотрит на имя
    /// сервера, к которому демон уже не подключается, и узнаёт правду только
    /// из «Подключено» с третьим названием.
    ///
    /// В штрафной ящик проигравший при этом не идёт. Проигрыш в гонке — это не
    /// отказ: сервер мог просто оказаться медленнее победителя. Ящик заведён
    /// для тех, у кого туннель разваливался, и записывать туда за медлительность
    /// значит на десять минут вычёркивать исправные серверы.
    fn adopt_chosen_server(&mut self, server: ProfileId) {
        let Some(current) = self.state.server().cloned() else {
            return;
        };
        if current == server {
            return;
        }

        tracing::info!(from = %current, to = %server, "проверка выбрала другой сервер");

        let state = match &self.state {
            TunnelState::Connecting { attempt, .. } => TunnelState::Connecting {
                server,
                attempt: *attempt,
            },
            TunnelState::Reconnecting { cause, attempt, .. } => TunnelState::Reconnecting {
                server,
                cause: cause.clone(),
                attempt: *attempt,
            },
            // Попытка уже никому не нужна: её результат отбросят по номеру
            // поколения, и трогать состояние тем более незачем.
            _ => return,
        };
        self.set_state(state);
    }

    /// Пересобирает соединение под изменившиеся настройки.
    ///
    /// # Почему не `begin_reconnect`
    ///
    /// Восстановление — это ответ на неудачу: оно считает попытки, выжидает
    /// паузу и, исчерпав бюджет, уходит на другой сервер. Здесь ничего не
    /// падало, менять сервер не за что, а пауза — это лишние секунды без
    /// связи.
    ///
    /// # Почему не только из `Connected`
    ///
    /// Настройку меняют и не дожидаясь подключения — переключили режим,
    /// передумали, вернули обратно. Прежде такая правка просто не доходила
    /// до ядра: перезапуск делался только из `Connected`, а попытка,
    /// начатая до неё, доигрывала со старой конфигурацией и поднимала
    /// соединение в том режиме, который пользователь уже отменил. Здесь
    /// прежняя попытка вытесняется новой: её результат придёт с устаревшим
    /// номером поколения, будет отброшен и погашен.
    fn reconfigure(&mut self) {
        if !matches!(self.desired, Desired::Connected { .. }) {
            return;
        }
        let Some(target) = self.state.server().cloned() else {
            return;
        };

        // Счётчик попыток обнуляем: смена настроек не должна приближать
        // соединение к смене сервера.
        self.reconnect_attempt = 0;

        // Подключение, ещё не доведённое до конца, остаётся подключением:
        // показать «восстанавливаю» тому, кто ни разу не был подключён,
        // значит сообщить о разрыве, которого не было.
        let state = if self.state.is_connected() {
            TunnelState::Reconnecting {
                server: target.clone(),
                cause: ReconnectCause::Reconfigured,
                attempt: 0,
            }
        } else {
            TunnelState::Connecting {
                server: target.clone(),
                attempt: 1,
            }
        };
        self.set_state(state);

        let previous = self.active.take();
        if let Err(e) = self.launch(target, previous, Duration::ZERO, Selection::Fixed) {
            tracing::error!(error = %e, "не удалось применить настройки к соединению");
            self.fail(e);
        }
    }

    /// Восстанавливает соединение после обрыва.
    ///
    /// Отличается от подключения тем, что запускается не пользователем, а
    /// самим демоном, и потому обязано считаться с его намерением: если
    /// пользователь отключился сам, восстанавливать нечего.
    fn begin_reconnect(&mut self, cause: ReconnectCause) {
        if !matches!(self.desired, Desired::Connected { .. }) {
            return;
        }

        self.reconnect_attempt += 1;
        let attempt = self.reconnect_attempt;

        let current = self.state.server().cloned();

        // Отказал сам сервер — уходим с него сразу, не тратя попытки.
        //
        // Прежде демон трижды бился в упавший сервер и только потом брал
        // следующий по списку. Обе части были неправильны: сервер, который
        // только что уронил соединение, не станет рабочим через секунду, а
        // «следующий по списку» — это не «лучший из имеющихся».
        // Виноват сервер — уходим с него сразу, не тратя попытки.
        //
        // Прежде демон трижды бился в упавший сервер и только потом брал
        // следующий по списку. Обе части были неправильны: сервер, который
        // только что уронил соединение, не станет рабочим через секунду, а
        // «следующий по списку» — это не «лучший из имеющихся».
        //
        // Виновата машина — остаёмся на месте. Прежде здесь стояло «если не
        // выходит и после нескольких попыток, дело всё-таки может быть в
        // сервере», и это был честный домысел: демон не умел отличать одно от
        // другого и после трёх неудач начинал перебирать адреса наугад.
        //
        // Теперь умеет, и домысел стал вредом. Перебор ничего не чинил — гонка
        // и так проверяет восемь серверов на каждом круге и сама назовёт
        // рабочий, — зато менял сервер в шапке окна каждые несколько секунд.
        // Ровно это и выглядело как пляска с серверами при исправном пинге.
        let blamed = server_at_fault(&cause);
        let target = match (blamed, current.as_ref()) {
            (true, Some(failed)) => self.note_failure(failed, &cause),
            // Сервера, на котором стояли, больше нет в списке.
            //
            // Так бывает после обновления подписки со сменой ключей: номер
            // сервера считается и от них, и прежний номер указывает в никуда.
            // Возвращаться на него — это отказ «сервер не найден» и снятое
            // намерение там, где нужен просто лучший из имеющихся.
            (false, Some(id)) if !self.servers.iter().any(|s| &s.id == id) => {
                self.best_by_probe(None)
            }
            _ => current.clone(),
        };

        let Some(target) = target else {
            tracing::error!("восстанавливать соединение не на чем: серверов нет");
            self.fail(TunnelError::NoUsableServers);
            return;
        };

        let delay = reconnect_delay_for(attempt, blamed);

        tracing::warn!(
            attempt,
            server = %target,
            delay_ms = delay.as_millis(),
            ?cause,
            "восстанавливаю соединение"
        );

        self.set_state(TunnelState::Reconnecting {
            server: target.clone(),
            cause,
            attempt,
        });

        let previous = self.active.take();
        if let Err(e) = self.launch(target, previous, delay, Selection::Race) {
            // Ошибка на этом шаге означает негодный профиль, а не обрыв:
            // повторять с тем же результатом смысла нет.
            tracing::error!(error = %e, "не удалось начать восстановление");
            self.fail(e);
        }
    }

    /// Запоминает падение, объявляет его и возвращает, на кого переходить.
    ///
    /// Объявление — отдельное событие, а не строчка в журнале: смена состояния
    /// на «переподключаюсь» не говорит, какой сервер выбыл и почему демон
    /// оказался на другом. Восстановить это потом неоткуда.
    fn note_failure(&mut self, failed: &ProfileId, cause: &ReconnectCause) -> Option<ProfileId> {
        self.failed_servers.insert(failed.clone(), Instant::now());

        let replacement = self.best_replacement(failed);
        let rtt = replacement
            .as_ref()
            .and_then(|id| self.probes.get(id))
            .and_then(|p| p.rtt_ms);

        tracing::warn!(
            server = %failed,
            replacement = replacement.as_ref().map(|id| id.to_string()),
            rtt_ms = rtt,
            ?cause,
            "сервер выбыл"
        );

        self.emit(Event::ServerFailed(sont_ipc::ServerFailure {
            name: self
                .servers
                .iter()
                .find(|s| &s.id == failed)
                .map_or_else(|| failed.to_string(), |s| s.name.clone()),
            server: failed.clone(),
            cause: cause.clone(),
            switching_to: replacement.clone(),
            switching_to_rtt_ms: rtt,
        }));

        // Замены нет — остаёмся на упавшем: единственный сервер подписки
        // лучше, чем отказ от попыток вообще.
        replacement.or_else(|| Some(failed.clone()))
    }

    /// Лучший по замеру сервер на замену упавшему.
    ///
    /// Именно лучший, а не следующий по списку: пользователь остался без сети,
    /// и вести его на случайный сервер, когда известно, какой отвечает быстрее
    /// всех, — значит выбирать худшее из доступного.
    ///
    /// Недавно упавшие исключаются. Если исключить пришлось всех — берём и их:
    /// сервер, лежавший десять минут назад, всё-таки лучше, чем отказ
    /// подключаться вообще.
    fn best_replacement(&self, failed: &ProfileId) -> Option<ProfileId> {
        let fresh: Vec<&ServerProfile> = self
            .candidates()
            .filter(|s| &s.id != failed)
            .filter(|s| !self.recently_failed(&s.id))
            .collect();

        if !fresh.is_empty() {
            return self.best_of(fresh);
        }

        tracing::warn!("все серверы недавно падали, пробую их заново");
        let retry: Vec<&ServerProfile> = self.candidates().filter(|s| &s.id != failed).collect();
        self.best_of(retry)
    }

    /// Лучший по замеру сервер, кроме указанного.
    fn best_by_probe(&self, except: Option<&ProfileId>) -> Option<ProfileId> {
        let pool: Vec<&ServerProfile> = self
            .candidates()
            .filter(|s| except.is_none_or(|id| &s.id != id))
            .collect();
        self.best_of(pool)
    }

    fn best_of(&self, pool: Vec<&ServerProfile>) -> Option<ProfileId> {
        pool.into_iter()
            .min_by_key(|s| {
                self.probes
                    .get(&s.id)
                    // Неизмеренный сервер хуже любого измеренного и отвечающего,
                    // но лучше измеренного и молчащего: про него хотя бы ничего
                    // плохого не известно.
                    .map_or(u32::MAX - 1, ProbeResult::score)
            })
            .map(|s| s.id.clone())
    }

    /// Серверы, среди которых вообще имеет смысл выбирать.
    ///
    /// Единственное место, где применяется фильтр по предпочитаемым
    /// протоколам: разложи его по трём функциям выбора — и они разойдутся,
    /// а пользователь получит «подключаюсь по тому протоколу, который
    /// запретил», причём только в одном из сценариев.
    ///
    /// Пустой список предпочтений означает «все», а не «ни одного».
    fn candidates(&self) -> impl Iterator<Item = &ServerProfile> {
        let preferred = &self.settings.preferred_transports;

        // Предпочтение, не оставившее ни одного сервера, игнорируется.
        //
        // Отказать в подключении, потому что в подписке нет любимого
        // протокола, значит оставить пользователя без сети ради настройки,
        // которую он трактовал как «лучше вот так», а не как «иначе не
        // подключаться».
        let usable = preferred.is_empty()
            || !self
                .servers
                .iter()
                .filter(|s| sont_xray::supports(&s.transport))
                .any(|s| preferred.contains(&s.transport.kind()));

        self.servers
            .iter()
            // Сервер, которого ядро не умеет, не кандидат ни при каких
            // предпочтениях.
            //
            // Раньше он попадал в выбор наравне с прочими, и подключение к
            // нему обрывалось окончательным отказом: «протокол не
            // поддерживается» — приговор профилю, а демон принимал его за
            // приговор всей попытке и снимал намерение. Один такой сервер в
            // подписке выключал автоподключение целиком.
            .filter(|s| sont_xray::supports(&s.transport))
            .filter(move |s| usable || preferred.contains(&s.transport.kind()))
    }

    fn recently_failed(&self, id: &ProfileId) -> bool {
        self.failed_servers
            .get(id)
            .is_some_and(|at| at.elapsed() < FAILED_SERVER_COOLDOWN)
    }

    /// Переводит соединение в отказ и снимает намерение.
    ///
    /// Используется там, где повторять попытку заведомо бесполезно: демон
    /// перестаёт бороться, а пользователь получает причину.
    fn fail(&mut self, error: TunnelError) {
        // Намерение снимается не всегда.
        //
        // Причина отказа бывает внешней и поправимой без участия демона: нет
        // ключа — его добавят, нет серверов — придёт подписка, кончились
        // попытки — вернётся сеть. Сдаться в таких случаях навсегда значит
        // оставить пользователя отключённым до тех пор, пока он не заметит
        // это сам и не нажмёт кнопку. Намерение остаётся, а примиритель
        // вернётся к нему, когда будет с чем работать.
        //
        // А вот незапускающееся ядро — отсутствующий файл, несошедшийся хэш,
        // неподдерживаемый протокол — само не починится, и повторять тут
        // нечего.
        //
        // Именно незапускающееся, а не «не запустившееся в этот раз». Разницу
        // несёт признак `permanent`, и без него здесь пропадало соединение
        // после смены настроек: новое ядро поднималось поверх ещё не
        // отпущенного порта, выходило, отказ считался окончательным — и демон
        // снимал намерение, хотя достаточно было повторить через секунду.
        if matches!(error, TunnelError::CoreStartFailed { permanent: true, .. }) {
            tracing::warn!(%error, "отказ окончательный, намерение снимается");
            self.desired = Desired::Disconnected;
        }
        self.reconnect_attempt = 0;

        // В режиме lockdown блокировка остаётся: соединение не поднялось,
        // и открыть трафик значило бы выпустить его мимо туннеля — ровно то,
        // что пользователь запретил. В `Auto` фильтры снимаются: там договор
        // другой — защищать перерыв в соединении, а не держать машину без
        // сети после того, как демон сдался.
        if !self.settings.firewall.survives_daemon_crash() {
            self.disengage_firewall();
        }

        let blocked = self.firewall.is_some();
        self.set_state(TunnelState::Failed { error, blocked });
    }

    /// Возвращает соединение, которого демон добивается, но не имеет.
    ///
    /// # Зачем отдельно от восстановления
    ///
    /// Восстановление ([`Self::begin_reconnect`]) — ответ на обрыв уже
    /// работавшего соединения, и оно исчерпаемо: бюджет попыток кончается,
    /// демон объявляет отказ. Здесь наоборот — состояние, а не событие:
    /// пользователь хочет соединения, соединения нет, и всё, что нужно, —
    /// периодически проверять, не появилось ли то, чего не хватало.
    ///
    /// Именно это делает добавление первого ключа самодостаточным. Демон
    /// стартовал без подписки, автоподключение не удалось, намерение
    /// осталось; ключ добавлен — подписка прочитана — серверы появились, и
    /// соединение поднимается само, без единого нажатия.
    fn tick_reconcile(&mut self) {
        if !matches!(self.desired, Desired::Connected { .. }) {
            return;
        }
        // Попытка, о которой давно ничего не слышно, — это не идущая работа.
        //
        // Задача, поднимающая ядро, отчитывается всегда: и об удаче, и о любой
        // неудаче. Но погибни она молча — паникой, отменой, чем угодно, — и
        // состояние «подключаюсь» останется навсегда: примиритель считает, что
        // работа идёт, а работать уже некому. Наружу это выглядит как намертво
        // зависшее окно, и выйти из него можно только руками.
        //
        // Сторожевой срок заведомо больше самой длинной законной попытки, поэтому
        // помешать живой работе он не может.
        let stalled = self.state.holds_a_route()
            && !self.state.is_connected()
            && self.last_attempt.elapsed() > STALLED_ATTEMPT;

        if stalled {
            tracing::error!(
                seconds = self.last_attempt.elapsed().as_secs(),
                state = self.state.kind(),
                "попытка подключения не отчиталась — начинаю заново"
            );
        } else {
            // Что-то уже происходит: подключаемся, восстанавливаемся, отключаемся.
            if self.state.holds_a_route() || matches!(self.state, TunnelState::Disconnecting) {
                return;
            }
            if self.last_attempt.elapsed() < RECONCILE_INTERVAL {
                return;
            }
        }
        // Пробовать не на чем — молча ждём дальше. Писать в журнал каждые
        // пятнадцать секунд «серверов нет» бессмысленно: это не событие.
        if self.candidates().next().is_none() {
            return;
        }

        let pinned = match &self.desired {
            Desired::Connected { server } => server.clone(),
            Desired::Disconnected => None,
        };

        tracing::info!("соединения нет, а оно нужно — пробую поднять");
        if let Err(e) = self.begin_connect(pinned) {
            tracing::warn!(error = %e, "попытка не удалась, вернусь позже");
        }
    }

    /// Надзор за поднятым соединением.
    ///
    /// Вызывается из основного цикла. Здесь демон и становится оркестратором:
    /// без этой проверки упавшее ядро остаётся незамеченным навсегда.
    fn supervise(&mut self) {
        if !self.state.is_connected() {
            return;
        }

        // 1. Жив ли процесс ядра.
        if let Some(active) = self.active.as_mut() {
            if let crate::core::Liveness::Exited(code) = active.core.liveness() {
                tracing::warn!(?code, "ядро завершилось само");
                self.begin_reconnect(ReconnectCause::CoreExited { code });
                return;
            }
        }

        // 2. Проводит ли туннель трафик.
        //
        // Проверка не начинается, пока не кончилась предыдущая: её бюджет
        // длиннее интервала, и две проверки разом посчитали бы одну неудачу
        // дважды.
        if self.health_in_flight || self.last_health_check.elapsed() < HEALTH_INTERVAL {
            return;
        }
        self.last_health_check = Instant::now();

        let Some(proxy) = self.proxy.clone() else {
            return;
        };
        let metrics = self.metrics_url.clone();
        let generation = self.generation;
        let tx = self.internal_tx.clone();
        self.health_in_flight = true;

        tokio::spawn(async move {
            let alive = server_responds(&proxy.socks, HEALTH_PROBE_BUDGET).await.is_ok();
            // Счётчик — после запроса: он вбирает весь трафик, прошедший за
            // время проверки, в том числе пока сам запрос висел.
            let downlink = match metrics {
                Some(url) => fetch_counters(&url).await.map(|c| c.downlink),
                None => None,
            };
            let _ = tx
                .send(Internal::HealthChecked {
                    generation,
                    alive,
                    downlink,
                })
                .await;
        });
    }

    /// Обрабатывает результат проверки живости.
    fn apply_health(&mut self, probe_ok: bool, downlink: Option<u64>) {
        self.health_in_flight = false;

        // Байты от сервера за время с прошлой проверки — главный признак жизни.
        //
        // Проверочный запрос каждый раз открывает свежее соединение через всю
        // цепочку: вход, ретранслятор, зарубежный выход, сайт. У пользователя
        // такое холодное соединение занимает от 0,6 до 6 с, а иногда виснет
        // совсем — замер через рабочий туннель это показал на всех адресах, не
        // только на 1.1.1.1. Приложения держат соединения открытыми и этого
        // почти не замечают. А демон, у которого два таких запроса подряд не
        // уложились в срок, рвал рабочий туннель — отсюда «Подключено», через
        // минуту «Восстанавливаю», и дальше круги.
        //
        // Сервер, от которого идут данные, жив — что бы ни случилось с нашим
        // запросом. Мёртвый не присылает ничего.
        let flowing = match (downlink, self.last_health_downlink) {
            (Some(now), Some(before)) => now > before,
            _ => false,
        };
        if downlink.is_some() {
            self.last_health_downlink = downlink;
        }

        if !probe_ok && flowing {
            tracing::info!(
                "проверочный запрос не прошёл, но от сервера идут данные — туннель жив"
            );
        }

        let alive = probe_ok || flowing;
        if alive {
            if self.health_failures > 0 {
                tracing::info!("связь восстановилась сама, переподключение не требуется");
            }
            self.health_failures = 0;
            // Соединение доказало работоспособность — счётчик попыток можно
            // обнулить, иначе следующий обрыв сразу начнётся с длинной паузы.
            self.reconnect_attempt = 0;
            return;
        }

        self.health_failures += 1;
        tracing::warn!(
            failures = self.health_failures,
            "туннель не отвечает на проверку"
        );

        if self.health_failures >= HEALTH_FAILURES_BEFORE_RECONNECT {
            self.begin_reconnect(ReconnectCause::HealthCheckFailed {
                consecutive_failures: self.health_failures,
            });
        }
    }

    fn begin_disconnect(&mut self, reason: DisconnectReason) {
        // Намерение снимаем всегда, даже если состояние уже «отключено»:
        // иначе висящая попытка восстановления продолжит работу вопреки
        // явной команде пользователя.
        self.desired = Desired::Disconnected;
        self.reconnect_attempt = 0;

        // Идущая попытка останавливается сразу. Иначе она доработала бы до
        // конца — и, дойдя до второго этапа, подняла бы адаптер уже после того,
        // как пользователь попросил отключиться.
        if let Some(attempt) = self.in_flight.take() {
            attempt.cancel();
        }

        if matches!(self.state, TunnelState::Disconnected { .. } | TunnelState::Disconnecting) {
            return;
        }

        self.generation += 1;
        let generation = self.generation;

        self.set_state(TunnelState::Disconnecting);
        self.stats = Stats::default();
        self.metrics_url = None;
        self.proxy = None;
        self.last_counters = None;

        let active = self.active.take();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            if let Some(started) = active {
                shutdown_started(started).await;
            }
            let _ = tx.send(Internal::DisconnectFinished { generation }).await;
        });

        // Причину запоминаем сразу: к моменту завершения она уже не изменится.
        self.pending_reason = Some(reason);
    }

    fn handle_internal(&mut self, msg: Internal) {
        match msg {
            Internal::ServersSilent { rejected } => self.refresh_after_silence(rejected),

            Internal::ServerChosen { generation, server } => {
                if generation == self.generation {
                    self.adopt_chosen_server(server);
                }
            }

            Internal::CoreStarted { generation, vouched, result } => {
                if generation != self.generation {
                    tracing::debug!(
                        generation,
                        current = self.generation,
                        "устаревшее подключение отброшено"
                    );
                    // Всё поднятое отменённой попыткой нужно погасить, иначе
                    // маршруты останутся указывать в брошенный туннель.
                    if let Ok(started) = *result {
                        tokio::spawn(shutdown_started(started));
                    }
                    return;
                }

                match *result {
                    Ok(started) => {
                        let Some(server) = self.state.server().cloned() else {
                            tokio::spawn(shutdown_started(started));
                            return;
                        };
                        tracing::info!(pid = started.core.pid(), "туннель поднят");

                        // Адреса берём у поднявшегося ядра, а не у собственных
                        // предположений: только оно знает, какие порты ему в
                        // итоге достались.
                        self.metrics_url =
                            Some(format!("http://{}/debug/vars", started.runtime.metrics_listen));
                        self.proxy = Some(sont_ipc::ProxyEndpoints {
                            http: started.runtime.http_listen.clone(),
                            socks: started.runtime.probe_listen.clone(),
                        });

                        self.active = Some(started);
                        // Соединение состоялось — счётчики надзора начинаются
                        // заново, иначе следующий обрыв унаследует длинную
                        // паузу от прошлых неудач.
                        self.reconnect_attempt = 0;
                        // И отметку о падении снимаем: сервер только что
                        // доказал, что работает, а держать его в опале по
                        // старой памяти значит обходить рабочий сервер.
                        self.failed_servers.remove(&server);
                        self.health_failures = 0;
                        self.last_health_check = Instant::now();

                        let tun = tun_info();
                        // Только теперь у блокировки появляется то, ради чего
                        // она вообще пропускает трафик: адаптер туннеля.
                        // Правила переставляются на месте, не открывая доступ
                        // ни на мгновение.
                        self.sync_firewall(tun.luid);

                        self.set_state(TunnelState::Connected {
                            server,
                            since_unix_ms: now_unix_ms(),
                            tun,
                        });
                    }
                    Err(error) => {
                        tracing::error!(%error, "не удалось поднять туннель");

                        // Повторять есть смысл не всегда: отсутствующая
                        // подписка или неподдерживаемый протокол от повторов
                        // не исправятся, и бесконечный цикл попыток только
                        // скроет от пользователя настоящую причину.
                        if error.is_retryable() && matches!(self.desired, Desired::Connected { .. })
                        {
                            self.begin_reconnect(blame(&error, vouched));
                        } else {
                            self.fail(error);
                        }
                    }
                }
            }

            Internal::SubscriptionFetched { id, result } => self.apply_fetched(id, result),

            Internal::CoreVersion(version) => {
                match &version {
                    Some(v) => tracing::info!(version = %v, "версия ядра"),
                    None => tracing::warn!("не удалось определить версию ядра"),
                }
                self.core_version = version;
            }

            Internal::CoreStats(counters) => self.apply_counters(counters),

            Internal::Probed(results) => self.apply_probes(results),

            Internal::HealthChecked {
                generation,
                alive,
                downlink,
            } => {
                // Результат проверки от прошлого сеанса ничего не говорит о
                // текущем: применять его — значит рвать заново поднятое
                // соединение из-за отказа предыдущего.
                if generation == self.generation {
                    self.apply_health(alive, downlink);
                }
            }

            Internal::DisconnectFinished { generation } => {
                if generation != self.generation {
                    tracing::debug!(generation, current = self.generation, "устаревшее отключение отброшено");
                    return;
                }
                let reason = self.pending_reason.take();
                // Явное отключение снимает блокировку даже в режиме lockdown:
                // пользователь сам попросил вернуть прямой доступ.
                self.disengage_firewall();
                self.set_state(TunnelState::Disconnected {
                    reason,
                    blocked: false,
                });
            }
        }
    }

    /// Выбирает сервер: явный → закреплённый → лучший по замерам.
    fn select_server(&self, explicit: Option<ProfileId>) -> Result<ProfileId, TunnelError> {
        if self.servers.is_empty() {
            return Err(if self.subscriptions.is_empty() {
                TunnelError::NoSubscription
            } else {
                TunnelError::NoUsableServers
            });
        }

        if let Some(id) = explicit {
            return if self.servers.iter().any(|s| s.id == id) {
                Ok(id)
            } else {
                Err(TunnelError::UnknownServer {
                    id: id.to_string(),
                })
            };
        }

        if !self.settings.auto_select_server {
            if let Some(pinned) = &self.settings.pinned_server {
                if self.servers.iter().any(|s| &s.id == pinned) {
                    return Ok(pinned.clone());
                }
                // Закреплённый сервер исчез из подписки — не отказываем
                // пользователю в подключении, а переходим к автовыбору.
                tracing::warn!(server = %pinned, "закреплённый сервер отсутствует, выбирается лучший доступный");
            }
        }

        self.best_by_probe(None).ok_or(TunnelError::NoUsableServers)
    }

    fn set_state(&mut self, state: TunnelState) {
        if self.state == state {
            return;
        }
        tracing::info!(from = self.state.kind(), to = state.kind(), "смена состояния");
        self.state = state.clone();
        // Машинную настройку правим до рассылки события, а не после: пусть
        // к моменту, когда клиенты узнали о смене состояния, система уже знает
        // адрес. Порядок здесь тот же, что и для пользовательских настроек, и
        // по той же причине — окно, в котором адрес не объявлен, приложения
        // используют, чтобы уйти напрямую.
        self.sync_machine_proxy();
        self.emit(Event::StateChanged(state));
    }

    /// Обрывает установленные соединения, чтобы они переехали на прокси.
    ///
    /// Настройка прокси действует только на новые соединения, а открытые живут
    /// часами — и приложение продолжает ходить напрямую при формально
    /// включённом VPN. В режиме туннеля этого не случается: подъём адаптера
    /// меняет маршрут, и прежние соединения рвутся сами. Здесь делаем то же
    /// самое явно. Подробности отбора — в [`crate::connections`].
    fn reset_connections_after_announcement(&mut self) {
        if !matches!(self.settings.mode, sont_core::ConnectionMode::Proxy) {
            return;
        }
        if !self.state.is_connected() {
            return;
        }

        let mut protect = crate::connections::Protected {
            // Свои процессы: оборвать связь ядра с сервером — обрушить туннель,
            // ради которого всё и делается.
            pids: vec![std::process::id()],
            addresses: Vec::new(),
        };
        if let Some(pid) = self.active.as_ref().and_then(|a| a.core.pid()) {
            protect.pids.push(pid);
        }
        // Адрес сервера, если он записан литералом. Для доменного имени
        // хватает защиты по процессу — резолвить здесь ради этого незачем.
        if let Some(server) = self.state.server() {
            if let Some(profile) = self.servers.iter().find(|s| &s.id == server) {
                if let Ok(std::net::IpAddr::V4(ip)) = profile.endpoint.host.parse() {
                    protect.addresses.push(ip);
                }
            }
        }

        let reset = crate::connections::reset_established(&protect);
        if reset > 0 {
            tracing::info!(
                count = reset,
                "соединения оборваны — приложения переоткроют их через прокси"
            );
        } else {
            tracing::debug!("обрывать нечего или не хватило прав");
        }
    }

    /// Какой адрес должна знать машинная настройка прямо сейчас.
    ///
    /// Условия те же, по которым адрес отдаётся клиентам: режим прокси и
    /// удерживаемый путь. Разъехавшись, две настройки указывали бы на разное,
    /// и часть приложений ходила бы через прокси, а часть мимо — причём
    /// понять, какая именно, стало бы невозможно.
    fn desired_machine_proxy(&self) -> Option<String> {
        if !matches!(self.settings.mode, sont_core::ConnectionMode::Proxy) {
            return None;
        }
        if !self.state.holds_a_route() {
            return None;
        }
        self.proxy.as_ref().map(|p| p.http.clone())
    }

    /// Приводит машинную настройку WinHTTP в соответствие с состоянием.
    ///
    /// Делает это демон, а не агент: настройка лежит в `HKLM`, и прав на неё у
    /// непривилегированного процесса нет. Пользовательские настройки, наоборот,
    /// демону недоступны — отсюда и разделение, описанное в [`crate::winhttp`].
    fn sync_machine_proxy(&mut self) {
        let desired = self.desired_machine_proxy();

        if desired == self.machine_proxy {
            return;
        }

        let outcome = match &desired {
            Some(http) => crate::winhttp::apply(http),
            None => crate::winhttp::clear(),
        };

        match outcome {
            Ok(()) => {
                match &desired {
                    Some(http) => tracing::info!(%http, "машинный прокси WinHTTP объявлен"),
                    None => tracing::info!("машинный прокси WinHTTP снят"),
                }
                self.machine_proxy = desired;
            }
            // Не отказ соединения: без прав администратора настройка недоступна,
            // но всё остальное — пользовательские настройки, переменные
            // окружения — работает и без неё.
            Err(e) => tracing::warn!(error = %e, "не удалось изменить машинный прокси WinHTTP"),
        }
    }

    /// Запрашивает у ядра свежие счётчики.
    ///
    /// Сами цифры приходят внутренним сообщением: HTTP-запрос нельзя делать
    /// в цикле supervisor, иначе подвисший служебный порт заморозит обработку
    /// команд пользователя.
    fn tick_stats(&mut self) {
        if !self.state.is_connected() {
            return;
        }
        // Опрашивать ядро, когда статистику никто не слушает, — пустой расход
        // батареи на ноутбуке пользователя.
        if self.events.receiver_count() == 0 {
            return;
        }
        let Some(url) = self.metrics_url.clone() else {
            return;
        };

        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let Some(counters) = fetch_counters(&url).await else {
                return;
            };
            let _ = tx.send(Internal::CoreStats(counters)).await;
        });
    }

    /// Превращает накопительные счётчики ядра в скорость и итоги сессии.
    fn apply_counters(&mut self, now: sont_xray::metrics::Counters) {
        let at = Instant::now();

        if let Some((prev, prev_at)) = self.last_counters {
            let elapsed = at.duration_since(prev_at).as_secs_f64();
            if elapsed > 0.0 {
                // saturating_sub на случай перезапуска ядра: счётчики
                // обнуляются, и разность иначе ушла бы в минус.
                self.stats.up_bps = ((now.uplink.saturating_sub(prev.uplink)) as f64 / elapsed) as u64;
                self.stats.down_bps =
                    ((now.downlink.saturating_sub(prev.downlink)) as f64 / elapsed) as u64;
            }
        }

        self.stats.total_up = now.uplink;
        self.stats.total_down = now.downlink;
        self.stats.rtt_ms = self
            .state
            .server()
            .and_then(|id| self.probes.get(id))
            .and_then(|p| p.rtt_ms);

        self.last_counters = Some((now, at));
        self.emit(Event::Stats(self.stats));
    }

    // ─────────────────────────── прочее ───────────────────────────

    fn snapshot(&self) -> StatusSnapshot {
        StatusSnapshot {
            state: self.state.clone(),
            stats: self.stats,
            subscriptions: self.subscription_statuses(),
            server_count: self.servers.len() as u32,
            // Адреса отдаём и на время переподключения, а не только по факту
            // соединения.
            //
            // На эти секунды прокси действительно не отвечает, и это
            // осознанная плата. Обратный порядок хуже: пока адрес не объявлен,
            // приложения переустанавливают соединения напрямую и остаются так
            // надолго — открытые сокеты на появившийся прокси не переносятся.
            // Отказ в соединении приложение переживает повтором, молчаливый
            // обход VPN — нет.
            proxy: self.state.holds_a_route().then(|| self.proxy.clone()).flatten(),
        }
    }

    fn server_views(&self) -> Vec<ServerView> {
        let mut views: Vec<ServerView> = self
            .servers
            .iter()
            .map(|s| {
                ServerView::from_profile(
                    s,
                    self.probes.get(&s.id).cloned(),
                    self.favorites.contains(&s.id),
                )
            })
            .collect();

        // Порядок: сначала избранное, затем по качеству связи, затем по имени.
        views.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| {
                    let sa = a.probe.as_ref().map_or(u32::MAX, ProbeResult::score);
                    let sb = b.probe.as_ref().map_or(u32::MAX, ProbeResult::score);
                    sa.cmp(&sb)
                })
                .then_with(|| a.name.cmp(&b.name))
        });

        views
    }

    fn emit(&self, event: Event) {
        // Ошибка означает лишь отсутствие подписчиков — это норма.
        let _ = self.events.send(event);
    }
}

/// Находит среди кандидатов сервер, который действительно проводит трафик.
///
/// # Почему не хватает замера
///
/// Замер доказывает только то, что до сервера доходит TCP. Порт отвечает и у
/// сервера с истёкшим ключом, и у сервера, с которого сняли ядро, а Reality на
/// чужой ClientHello отвечает настоящим рукопожатием — он для того и устроен,
/// чтобы выглядеть обычным сайтом. Проверить сервер, не проведя через него
/// запрос, нельзя, и попытки обойтись более дешёвой проверкой отсеивают только
/// совсем мёртвые адреса.
///
/// # Почему это не растягивает подключение
///
/// Запрос проводится не подключением, а гонкой: одно ядро, у каждого кандидата
/// своя дорожка, все дорожки идут одновременно (см. [`crate::race`]). Победитель
/// известен через секунду и известен наверняка — а прежний перебор по одному
/// стоил полного срока подключения на каждом негодном сервере.
///
/// Возвращает выбранный сервер: победителя гонки, а при её неудаче — того, кого
/// назвало ранжирование. Молчание всех дорожек значит «сеть не работает», а не
/// «серверы негодны», и подменять этим причину отказа нельзя.
async fn choose_working(
    launcher: &CoreLauncher,
    pool: Vec<ServerProfile>,
    settings: &Settings,
    config_path: &std::path::Path,
    cancel: &tokio_util::sync::CancellationToken,
) -> Chosen {
    use crate::race::Outcome;

    let raced =
        crate::race::fastest_working(launcher, &pool, config_path, &settings.log_level, cancel)
            .await;
    match raced {
        Outcome::Winner(winner) => match pool.into_iter().find(|s| s.id == winner.server) {
            Some(profile) => Chosen::Vouched(Box::new(profile)),
            None => Chosen::Unknown,
        },
        Outcome::NobodyAnswered { rejected } => Chosen::NoWayOut { rejected },
        Outcome::NotRun => Chosen::Unknown,
    }
}

/// Что проверка выяснила про сервер, который собираются поднимать.
///
/// Различие нужно не для выбора — сервер к этому моменту уже назван, — а для
/// разбора неудачи. Виноват ли сервер в том, что подключение не состоялось,
/// зависит от того, ручался ли за него кто-нибудь секунду назад.
enum Chosen {
    /// Гонка подтвердила сервер: через него только что прошёл настоящий запрос.
    ///
    /// В коробке: профиль весит сотни байт, а остальные варианты — ничего, и
    /// без неё этот вес таскал бы с собой каждый исход.
    Vouched(Box<ServerProfile>),
    /// Гонки не было. Идём по ранжированию, ни за кого не ручаясь.
    Unknown,
    /// Пути наружу нет: гонка состоялась, и не отозвался никто.
    NoWayOut {
        /// Серверы отвергли ключ Reality — см. [`crate::race::Outcome`].
        rejected: bool,
    },
}

/// Поднимает ядро и убеждается, что трафик через туннель действительно ходит.
///
/// Порядок шагов выбран так, чтобы каждая неудача давала пользователю точную
/// причину: сначала генерация конфигурации, затем её проверка самим ядром,
/// затем запуск, и только потом — проверка связности.
async fn start_core(
    launcher: &CoreLauncher,
    profile: &sont_core::ServerProfile,
    peers: &[String],
    settings: &Settings,
    runtime: &sont_xray::RuntimeInfo,
    config_path: &std::path::Path,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<Started, TunnelError> {
    let config = sont_xray::build(profile, settings, runtime).map_err(|e| {
        // Навсегда: конфигурацию для этого профиля не собрать ни сейчас, ни
        // через минуту.
        TunnelError::CoreStartFailed {
            detail: e.to_string(),
            permanent: true,
        }
    })?;

    write_core_config(config_path, &config).map_err(|e| TunnelError::CoreStartFailed {
        // Не навсегда: файл мог быть занят антивирусом или прошлым ядром,
        // которое ещё не отпустило дескриптор.
        detail: format!("не удалось записать конфигурацию ядра: {e}"),
        permanent: false,
    })?;

    let mut core = launcher
        .spawn(config_path)
        .await
        .map_err(|e| TunnelError::CoreStartFailed {
            // Навсегда: бинаря нет, хэш не сошёлся, запускать нечего. Это
            // чинится переустановкой, а не повтором.
            detail: e.to_string(),
            permanent: true,
        })?;

    // Фоновые запросы второго этапа — сразу после запуска ядра, не раньше.
    //
    // Адреса остальных серверов и прямой выход машины нужны только при
    // подъёме сетевого слоя, но ждать их там значило бы прибавить поездку к
    // DNS и один запрос наружу к каждому подключению. Здесь они идут
    // одновременно с первым этапом — а тот сам по себе занимает не меньше
    // секунды, — и в обычном случае не стоят ничего.
    //
    // Не раньше запуска ядра: стояли они в самом начале, и ядро, которое не
    // запускалось вовсе, успевало отправить в сеть поиск имён и запрос к
    // адресу проверки. Толку от них в этом случае нет, а поиск несуществующего
    // имени держит системный поток секунд десять.
    //
    // В режиме прокси обходить нечего — и спрашивать сеть незачем.
    let tunnel_mode = matches!(settings.mode, sont_core::ConnectionMode::Tunnel);
    let peers_lookup = tunnel_mode.then(|| {
        let peers = peers.to_vec();
        let current = profile.endpoint.host.clone();
        tokio::spawn(async move { resolve_peers(&peers, &current).await })
    });
    // Прямой выход обязательно меряется до подъёма сетевого слоя, пока маршрут
    // по умолчанию ещё ведёт в физический интерфейс, — см. [`routed`].
    let direct_lookup = tunnel_mode.then(|| tokio::spawn(direct_egress()));

    let socks: std::net::SocketAddr =
        runtime
            .probe_listen
            .parse()
            .map_err(|_| TunnelError::Internal {
                detail: format!("некорректный адрес SOCKS: {}", runtime.probe_listen),
            })?;

    // ── Этап 1: работает ли сервер ────────────────────────────────────
    //
    // Готовность и смерть ядра — два равноправных исхода, и ждать надо оба.
    // Иначе упавшее через секунду ядро заставляло бы пользователя смотреть
    // на «подключаюсь» все двадцать секунд таймаута.
    let outcome = tokio::select! {
        ready = server_responds(&runtime.probe_listen, READY_TIMEOUT) => ready,
        // Вытеснили — выходим. Ядро погасит обработка ошибки сразу ниже.
        _ = cancel.cancelled() => Err(superseded()),
        code = core.wait_exit() => {
            let reason = core.recent_output();
            let detail = if reason.is_empty() {
                match code {
                    Some(c) => format!("ядро завершилось с кодом {c}"),
                    None => "ядро завершилось".to_owned(),
                }
            } else {
                reason
            };

            return Err(if crate::core::looks_like_permission_error(&detail) {
                // Навсегда: без прав администратора адаптер не создать, и
                // повторы этого не изменят — нужен перезапуск службы.
                TunnelError::CoreStartFailed {
                    detail: "нужны права администратора: создание сетевого адаптера требует их".to_owned(),
                    permanent: true,
                }
            } else {
                // А вот здесь — не навсегда, и это главный случай.
                //
                // Ядро запустилось, значит установка цела. Вышло оно из-за
                // чего-то, что относится к этой попытке: порт ещё держит
                // погашенный экземпляр, TUN-адаптер не успел освободиться,
                // конфигурация переписывалась под ним. Ровно так и выглядит
                // смена настроек, где новое ядро поднимается сразу за старым.
                TunnelError::CoreStartFailed { detail, permanent: false }
            });
        }
    };

    let tunnel_ip = match outcome {
        Ok(ip) => ip,
        Err(e) => {
            core.shutdown().await;
            return Err(e);
        }
    };
    tracing::info!(ip = %tunnel_ip, "сервер отвечает");

    // В режиме прокси на этом всё: сетевой слой не нужен, адаптер не
    // создаётся, права администратора не требуются. Проверять маршрутизацию
    // тоже нечего — трафик пойдёт через прокси только у тех приложений,
    // которые о нём знают.
    if matches!(settings.mode, sont_core::ConnectionMode::Proxy) {
        tracing::info!(
            http = %runtime.http_listen,
            socks = %runtime.probe_listen,
            "режим прокси: сетевой слой не поднимается"
        );
        return Ok(Started {
            core,
            tunnel: None,
            runtime: runtime.clone(),
        });
    }

    // ── Этап 2: поднимаем сетевой слой ────────────────────────────────
    //
    // Адрес сервера обязан идти мимо туннеля, иначе подключение ядра к нему
    // замкнётся само на себя.
    let mut bypass = resolve_bypass(&profile.endpoint.host, SERVER_RESOLVE_TIMEOUT).await;
    if bypass.is_empty() {
        core.shutdown().await;
        return Err(TunnelError::NetworkSetupFailed {
            detail: format!("не удалось определить адрес сервера {}", profile.endpoint.host),
        });
    }

    // Мимо туннеля идут все серверы подписки, а не только текущий.
    //
    // Прежде обходил туннель один сервер — тот, к которому подключались. Всё
    // остальное, включая остальные серверы, уходило в TUN, а там соединение
    // принимает пользовательский стек TCP ещё до того, как что-то уйдёт
    // наружу. Замер задержки поэтому «доходил» до Сеула за миллисекунду: в
    // списке у пользователя стояло 0–1 мс против настоящих 363 мс у текущего.
    //
    // Это не косметика. Ранжирование выворачивалось наизнанку — худшим
    // выглядел единственный честно измеренный сервер, — и на нём держался и
    // выбор замены при падении, и состав гонки. Хуже того, эти числа
    // переживали отключение: восстановление начиналось с заведомо ложной
    // картины.
    //
    // Пускать серверы мимо туннеля безопасно: трафик к ним ведут только само
    // ядро и замеры, пользовательские приложения туда не ходят. И kill-switch
    // уже выпускает их напрямую — см. `allowances`, — так что правило для
    // маршрутов лишь догоняет правило для фильтров.
    if let Some(lookup) = peers_lookup {
        bypass.extend(lookup.await.unwrap_or_default());
    }

    // Сайты из исключений — тоже отдельными маршрутами.
    //
    // Одного правила в ядре для них мало, и это не недосмотр, а устройство
    // режима туннеля. Маршрут по умолчанию ведёт в TUN, значит пакет к
    // сайту попадает в туннель ещё до того, как ядро вообще увидит
    // соединение. Ядро честно отправит его в `direct` — обычным сокетом,
    // пакеты которого снова пойдут по маршруту по умолчанию, то есть опять в
    // TUN. Получается петля, а не прямой доступ.
    //
    // Единственный способ вывести адрес из туннеля — не пускать его туда:
    // отдельный маршрут через физический шлюз, ровно как для самого
    // VPN-сервера.
    //
    // Разрешаются разом: исключений бывает десяток, и по очереди каждое
    // неотвечающее имя добавляло бы к подключению свой срок целиком.
    let hosts = bypass_hosts(settings);
    let resolved = futures_util::future::join_all(
        hosts
            .iter()
            .map(|host| resolve_bypass(host, EXCEPTION_RESOLVE_TIMEOUT)),
    )
    .await;
    for (host, ips) in hosts.iter().zip(resolved) {
        if ips.is_empty() {
            // Не повод отменять подключение: один неразрешившийся домен из
            // списка исключений — это потеря одного исключения, а не связи.
            tracing::warn!(%host, "исключение не добавлено: имя не разрешилось");
            continue;
        }
        tracing::info!(%host, addresses = ips.len(), "исключение уходит мимо туннеля");
        bypass.extend(ips);
    }
    bypass.sort();
    bypass.dedup();

    // Прямой выход дожидаемся здесь, до подъёма адаптера, — и только здесь.
    //
    // После этой строки маршрут по умолчанию уходит в туннель, и запрос,
    // не успевший установить соединение, ответил бы уже выходом туннеля —
    // то есть подменил бы собой то, с чем его потом сравнят.
    let direct_ip = match direct_lookup {
        Some(lookup) => lookup.await.ok().flatten(),
        None => None,
    };

    // Последний момент, когда отменённой попытке нечего прибирать, кроме ядра.
    // Дальше она подняла бы адаптер и перехватила маршрут по умолчанию — у
    // той, что пришла ей на смену.
    if cancel.is_cancelled() {
        core.shutdown().await;
        return Err(superseded());
    }

    let tunnel = match crate::tunnel::Tunnel::start(crate::tunnel::TunnelConfig {
        socks,
        tun_name: runtime.tun_name.clone(),
        mtu: runtime.mtu,
        bypass,
        lan_direct: settings.allow_lan,
    }) {
        Ok(t) => t,
        Err(e) => {
            core.shutdown().await;
            return Err(TunnelError::NetworkSetupFailed {
                detail: e.to_string(),
            });
        }
    };

    // ── Этап 3: пошла ли через туннель система ────────────────────────
    // Короткая передышка вместо фиксированного ожидания.
    //
    // Раньше здесь стояла пауза в две секунды «чтобы маршруты успели». Это
    // была плата за то, что клиент переиспользовал соединение из пула и
    // застревал на старом маршруте навсегда. Пул отключён, каждая попытка
    // открывает новое соединение, поэтому достаточно опрашивать часто — и
    // подключение завершается ровно тогда, когда маршруты реально встали, а
    // не по истечении угаданного срока.
    tokio::time::sleep(SETTLE_GRACE).await;
    tracing::info!("сетевой слой запущен, проверяю маршрутизацию");
    let routing = tokio::select! {
        routed = system_routed_through_tunnel(&tunnel_ip, direct_ip.as_deref()) => routed,
        // Вытеснили, пока ждали маршрутов, — адаптер уже поднят, и снять его
        // обязаны мы: у новой попытки он свой.
        _ = cancel.cancelled() => Err(superseded()),
    };

    match routing {
        Ok(()) => Ok(Started {
            core,
            tunnel: Some(tunnel),
            runtime: runtime.clone(),
        }),
        Err(e) => {
            // Порядок обратный запуску: сначала снимаем маршруты, потом
            // гасим ядро. Иначе останется таблица, указывающая в никуда.
            tunnel.stop().await;
            core.shutdown().await;
            Err(e)
        }
    }
}

/// Отказ попытки, которую вытеснила новая.
///
/// До вызывающего он не дойдёт: поколение уже сменилось, и результат будет
/// отброшен. Нужен он затем, чтобы каждый этап выходил одной и той же дорогой
/// — через свою уборку, — а не своим отдельным путём, где её легко забыть.
fn superseded() -> TunnelError {
    TunnelError::Internal {
        detail: "попытку вытеснила новая".to_owned(),
    }
}

/// Ядро и сетевой слой, поднятые вместе.
pub struct Started {
    pub core: CoreProcess,
    /// `None` в режиме прокси: там адаптер не создаётся.
    pub tunnel: Option<crate::tunnel::Tunnel>,
    /// Адреса, на которых слушает именно это ядро.
    ///
    /// Возвращаются наружу, а не выбираются заранее: пока прежняя сессия не
    /// остановлена, её порты заняты, и выбранный до остановки номер оказался
    /// бы случайным. См. [`Supervisor::launch`].
    pub runtime: sont_xray::RuntimeInfo,
}

/// Останавливает всё поднятое, соблюдая порядок.
///
/// Сначала снимаются маршруты и адаптер, и только потом гасится ядро. Обратный
/// порядок оставил бы систему с таблицей маршрутов, указывающей в туннель,
/// за которым уже никого нет, — то есть без сети.
async fn shutdown_started(started: Started) {
    if let Some(tunnel) = started.tunnel {
        tunnel.stop().await;
    }
    started.core.shutdown().await;
}

/// Определяет адреса сервера, которые должны идти мимо туннеля.
///
/// Для доменного имени берём все адреса, которые вернул резолвер: сервер может
/// отвечать с нескольких, и пропустить хотя бы один значит получить петлю при
/// следующем переподключении.
/// Какие сайты в режиме туннеля надо вывести отдельными маршрутами.
///
/// Только режим `Exclude`: там перечислено то, что идёт мимо туннеля, и это
/// прямо ложится на маршруты. В `Include` перечислено обратное — что идёт
/// **через** туннель, — а «всё остальное мимо» маршрутами не выразить: список
/// адресов интернета конечным не бывает.
///
/// Список программ сюда не попадает и попасть не может: маршрут выбирается по
/// адресу назначения, а не по тому, кто отправитель. Для программ работает
/// только режим прокси.
fn bypass_hosts(settings: &Settings) -> &[String] {
    match settings.split_tunnel.mode {
        sont_core::SplitTunnelMode::Exclude => &settings.split_tunnel.sites,
        _ => &[],
    }
}

/// Предел разрешения имён остальных серверов.
///
/// Короткий: это не адрес текущего сервера, без которого подключиться нельзя, а
/// забота о честности замеров. Не разрешившееся за это время имя просто не
/// попадёт в обход — ценой одного неверного замера, а не задержки подключения.
const PEER_RESOLVE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Адреса остальных серверов подписки, которые надо вывести мимо туннеля.
///
/// Разрешаются разом, а не по одному: подписка на полсотни серверов с именами
/// вместо адресов иначе добавляла бы к каждому подключению по поездке к DNS на
/// сервер. Адреса-литералы — а таких большинство — разрешать не нужно вовсе.
///
/// Текущий сервер пропускается: его адрес уже в списке, и разрешён он там
/// обязательно, с отказом при неудаче. Здесь неудача не отказ.
async fn resolve_peers(hosts: &[String], current: &str) -> Vec<std::net::IpAddr> {
    use futures_util::future::join_all;

    let lookups = hosts.iter().filter(|h| h.as_str() != current).map(|host| async move {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return vec![ip];
        }
        match tokio::time::timeout(PEER_RESOLVE_TIMEOUT, tokio::net::lookup_host((host.as_str(), 0)))
            .await
        {
            Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
            _ => {
                tracing::debug!(%host, "адрес сервера не разрешился, в обход туннеля не попал");
                Vec::new()
            }
        }
    });

    let mut ips: Vec<std::net::IpAddr> = join_all(lookups).await.into_iter().flatten().collect();
    ips.sort();
    ips.dedup();
    ips
}

/// Сколько ждём адрес сервера, к которому подключаемся.
///
/// Без него подключиться нельзя, поэтому срок щедрее, чем у исключений.
const SERVER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(8);

/// Сколько ждём адрес одного сайта из исключений.
const EXCEPTION_RESOLVE_TIMEOUT: Duration = Duration::from_secs(4);

/// Разрешает имя в адреса для маршрутов в обход туннеля.
///
/// # Почему асинхронно и со сроком
///
/// Здесь стоял блокирующий `to_socket_addrs` — прямо в асинхронной попытке
/// подключения, то есть на рабочем потоке рантайма. Пока системный резолвер
/// ждал ответа, поток стоял, а вместе с ним и задачи из его локальной очереди:
/// IPC-сервер, главный цикл. Вызывается это сразу после снятия туннеля, когда
/// DNS ещё смотрит в погашенный адаптер, — и на каждый из десятка сайтов
/// исключений. У пользователя так замер весь демон: машина ушла в режим
/// ожидания посреди переподключения, и почти сутки он не писал в журнал, не
/// отвечал окну и не пытался подключиться снова.
async fn resolve_bypass(host: &str, budget: Duration) -> Vec<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }

    match tokio::time::timeout(budget, tokio::net::lookup_host((host, 0u16))).await {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<std::net::IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Ok(Err(e)) => {
            tracing::error!(%host, error = %e, "не удалось разрешить адрес");
            Vec::new()
        }
        Err(_) => {
            tracing::error!(%host, seconds = budget.as_secs(), "адрес не разрешился за отведённое время");
            Vec::new()
        }
    }
}

/// Снимает счётчики со служебного порта ядра.
///
/// Неудача — обычное дело: порт поднимается не мгновенно, а после остановки
/// ядра его уже нет. Молчаливый `None` здесь правильнее шума в журнале.
async fn fetch_counters(url: &str) -> Option<sont_xray::metrics::Counters> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        // Служебный порт на localhost, системный прокси тут только помешает.
        .no_proxy()
        .build()
        .ok()?;

    let body = client.get(url).send().await.ok()?.text().await.ok()?;
    sont_xray::metrics::parse(&body, "proxy")
}

/// Сколько ждём ответа сервера после запуска ядра.
///
/// Двадцать секунд — две полные попытки по [`PROBE_REQUEST_TIMEOUT`].
///
/// Здесь стояло семь, с обоснованием «рукопожатие Reality на живом сервере
/// укладывается в доли секунды». Это верно для сервера, до которого рукой
/// подать, и неверно для цепочки, какие раздают панели: вход в реле внутри
/// страны, оттуда зарубежный выход, оттуда адрес проверки. Сколько это стоит
/// на самом деле, записано в журнале: у самого быстрого из восьми серверов
/// медиана 1,25 с, 90% — 3,4 с, максимум 4,7 с. Семь секунд при двухсекундных
/// попытках обрывали треть запросов за миг до ответа.
/// Две полные попытки: одна заминка на холодном соединении не должна решать
/// исход этапа.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Сколько ждём, пока система переключится на туннель.
///
/// Маршруты Windows устанавливает быстро, но проверяются они запросом, а
/// запрос идёт по той же цепочке и стоит те же секунды, — см. [`READY_TIMEOUT`].
/// Тоже две полные попытки — запрос идёт той же цепочкой.
const ROUTING_TIMEOUT: Duration = Duration::from_secs(20);

/// Шаг опроса при проверках.
///
/// Подключение завершается по первой удачной попытке, поэтому шаг напрямую
/// определяет, насколько быстро пользователь увидит «Подключено». Частый
/// опрос localhost ничего не стоит.
const READY_INTERVAL: Duration = Duration::from_millis(100);

/// Пауза перед первой проверкой маршрутизации.
///
/// Ровно чтобы сетевой слой успел начать работу, а не «на всякий случай»:
/// дальше решает опрос.
const SETTLE_GRACE: Duration = Duration::from_millis(100);

/// Предел одной попытки проверки.
///
/// Десять секунд, и это не «на всякий случай», а измерение: запрос через
/// цепочку реле → выход → адрес проверки у пользователя занимает до 6,3 с даже
/// через рабочий туннель. Предел обязан быть больше этого, иначе он не
/// отличает медленный путь от мёртвого.
///
/// Здесь стояло две секунды, и это была главная причина долгих подключений.
/// Треть запросов обрывалась прямо перед ответом. Первый этап проваливался
/// сразу после того, как гонка подтвердила тот же сервер; проверка живости
/// рвала рабочий туннель, стоило пути на полминуты замедлиться, — и окно
/// показывало «восстанавливаю» у соединения, которое работало.
///
/// Частые короткие попытки медленный путь не ускоряют: каждая начинает
/// рукопожатие заново, то есть платит за те же поездки туда-обратно, что и
/// оборванная предыдущая. Одна попытка, которой дали дожить, приходит раньше.
/// Замер через рабочий туннель на всех адресах, не только на 1.1.1.1, дал
/// холодные запросы от 0,6 до 6,3 с, и один провисел пятнадцать. Предел в шесть
/// секунд обрывал настоящие ответы — десять пропускает их с запасом.
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Адрес, возвращающий внешний IP обратившегося.
///
/// Обращение идёт по IP-литералу, а не по домену, и это принципиально:
/// проверка выполняется в тот момент, когда системный резолвер уже смотрит в
/// туннель. Запрос к домену тогда упирается в DNS и не выполняется вовсе — а
/// прошлая версия проверки не отличала «не получил ответа» от «получил другой
/// адрес» и в обоих случаях винила посторонний VPN-клиент.
/// Тот же адрес, что загоняется в туннель правилом маршрутизации ядра:
/// разъедься они — и проверка пошла бы мимо туннеля, подтверждая работу
/// того, чего нет.
const IP_ECHO_URL: &str = sont_xray::config::HEALTH_CHECK_URL;

/// Достаёт внешний адрес из ответа вида `ip=203.0.113.5`.
fn parse_echoed_ip(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("ip="))
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
}

/// Этап 1: отвечает ли сервер. Возвращает внешний адрес, видимый через него.
async fn server_responds(probe_listen: &str, budget: Duration) -> Result<String, TunnelError> {
    // Запрос идёт через локальный SOCKS-вход ядра, то есть ровно по пути
    // «клиент → ядро → сервер».
    //
    // Проверять обычным запросом наружу нельзя: пока система не переключилась
    // на TUN, такой запрос уходит через обычный интерфейс и подтверждает
    // связность, которой в туннеле ещё нет. Именно так получалось
    // «Подключено» через сто миллисекунд после старта ядра.
    let proxy = reqwest::Proxy::all(format!("socks5h://{probe_listen}")).map_err(|e| {
        TunnelError::Internal {
            detail: format!("не удалось настроить проверочный прокси: {e}"),
        }
    })?;

    let client = reqwest::Client::builder()
        .timeout(PROBE_REQUEST_TIMEOUT)
        .proxy(proxy)
        .build()
        .map_err(|e| TunnelError::Internal {
            detail: e.to_string(),
        })?;

    // ── Этап 1: работает ли сам сервер ────────────────────────────────
    let deadline = Instant::now() + budget;

    let last_error = loop {
        match echo_once(&client, deadline).await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break e;
                }
                tokio::time::sleep(READY_INTERVAL.min(left)).await;
            }
        }
    };

    tracing::warn!(%last_error, "сервер не отвечает");
    Err(TunnelError::HandshakeTimeout {
        seconds: budget.as_secs(),
    })
}

/// Один запрос к адресу проверки — не дольше, чем осталось до срока этапа.
///
/// Возвращает внешний адрес из ответа или описание отказа.
///
/// # Почему попытка ограничена остатком срока
///
/// Раньше цикл проверял срок только перед началом попытки, а сама она жила
/// своим пределом. Начатая за миг до срока, она перехлёстывала его на целый
/// предел попытки — и сумма этапов переставала помещаться в
/// [`CONNECT_TIMEOUT`]. Тот срабатывал вместо этапов и выбрасывал уже сделанную
/// работу. Здесь предел попытки — меньшее из её собственного и остатка срока,
/// и этап кончается тогда, когда обещал.
async fn echo_once(client: &reqwest::Client, deadline: Instant) -> Result<String, String> {
    let limit = deadline
        .saturating_duration_since(Instant::now())
        .min(PROBE_REQUEST_TIMEOUT);
    if limit.is_zero() {
        return Err("срок этапа вышел".to_owned());
    }

    let attempt = async {
        let response = client.get(IP_ECHO_URL).send().await.map_err(describe)?;
        if !response.status().is_success() {
            return Err(format!("неожиданный код ответа {}", response.status().as_u16()));
        }
        let body = response.text().await.map_err(describe)?;
        parse_echoed_ip(&body).ok_or_else(|| "ответ без адреса".to_owned())
    };

    match tokio::time::timeout(limit, attempt).await {
        Ok(result) => result,
        Err(_) => Err(format!("нет ответа за {:.1} с", limit.as_secs_f32())),
    }
}

/// Текст ошибки со всей цепочкой причин.
///
/// `reqwest` в своём тексте пишет только верхний уровень — «error sending
/// request for url». Настоящая причина лежит ниже, в `source()`: истёк срок,
/// сброшено соединение, отказал SOCKS. Без неё журнал сообщал лишь, что
/// что-то не вышло, и причину долгих подключений приходилось выводить из
/// косвенных признаков — по времени, по совпадениям, по догадкам.
pub(crate) fn describe(error: impl std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(inner) = cause {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        cause = inner.source();
    }
    text
}

/// Этап 3: пошёл ли системный трафик через туннель.
///
/// Проверка сервера доказывает лишь его исправность. Если маршруты не
/// применились, обычный трафик по-прежнему идёт мимо, и объявлять соединение
/// установленным нельзя: пользователь увидит «Подключено» при неработающем VPN.
/// Прошёл ли системный трафик через туннель — по одному ответу системы.
///
/// # Почему не просто `system_ip == tunnel_ip`
///
/// Так было, и так проверка врала. Она сравнивала адрес, с которым в интернет
/// вышел запрос через ядро, с адресом, с которым вышел запрос системы, — и
/// ждала совпадения. Но у многих провайдеров выход не один, а целый пул: один и
/// тот же сервер у пользователя выходил то с 185.229.191.52, то с .71, то с
/// 79.127.239.84, то с 89.187.174.104 — каждое соединение со своего адреса.
/// Два независимых образца из такого пула совпадают только случайно. Проверка
/// превращалась в монетку: система уже шла через туннель, маршрут работал, а
/// демон объявлял «маршрут удерживает кто-то ещё» и шёл на новый круг. В
/// режиме прокси этой проверки нет вовсе — отсюда «через туннель подключается
/// только после прокси».
///
/// # Как теперь
///
/// Сравнивается не выход туннеля с выходом системы, а выход системы до
/// туннеля с выходом после. Первый — адрес провайдера пользователя, и он
/// постоянен. Если после подъёма сетевого слоя система выходит в интернет уже
/// не с него, её трафик больше не идёт напрямую, и больше идти ему некуда,
/// кроме как через туннель.
///
/// Совпадение с выходом туннеля по-прежнему засчитывается — оно доказывает то
/// же самое, просто не всегда случается.
fn routed(system_ip: &str, tunnel_ip: &str, direct_ip: Option<&str>) -> bool {
    system_ip == tunnel_ip || direct_ip.is_some_and(|direct| system_ip != direct)
}

/// Внешний адрес, с которым машина выходит в интернет напрямую.
///
/// Меряется до подъёма сетевого слоя, пока маршрут по умолчанию ведёт в
/// физический интерфейс, — см. [`routed`]. `None` — узнать не удалось: сеть
/// отказала или ответ пришёл без адреса. Тогда проверка маршрутизации
/// откатывается к прежнему, более строгому правилу.
async fn direct_egress() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(PROBE_REQUEST_TIMEOUT)
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()
        .ok()?;
    let body = client.get(IP_ECHO_URL).send().await.ok()?.text().await.ok()?;
    parse_echoed_ip(&body)
}

async fn system_routed_through_tunnel(
    tunnel_ip: &str,
    direct_ip: Option<&str>,
) -> Result<(), TunnelError> {
    let direct = reqwest::Client::builder()
        .timeout(PROBE_REQUEST_TIMEOUT)
        .no_proxy()
        // Каждая попытка обязана открывать новое соединение.
        //
        // Проверка начинается сразу после запуска сетевого слоя, и первый
        // запрос успевает уйти до того, как применились маршруты. Windows не
        // переносит уже установленные соединения на новый маршрут, поэтому
        // переиспользованное из пула соединение навсегда остаётся вне
        // туннеля — и цикл повторов превращается в переспрашивание по одному
        // и тому же каналу с заведомо одинаковым ответом.
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| TunnelError::Internal {
            detail: e.to_string(),
        })?;

    let deadline = Instant::now() + ROUTING_TIMEOUT;
    // Различаем два принципиально разных исхода: система ответила чужим
    // адресом (маршрутизация не применилась) или не ответила совсем (скорее
    // всего сломан путь наружу). Валить их в одну ошибку значит отправлять
    // пользователя чинить не то.
    let mut system_ip: Option<String> = None;
    let mut last_error = String::from("ответа нет");

    loop {
        match echo_once(&direct, deadline).await {
            Ok(ip) => {
                if routed(&ip, tunnel_ip, direct_ip) {
                    tracing::info!(%ip, "маршрутизация применилась");
                    return Ok(());
                }
                tracing::debug!(system = %ip, tunnel = %tunnel_ip, "система идёт мимо туннеля");
                system_ip = Some(ip);
            }
            Err(e) => last_error = e,
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        tokio::time::sleep(READY_INTERVAL.min(left)).await;
    }

    // Таблицу маршрутов показываем до остановки ядра: после его завершения
    // маршруты исчезнут вместе с интерфейсом, и понять, кто выиграл маршрут
    // по умолчанию, будет уже нельзя.
    log_default_routes().await;

    match system_ip {
        Some(ip) => {
            tracing::warn!(
                system = %ip,
                tunnel = %tunnel_ip,
                direct = direct_ip.unwrap_or("—"),
                "маршрутизация не применилась"
            );
            Err(TunnelError::NetworkSetupFailed {
                detail: if direct_ip == Some(ip.as_str()) {
                    // Самое определённое, что можно сказать: система выходит
                    // ровно так же, как до подъёма туннеля.
                    format!(
                        "трафик системы по-прежнему выходит напрямую, адресом {ip} — \
                         маршрут по умолчанию удерживает кто-то ещё"
                    )
                } else {
                    format!(
                        "трафик системы выходит адресом {ip} вместо {tunnel_ip} — \
                         маршрут по умолчанию удерживает кто-то ещё"
                    )
                },
            })
        }
        None => {
            tracing::warn!(%last_error, "система не смогла выйти наружу");
            Err(TunnelError::NetworkSetupFailed {
                detail: format!("трафик системы не проходит наружу: {last_error}"),
            })
        }
    }
}

/// Выводит в журнал текущие маршруты по умолчанию.
///
/// Диагностика на случай, когда туннель поднят, а трафик идёт мимо: по этому
/// выводу видно, какой интерфейс и с какой метрикой удерживает маршрут.
async fn log_default_routes() {
    // Без фильтра по адресу назначения: фильтр `0.0.0.0` показывает только
    // маршрут по умолчанию и скрывает половины `/1`, ради которых всё и
    // затевалось. Заголовки таблицы локализованы и в журнале выглядят
    // мусором, но строки с адресами и метриками — чистый ASCII и читаются.
    #[cfg(windows)]
    let mut command = {
        let mut c = tokio::process::Command::new("route.exe");
        c.args(["print", "-4"]);
        c
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut c = tokio::process::Command::new("ip");
        c.args(["route", "show", "default"]);
        c
    };

    match command.output().await {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let line = line.trim();
                // Оставляем только содержательные строки: заголовки в
                // локализованной кодировке всё равно нечитаемы, а строки с
                // маршрутами и списком интерфейсов состоят из ASCII.
                let useful = line.contains('.')
                    && line.chars().any(|c| c.is_ascii_digit())
                    && !line.starts_with('=');
                if useful {
                    tracing::info!(target: "routes", "{line}");
                }
            }
        }
        Err(e) => tracing::debug!(error = %e, "не удалось получить таблицу маршрутов"),
    }
}

/// Читает подписки с диска, при необходимости перенося прежнюю раскладку.
///
/// Перенос не роскошь: ключ подписки — это платный доступ пользователя,
/// который он вводил вручную. Потерять его из-за того, что у нас поменялась
/// структура файлов, недопустимо.
fn load_subscriptions(config: &SupervisorConfig) -> Vec<SubscriptionEntry> {
    if let Some(entries) = secrets::load_json::<Vec<SubscriptionEntry>>(&config.subscriptions_path) {
        return entries;
    }

    let migrated = migrate_single_subscription(config);
    if migrated.is_empty() {
        return migrated;
    }

    tracing::info!("подписка перенесена в новый формат хранения");
    if let Err(e) = secrets::store_json(&config.subscriptions_path, &migrated) {
        // Не теряем то, что уже прочитали: в этот запуск подписка работает, а
        // старые файлы остаются на месте и попробуем снова при следующем.
        tracing::error!(error = %e, "не удалось сохранить перенесённую подписку");
        return migrated;
    }

    // Старое убираем только после успешной записи нового — иначе неудачная
    // запись оставила бы пользователя вообще без ключа.
    let _ = secrets::clear(&config.legacy_subscription_path);
    let _ = secrets::clear(&config.legacy_servers_cache_path);

    migrated
}

/// Собирает запись из файлов прежней раскладки.
fn migrate_single_subscription(config: &SupervisorConfig) -> Vec<SubscriptionEntry> {
    let secret = match secrets::load(&config.legacy_subscription_path) {
        Ok(Some(secret)) => secret,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::error!(error = %e, "не удалось прочитать сохранённый ключ подписки");
            return Vec::new();
        }
    };

    // Разобранные серверы могли и не сохраниться — тогда запись всё равно
    // осмысленна: ключ есть, серверы придут с первым обновлением.
    let cached = secrets::load_json::<LegacyCachedSubscription>(&config.legacy_servers_cache_path);

    let id = SubscriptionId::from_url(secret.expose());
    vec![SubscriptionEntry {
        masked_url: secret.masked(),
        profiles: cached
            .as_ref()
            .filter(|c| c.id == id)
            .map(|c| c.profiles.clone())
            .unwrap_or_default(),
        info: cached
            .filter(|c| c.id == id)
            .map(|c| c.info)
            .unwrap_or_default(),
        id,
        secret,
    }]
}

/// Виноват ли в переподключении сам сервер.
///
/// Различие определяет, менять ли сервер. Упавшее ядро и молчащий туннель —
/// это про сервер. Пропавшая сеть и выход из сна — про машину: на другом
/// сервере они повторятся один в один, а пользователь получит смену адреса
/// вместо соединения.
/// Кого винить в том, что подключение не состоялось.
///
/// # Зачем это отдельное решение
///
/// Прежде здесь стояла константа: любая неудачная попытка объявлялась
/// `CoreExited`, то есть виной сервера. Из этого выходила самая дорогая
/// поломка, какая была у демона.
///
/// Отказывает-то обычно машина. Маршрут по умолчанию удерживает погашенный
/// туннель, адаптер не успел подняться, ядро вышло, не поделив порт с
/// предшественником — на любом другом сервере всё это повторится один в один.
/// А демон записывал сервер в отказавшие, сажал его в штрафной ящик на десять
/// минут и уходил к следующему. Тот падал так же, и следующий, и следующий:
/// в журнале это выглядит как `checked=8, 8, 7, 6, 5, 4, 3, 2` — пул
/// кандидатов таял на глазах, пока гонке не переставало хватать участников.
/// Каждый круг стоил около двадцати секунд, кругов набиралось с десяток, и
/// подключение растягивалось на минуты. Со стороны — «агент пляшет с
/// серверами», хотя пинг у всех прекрасный.
///
/// # Как решается теперь
///
/// Сервер виноват ровно в одном случае: за него никто не ручался, и он не
/// ответил. Если гонка секунду назад провела через него настоящий запрос, то
/// он исправен по определению — что бы ни сломалось дальше, сломалось оно на
/// этой машине.
fn blame(error: &TunnelError, vouched: bool) -> ReconnectCause {
    let server_silent = matches!(error, TunnelError::HandshakeTimeout { .. });

    if server_silent && !vouched {
        ReconnectCause::CoreExited { code: None }
    } else {
        // Сеть машины — общее имя для всего, что не про сервер: маршруты,
        // адаптер, не поднявшееся ядро, а также молчание сервера, который
        // только что доказал обратное.
        ReconnectCause::NetworkChanged
    }
}

fn server_at_fault(cause: &ReconnectCause) -> bool {
    match cause {
        ReconnectCause::CoreExited { .. } | ReconnectCause::HealthCheckFailed { .. } => true,
        ReconnectCause::NetworkChanged
        | ReconnectCause::SystemResumed
        | ReconnectCause::ServerSwitched
        // Смена настроек тем более не вина сервера: он исправен, просто
        // конфигурация ядра собрана по старым значениям.
        | ReconnectCause::Reconfigured
        // Переход на более быстрый сервер — не отказ текущего: он работает,
        // просто нашёлся лучше. Записать его в упавшие значило бы посадить
        // рабочий сервер в штрафной ящик на десять минут.
        | ReconnectCause::BetterServerFound { .. } => false,
    }
}

/// Общий список серверов из всех подписок.
///
/// Порядок подписок задаёт приоритет: сервер, встретившийся в двух, берётся из
/// той, что добавлена раньше. Дубликаты по `id` — не редкость: панели
/// перепродают одни и те же узлы, а id считается от адреса и учётных данных.
fn merge_servers(subscriptions: &[SubscriptionEntry]) -> Vec<ServerProfile> {
    let mut seen: HashSet<ProfileId> = HashSet::new();
    let mut servers = Vec::new();

    for entry in subscriptions {
        for profile in &entry.profiles {
            if seen.insert(profile.id.clone()) {
                servers.push(profile.clone());
            }
        }
    }

    servers
}

fn runtime_info(settings: &Settings) -> sont_xray::RuntimeInfo {
    sont_xray::RuntimeInfo {
        log_level: settings.log_level.clone(),
        // Служебный порт статистики наружу не объявляется: его адрес живёт
        // внутри демона, и постоянство ему ни к чему.
        metrics_listen: format!("127.0.0.1:{}", pick_free_port()),
        // А вот адреса прокси пользователь видит и настраивает по ним
        // приложения — их держим постоянными, насколько это возможно.
        //
        // Вызывать эту функцию следует только после остановки прежнего ядра:
        // иначе предпочитаемые порты заняты им же, и «постоянные» адреса
        // меняются на каждом переподключении.
        probe_listen: format!("127.0.0.1:{}", preferred_or_free_port(PREFERRED_SOCKS_PORT)),
        // Если порт занят кем-то посторонним — берём любой свободный: упереться
        // в это и вовсе не подключиться было бы хуже. Агент в сеансе
        // пользователя переприменяет настройки при каждой смене состояния,
        // поэтому смену порта система переживает.
        http_listen: format!("127.0.0.1:{}", preferred_or_free_port(PREFERRED_HTTP_PORT)),
        ..Default::default()
    }
}

/// Подбирает свободный порт для служебного интерфейса ядра.
///
/// Между освобождением порта здесь и его занятием ядром есть зазор, в который
/// теоретически может влезть другой процесс. Для локального служебного порта
/// это приемлемо: неудачу мы увидим сразу при запуске ядра, а фиксированный
/// номер порождал бы конфликт при каждом повторном подключении.
/// Предпочитаемый порт локального HTTP-прокси.
const PREFERRED_HTTP_PORT: u16 = 18966;
/// Предпочитаемый порт локального SOCKS.
const PREFERRED_SOCKS_PORT: u16 = 18965;

/// Возвращает предпочитаемый порт, если он свободен, иначе любой свободный.
fn preferred_or_free_port(preferred: u16) -> u16 {
    match std::net::TcpListener::bind(("127.0.0.1", preferred)) {
        Ok(listener) => {
            drop(listener);
            preferred
        }
        Err(_) => {
            let port = pick_free_port();
            tracing::info!(preferred, chosen = port, "предпочитаемый порт занят");
            port
        }
    }
}

pub fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|addr| addr.port())
        .unwrap_or(18964)
}

/// Что сообщить клиентам о сетевом адаптере.
///
/// Имя и MTU берутся из умолчаний ядра. Портов эта функция не касается
/// намеренно: раньше она собирала полный `RuntimeInfo` и на каждом переходе в
/// «подключено» занимала и отпускала три сокета — попутно записывая в журнал
/// «предпочитаемый порт занят» про порт, который сама же и заняла, и сообщая
/// клиентам номера, не имеющие отношения к работающему ядру.
fn tun_info() -> TunInfo {
    let runtime = sont_xray::RuntimeInfo::default();
    TunInfo {
        name: runtime.tun_name,
        // Индекс и LUID интерфейса понадобятся слою firewall в фазе 4;
        // до тех пор их незачем добывать.
        index: 0,
        luid: None,
        // Адрес адаптеру назначает сетевой слой, а не мы.
        addresses: Vec::new(),
        mtu: u32::from(runtime.mtu),
    }
}

/// Пишет конфигурацию ядра.
///
/// Файл содержит учётные данные сервера, поэтому кладётся в каталог демона с
/// ограниченным доступом и перезаписывается атомарно — иначе ядро может
/// прочитать его наполовину записанным.
pub fn write_core_config(path: &std::path::Path, config: &serde_json::Value) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(config)?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, path)
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::FirewallMode;

    /// Успешный запуск ядра без настоящего процесса.
    ///
    /// Тесты здесь проверяют конечный автомат, а не Xray: поднимать ради них
    /// реальное ядро значило бы требовать сеть, права администратора и TUN.
    fn core_started(generation: u64) -> Internal {
        Internal::CoreStarted {
            generation,
            vouched: true,
            result: Box::new(Ok(Started {
                core: CoreProcess::placeholder(),
                tunnel: Some(crate::tunnel::Tunnel::placeholder()),
                runtime: sont_xray::RuntimeInfo::default(),
            })),
        }
    }

    /// Supervisor с временным каталогом состояния.
    fn make(demo_servers: bool) -> (Supervisor, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (events, _rx) = broadcast::channel(64);
        let sup = Supervisor::new(
            SupervisorConfig {
                demo_servers,
                settings_path: dir.path().join("settings.json"),
                favorites_path: dir.path().join("favorites.json"),
                subscriptions_path: dir.path().join("subscriptions.bin"),
                legacy_subscription_path: dir.path().join("subscription.bin"),
                legacy_servers_cache_path: dir.path().join("servers.bin"),
                core_binary: dir.path().join("xray-отсутствует.exe"),
                core_config_path: dir.path().join("xray-config.json"),
            },
            events,
            LogBuffer::new(),
        );
        (sup, dir)
    }

    #[tokio::test]
    async fn connect_without_subscription_is_rejected() {
        let (mut sup, _dir) = make(false);
        let response = sup.handle(Request::Connect { server: None });
        assert_eq!(
            response,
            Response::Error(IpcError::Tunnel(TunnelError::NoSubscription))
        );
        assert_eq!(sup.state.kind(), "disconnected");
    }

    #[tokio::test]
    async fn connect_moves_through_connecting_to_connected() {
        let (mut sup, _dir) = make(true);

        assert_eq!(sup.handle(Request::Connect { server: None }), Response::Accepted);
        assert_eq!(sup.state.kind(), "connecting");
        assert!(sup.state.is_blocked(), "во время подключения трафик закрыт");

        let generation = sup.generation;
        sup.handle_internal(core_started(generation));
        assert_eq!(sup.state.kind(), "connected");
        assert!(!sup.state.is_blocked());
    }

    #[tokio::test]
    async fn reconnecting_while_connected_hands_off_the_previous_session() {
        // Типичный путь применить смену режима — переподключиться, не
        // отключаясь явно. Прежнюю сессию (процесс ядра, TUN-адаптер) нельзя
        // просто забыть: `CoreProcess` и `Tunnel` не останавливаются в
        // `Drop`, и она осталась бы висеть — снять её после этого нечем.
        let (mut sup, _dir) = make(true);

        sup.handle(Request::Connect { server: None });
        let g1 = sup.generation;
        sup.handle_internal(core_started(g1));
        assert!(sup.active.is_some());

        sup.handle(Request::Connect { server: None });
        assert!(
            sup.active.is_none(),
            "прежняя сессия должна уйти на остановку, а не быть заброшенной"
        );

        let g2 = sup.generation;
        assert_ne!(g1, g2, "повторное подключение обязано начать новое поколение");
        sup.handle_internal(core_started(g2));
        assert!(sup.active.is_some());
    }

    /// Переводит настройки в режим прокси.
    fn set_proxy_mode(sup: &mut Supervisor) {
        sup.handle(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                mode: Some(sont_core::ConnectionMode::Proxy),
                ..Default::default()
            },
        });
    }

    #[tokio::test]
    async fn machine_proxy_follows_the_same_rule_as_the_user_one() {
        // Настроек прокси в Windows три, и читают их разные семейства
        // программ. Разъедься они — часть приложений пойдёт через прокси, а
        // часть мимо, и понять, какая именно, будет невозможно.
        let (mut sup, _dir) = make(true);
        set_proxy_mode(&mut sup);

        // Пути ещё нет — объявлять нечего.
        assert_eq!(sup.desired_machine_proxy(), None);

        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));

        let announced = sup.desired_machine_proxy();
        assert_eq!(
            announced.as_deref(),
            sup.snapshot().proxy.as_ref().map(|p| p.http.as_str()),
            "машинная и пользовательская настройки обязаны знать один адрес"
        );
        assert!(announced.is_some());
    }

    #[tokio::test]
    async fn machine_proxy_is_not_announced_in_tunnel_mode() {
        // В туннеле трафик идёт через адаптер, и лишняя настройка только
        // заставит службы ходить через прокси поверх туннеля.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));

        assert!(sup.state.is_connected());
        assert_eq!(sup.desired_machine_proxy(), None);
    }

    #[tokio::test]
    async fn machine_proxy_is_taken_back_on_disconnect() {
        // Оставленный машинный адрес ломает обновления системы, и связать это
        // с выключенным накануне VPN пользователь не сможет.
        let (mut sup, _dir) = make(true);
        set_proxy_mode(&mut sup);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        assert!(sup.desired_machine_proxy().is_some());

        sup.handle(Request::Disconnect);
        assert_eq!(sup.desired_machine_proxy(), None);
    }

    #[tokio::test]
    async fn machine_proxy_survives_a_reconnect() {
        // Ровно то же требование, что и к пользовательской настройке: снятый
        // на время переподключения адрес — это окно, в которое приложения
        // уходят напрямую и там остаются.
        let (mut sup, _dir) = make(true);
        set_proxy_mode(&mut sup);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        let during = sup.desired_machine_proxy();

        sup.handle(Request::Connect { server: None });
        assert_eq!(sup.desired_machine_proxy(), during);
    }

    #[tokio::test]
    async fn proxy_addresses_survive_a_reconnect() {
        // Самое важное свойство режима прокси: адрес объявлен непрерывно.
        //
        // Стоит перестать объявлять его на время переподключения — и в это
        // окно приложения переустановят соединения напрямую. Обратно на
        // прокси они уже не вернутся: открытые сокеты никто не переносит, а
        // HTTP/2 и WebSocket живут часами.
        let (mut sup, _dir) = make(true);

        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        let during_connection = sup.snapshot().proxy;
        assert!(during_connection.is_some());

        // Переподключение: ядро упало и поднимается заново.
        sup.handle(Request::Connect { server: None });
        assert_eq!(
            sup.snapshot().proxy,
            during_connection,
            "на время переподключения адрес прокси обязан оставаться объявленным"
        );
    }

    #[tokio::test]
    async fn disconnecting_takes_the_proxy_address_back() {
        // Обратное тоже обязано работать: адрес, за которым больше никого не
        // будет, для пользователя выглядит как полностью пропавший интернет.
        let (mut sup, _dir) = make(true);

        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        assert!(sup.snapshot().proxy.is_some());

        sup.handle(Request::Disconnect);
        assert_eq!(
            sup.snapshot().proxy,
            None,
            "после команды отключения адрес объявлять нечем"
        );
    }

    #[tokio::test]
    async fn proxy_addresses_are_published_only_after_the_core_reports_them() {
        // Порты выбирает фоновая задача — уже после остановки прежней сессии,
        // иначе предпочитаемые номера заняты ею же. Значит, до готовности ядра
        // адресов попросту нет, и выдавать предполагаемые нельзя: клиент
        // пропишет в настройки системы порт, который ядру мог и не достаться.
        let (mut sup, _dir) = make(true);

        sup.handle(Request::Connect { server: None });
        assert!(
            sup.proxy.is_none(),
            "во время подключения адреса ядра ещё неизвестны"
        );

        let generation = sup.generation;
        sup.handle_internal(core_started(generation));

        let expected = sont_xray::RuntimeInfo::default();
        let proxy = sup.proxy.clone().expect("после старта адреса обязаны быть");
        assert_eq!(proxy.http, expected.http_listen);
        assert_eq!(proxy.socks, expected.probe_listen);
        assert_eq!(
            sup.metrics_url.as_deref(),
            Some(format!("http://{}/debug/vars", expected.metrics_listen).as_str()),
        );
    }

    #[test]
    fn preferred_proxy_ports_do_not_collide() {
        // Оба входа поднимает одно ядро: совпади номера — оно не стартует.
        assert_ne!(PREFERRED_HTTP_PORT, PREFERRED_SOCKS_PORT);
    }

    #[tokio::test]
    async fn stale_connect_result_does_not_resurrect_cancelled_session() {
        // Пользователь нажал «подключить», передумал и нажал «отключить»
        // раньше, чем туннель поднялся. Запоздавший результат первой попытки
        // не должен вернуть соединение.
        let (mut sup, _dir) = make(true);

        sup.handle(Request::Connect { server: None });
        let stale = sup.generation;

        sup.handle(Request::Disconnect);
        assert_eq!(sup.state.kind(), "disconnecting");

        sup.handle_internal(core_started(stale));
        assert_eq!(
            sup.state.kind(),
            "disconnecting",
            "устаревший результат подключения был применён"
        );

        let current = sup.generation;
        sup.handle_internal(Internal::DisconnectFinished { generation: current });
        assert_eq!(sup.state.kind(), "disconnected");
    }

    #[tokio::test]
    async fn failure_does_not_claim_a_block_that_does_not_exist() {
        // Состояние сообщает о блокировке только тогда, когда фильтры
        // действительно стоят. Здесь до подключения дело не дошло, ставить
        // их было некому — и «трафик заблокирован» отправило бы пользователя
        // искать несуществующую блокировку вместо настоящей причины отказа.
        let (mut sup, _dir) = make(true);
        sup.settings.firewall = FirewallMode::Lockdown;

        sup.fail(TunnelError::NoUsableServers);

        assert_eq!(sup.state.kind(), "failed");
        assert!(
            !sup.state.is_blocked(),
            "объявлена блокировка, которой нечем удержать"
        );
    }

    #[tokio::test]
    async fn lockdown_keeps_the_block_after_a_failure() {
        // Соединение не поднялось, а трафик всё равно закрыт — в этом и
        // смысл режима: выпустить его напрямую значило бы сделать ровно то,
        // что пользователь запретил.
        let (mut sup, _dir) = make(true);
        sup.settings.firewall = FirewallMode::Lockdown;

        sup.handle(Request::Connect { server: None });
        assert!(sup.firewall.is_some(), "фильтры ставятся до запуска ядра");

        sup.fail(TunnelError::NoUsableServers);

        assert_eq!(sup.state.kind(), "failed");
        assert!(sup.state.is_blocked(), "lockdown обязан удержать блокировку");
    }

    #[tokio::test]
    async fn auto_mode_opens_the_traffic_when_the_daemon_gives_up() {
        // Договор `Auto` другой: защищать перерыв в соединении, а не держать
        // машину без сети после того, как демон перестал бороться.
        let (mut sup, _dir) = make(true);
        sup.settings.firewall = FirewallMode::Auto;

        sup.handle(Request::Connect { server: None });
        assert!(sup.firewall.is_some());

        sup.fail(TunnelError::NoUsableServers);

        assert!(sup.firewall.is_none(), "фильтры остались висеть");
        assert!(!sup.state.is_blocked());
    }

    #[tokio::test]
    async fn turning_the_kill_switch_off_lifts_the_block() {
        let (mut sup, _dir) = make(true);
        sup.settings.firewall = FirewallMode::Lockdown;
        sup.handle(Request::Connect { server: None });
        assert!(sup.firewall.is_some());

        sup.handle(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                firewall: Some(FirewallMode::Off),
                ..Default::default()
            },
        });

        assert!(sup.firewall.is_none(), "выключенный kill-switch продолжает блокировать");
    }

    #[tokio::test]
    async fn the_kill_switch_does_not_cut_the_net_of_a_disconnected_user() {
        // Пользователь отключён и включает блокировку «на будущее». Ставить
        // фильтры прямо сейчас значило бы отрезать ему сеть настройкой,
        // которая должна была её всего лишь защитить.
        let (mut sup, _dir) = make(true);

        sup.handle(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                firewall: Some(FirewallMode::Lockdown),
                ..Default::default()
            },
        });

        assert!(sup.firewall.is_none());
        assert!(!sup.state.is_blocked());
    }

    #[tokio::test]
    async fn explicit_disconnect_lifts_the_block_even_in_lockdown() {
        let (mut sup, _dir) = make(true);
        sup.settings.firewall = FirewallMode::Lockdown;

        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));

        sup.handle(Request::Disconnect);
        let g = sup.generation;
        sup.handle_internal(Internal::DisconnectFinished { generation: g });

        assert!(
            !sup.state.is_blocked(),
            "пользователь явно попросил вернуть прямой доступ"
        );
        assert!(matches!(
            sup.state,
            TunnelState::Disconnected {
                reason: Some(DisconnectReason::UserRequest),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unknown_server_is_reported() {
        let (mut sup, _dir) = make(true);
        let response = sup.handle(Request::Connect {
            server: Some(ProfileId::from_raw("не существует")),
        });
        assert!(matches!(
            response,
            Response::Error(IpcError::Tunnel(TunnelError::UnknownServer { .. }))
        ));
    }

    #[tokio::test]
    async fn auto_selection_prefers_the_best_probe() {
        let (mut sup, _dir) = make(true);

        // Делаем один сервер заведомо лучшим.
        let best = sup.servers[2].id.clone();
        for (id, probe) in sup.probes.iter_mut() {
            probe.rtt_ms = Some(if *id == best { 5 } else { 400 });
        }

        assert_eq!(sup.select_server(None).unwrap(), best);
    }

    #[tokio::test]
    async fn unreachable_servers_lose_to_reachable_ones() {
        let (mut sup, _dir) = make(true);
        let reachable = sup.servers[1].id.clone();
        for (id, probe) in sup.probes.iter_mut() {
            probe.rtt_ms = if *id == reachable { Some(300) } else { None };
        }
        assert_eq!(sup.select_server(None).unwrap(), reachable);
    }

    #[tokio::test]
    async fn missing_pinned_server_falls_back_instead_of_failing() {
        // Панель убрала сервер из подписки. Отказывать пользователю в
        // подключении из-за этого нельзя.
        let (mut sup, _dir) = make(true);
        sup.settings.auto_select_server = false;
        sup.settings.pinned_server = Some(ProfileId::from_raw("исчезнувший"));

        let chosen = sup.select_server(None).expect("должен быть выбран запасной сервер");
        assert!(sup.servers.iter().any(|s| s.id == chosen));
    }

    #[tokio::test]
    async fn pinned_server_is_used_when_auto_selection_is_off() {
        let (mut sup, _dir) = make(true);
        let pinned = sup.servers[3].id.clone();
        sup.settings.auto_select_server = false;
        sup.settings.pinned_server = Some(pinned.clone());

        assert_eq!(sup.select_server(None).unwrap(), pinned);
    }

    #[tokio::test]
    async fn favorites_sort_first() {
        let (mut sup, _dir) = make(true);
        // Делаем избранным сервер с худшей задержкой — он всё равно должен
        // оказаться первым.
        let worst = sup.servers[0].id.clone();
        for (id, probe) in sup.probes.iter_mut() {
            probe.rtt_ms = Some(if *id == worst { 999 } else { 10 });
        }
        sup.favorites.insert(worst.clone());

        let views = sup.server_views();
        assert_eq!(views[0].id, worst);
        assert!(views[0].favorite);
    }

    /// Подключает демон и доводит до «подключено».
    fn connect_to(sup: &mut Supervisor, server: &ProfileId) {
        sup.handle(Request::Connect {
            server: Some(server.clone()),
        });
        sup.handle_internal(core_started(sup.generation));
        assert_eq!(sup.state.server(), Some(server));
    }

    /// Расставляет замеры: чем дальше по списку, тем хуже.
    fn set_probes(sup: &mut Supervisor, rtts: &[(usize, u32)]) {
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        for (index, rtt) in rtts {
            sup.probes.insert(
                ids[*index].clone(),
                ProbeResult {
                    server: ids[*index].clone(),
                    rtt_ms: Some(*rtt),
                    loss_percent: 0,
                    measured_at_unix_ms: 0,
                },
            );
        }
    }

    /// Кладёт замеры и сообщает их супервизору так, как это делает фоновая
    /// задача, — чтобы проверялся весь путь, а не только выбор.
    fn report_probes(sup: &mut Supervisor, rtts: &[(usize, u32)]) {
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        let results = rtts
            .iter()
            .map(|(index, rtt)| ProbeResult {
                server: ids[*index].clone(),
                rtt_ms: Some(*rtt),
                loss_percent: 0,
                measured_at_unix_ms: 0,
            })
            .collect();
        sup.handle_internal(Internal::Probed(results));
    }

    // ──────────────── задержка в шапке при подключённом соединении ────────────────

    /// Результат замера, в котором сервер не ответил.
    fn silent(server: &ProfileId) -> ProbeResult {
        ProbeResult {
            server: server.clone(),
            rtt_ms: None,
            loss_percent: 100,
            measured_at_unix_ms: 0,
        }
    }

    #[tokio::test]
    async fn a_failed_probe_does_not_erase_the_connected_servers_latency() {
        // Замер попал на провал сети — сон, мигнувший Wi-Fi. Туннель через
        // сервер работает, а прежде этот промах стирал задержку, и в шапке до
        // следующего замера, пять минут, стояло тире.
        let (mut sup, _dir) = make(true);
        let server = sup.servers[0].id.clone();
        connect_to(&mut sup, &server);
        report_probes(&mut sup, &[(0, 42)]);

        sup.handle_internal(Internal::Probed(vec![silent(&server)]));

        assert_eq!(
            sup.probes.get(&server).and_then(|p| p.rtt_ms),
            Some(42),
            "задержка подключённого сервера обязана пережить неудачный замер"
        );
    }

    #[tokio::test]
    async fn a_failed_probe_still_marks_other_servers_unreachable() {
        // Правило касается только сервера, про который известно больше, чем
        // говорит замер. Остальные по-прежнему честно пишутся недоступными —
        // иначе выбор замены опирался бы на устаревшие числа.
        let (mut sup, _dir) = make(true);
        let connected = sup.servers[0].id.clone();
        let other = sup.servers[1].id.clone();
        connect_to(&mut sup, &connected);
        report_probes(&mut sup, &[(0, 42), (1, 30)]);

        sup.handle_internal(Internal::Probed(vec![silent(&other)]));

        assert_eq!(sup.probes.get(&other).and_then(|p| p.rtt_ms), None);
    }

    #[tokio::test]
    async fn without_a_known_latency_the_connected_server_is_measured_soon() {
        // Тире в шапке не должно висеть до следующего общего круга: пока
        // задержка до сервера соединения не известна, он меряется отдельно.
        let (mut sup, _dir) = make(true);
        let server = sup.servers[0].id.clone();
        connect_to(&mut sup, &server);

        // Задержка известна — отдельный замер не нужен.
        assert_eq!(sup.connected_server_without_rtt(), None);

        // Замер, попавший на провал сети, записал сервер недоступным.
        sup.probes.insert(server.clone(), silent(&server));
        assert_eq!(sup.connected_server_without_rtt(), Some(server));
    }

    #[tokio::test]
    async fn measuring_one_server_does_not_postpone_the_round_of_all() {
        // Иначе частые повторы замера текущего сервера отодвигали бы общий круг
        // бесконечно — и остальные серверы не мерились бы вовсе.
        let (mut sup, _dir) = make(true);
        let before = sup.last_probe;
        let server = sup.servers[0].id.clone();

        sup.begin_probe(Some(vec![server]));

        assert_eq!(sup.last_probe, before);
    }

    #[tokio::test]
    async fn preferred_protocols_narrow_the_choice() {
        // Настройка существовала и сохранялась, но на выбор не влияла вовсе:
        // пользователь запрещал протокол и всё равно подключался по нему.
        use sont_core::TransportKind;

        let (mut sup, _dir) = make(true);
        let ss = sup
            .servers
            .iter()
            .find(|s| s.transport.kind() == TransportKind::Shadowsocks)
            .expect("в демо-наборе должен быть Shadowsocks")
            .id
            .clone();

        // Пусть Shadowsocks окажется худшим по замеру — предпочтение обязано
        // перевесить.
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        for (i, id) in ids.iter().enumerate() {
            sup.probes.insert(
                id.clone(),
                ProbeResult {
                    server: id.clone(),
                    rtt_ms: Some(if id == &ss { 500 } else { 10 * (i as u32 + 1) }),
                    loss_percent: 0,
                    measured_at_unix_ms: 0,
                },
            );
        }

        sup.settings.preferred_transports = vec![TransportKind::Shadowsocks];
        assert_eq!(sup.select_server(None).unwrap(), ss);
    }

    #[tokio::test]
    async fn a_preference_nothing_matches_is_ignored() {
        // «Лучше вот так» — не то же самое, что «иначе не подключаться».
        // Отказ оставил бы пользователя без сети ради настройки, которой в
        // подписке просто нечем удовлетворить.
        use sont_core::TransportKind;

        let (mut sup, _dir) = make(true);
        sup.settings.preferred_transports = vec![TransportKind::WireGuard];

        assert!(
            sup.servers
                .iter()
                .all(|s| s.transport.kind() != TransportKind::WireGuard),
            "тест опирается на отсутствие WireGuard в демо-наборе"
        );
        assert!(sup.select_server(None).is_ok());
    }

    #[tokio::test]
    async fn a_setting_that_changes_the_core_config_reconnects_by_itself() {
        // Иначе пользователь переключает режим, видит новое значение в
        // интерфейсе — и продолжает работать по старой конфигурации, пока не
        // догадается переподключиться вручную.
        let (mut sup, _dir) = make(true);
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        connect_to(&mut sup, &ids[0]);

        sup.handle(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                mode: Some(sont_core::ConnectionMode::Proxy),
                ..Default::default()
            },
        });

        assert_eq!(sup.state.kind(), "reconnecting");
    }

    #[tokio::test]
    async fn a_setting_changed_mid_connect_restarts_the_attempt() {
        // Пользователь переключает режим, не дождавшись подключения, и
        // возвращает обратно. Прежде попытка, начатая до правки, доигрывала
        // со старой конфигурацией — соединение поднималось в отменённом
        // режиме либо не поднималось вовсе.
        let (mut sup, _dir) = make(true);
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();

        sup.handle(Request::Connect {
            server: Some(ids[0].clone()),
        });
        let stale = sup.generation;
        assert_eq!(sup.state.kind(), "connecting");

        sup.handle(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                mode: Some(sont_core::ConnectionMode::Proxy),
                ..Default::default()
            },
        });
        assert!(sup.generation > stale, "попытка должна начаться заново");
        assert_eq!(sup.state.kind(), "connecting", "разрыва не было");

        // Результат прежней попытки приходит уже ни к чему.
        sup.handle_internal(core_started(stale));
        assert_eq!(sup.state.kind(), "connecting");

        sup.handle_internal(core_started(sup.generation));
        assert_eq!(sup.state.kind(), "connected");
        assert_eq!(sup.settings.mode, sont_core::ConnectionMode::Proxy);
    }

    #[tokio::test]
    async fn a_cosmetic_setting_leaves_the_connection_alone() {
        // Смена языка не повод рвать соединение.
        let (mut sup, _dir) = make(true);
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        connect_to(&mut sup, &ids[0]);

        sup.handle(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                language: Some("en".into()),
                ..Default::default()
            },
        });

        assert_eq!(sup.state.kind(), "connected");
    }

    #[tokio::test]
    async fn a_much_faster_server_is_taken_when_asked() {
        // Ради этого настройка и заводится: замер показал сервер заметно
        // быстрее — демон переходит на него сам.
        let (mut sup, _dir) = make(true);
        sup.settings.auto_switch = true;
        sup.settings.switch_threshold_ms = 30;

        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        connect_to(&mut sup, &ids[0]);

        report_probes(&mut sup, &[(0, 200), (1, 20)]);

        assert_eq!(sup.state.server(), Some(&ids[1]));
        assert!(
            !sup.recently_failed(&ids[0]),
            "прежний сервер исправен — в штрафной ящик ему не за что"
        );
    }

    #[tokio::test]
    async fn a_marginally_faster_server_is_left_alone() {
        // Смена сервера рвёт все соединения. Делать это ради нескольких
        // миллисекунд — вредить, а не улучшать.
        let (mut sup, _dir) = make(true);
        sup.settings.auto_switch = true;
        sup.settings.switch_threshold_ms = 30;

        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        connect_to(&mut sup, &ids[0]);

        report_probes(&mut sup, &[(0, 50), (1, 29)]);

        assert_eq!(sup.state.server(), Some(&ids[0]));
    }

    #[tokio::test]
    async fn switching_stays_off_unless_asked() {
        // Значение по умолчанию: демон не рвёт соединения по своей инициативе.
        let (mut sup, _dir) = make(true);
        assert!(!sup.settings.auto_switch);

        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        connect_to(&mut sup, &ids[0]);

        report_probes(&mut sup, &[(0, 500), (1, 10)]);

        assert_eq!(sup.state.server(), Some(&ids[0]));
    }

    #[tokio::test]
    async fn a_pinned_server_is_never_taken_away() {
        // Пользователь выбрал сервер сам — это его решение, а не подсказка.
        let (mut sup, _dir) = make(true);
        sup.settings.auto_switch = true;
        sup.settings.auto_select_server = false;

        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        sup.settings.pinned_server = Some(ids[0].clone());
        connect_to(&mut sup, &ids[0]);

        report_probes(&mut sup, &[(0, 500), (1, 10)]);

        assert_eq!(sup.state.server(), Some(&ids[0]));
    }

    #[tokio::test]
    async fn a_fallen_server_is_replaced_by_the_fastest_one() {
        // Ради этого замеры и делаются: пользователь остался без сети, и
        // выбирать наугад, когда известно, кто отвечает быстрее всех, незачем.
        let (mut sup, _dir) = make(true);
        assert!(sup.servers.len() >= 3, "нужен выбор из нескольких серверов");

        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        // Нулевой — текущий, второй заведомо быстрее первого.
        set_probes(&mut sup, &[(0, 20), (1, 300), (2, 40)]);
        connect_to(&mut sup, &ids[0]);

        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::HandshakeTimeout { seconds: 20 })),
        });

        assert_eq!(
            sup.state.server(),
            Some(&ids[2]),
            "замену выбирают по замеру, а не по порядку в списке"
        );
    }

    #[tokio::test]
    async fn a_fallen_server_is_announced_with_its_replacement() {
        // Отдельное событие, потому что из «переподключаюсь» не восстановить,
        // какой сервер выбыл и почему адрес сменился.
        let (mut sup, _dir) = make(true);
        let mut events = sup.events.subscribe();

        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        set_probes(&mut sup, &[(0, 20), (1, 300), (2, 40)]);
        connect_to(&mut sup, &ids[0]);

        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::HandshakeTimeout { seconds: 20 })),
        });

        let mut failure = None;
        while let Ok(event) = events.try_recv() {
            if let Event::ServerFailed(f) = event {
                failure = Some(f);
            }
        }

        let failure = failure.expect("падение сервера обязано быть объявлено");
        assert_eq!(failure.server, ids[0]);
        assert_eq!(failure.switching_to.as_ref(), Some(&ids[2]));
        assert_eq!(
            failure.switching_to_rtt_ms,
            Some(40),
            "без задержки сообщение о смене сервера ничего не объясняет"
        );
        assert!(!failure.name.is_empty(), "по одному id сервер не опознать");
    }

    #[tokio::test]
    async fn a_fallen_server_is_not_chosen_again_right_away() {
        // Замер упавший сервер не отличает: TCP до него доходит, отказывает
        // туннель поверх. Без памяти о падении «лучший по пингу» вернул бы нас
        // ровно туда, откуда мы только что ушли.
        let (mut sup, _dir) = make(true);
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();

        // Упавший — самый быстрый по замеру.
        set_probes(&mut sup, &[(0, 10), (1, 100), (2, 50)]);
        connect_to(&mut sup, &ids[0]);
        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::HandshakeTimeout { seconds: 20 })),
        });

        assert_ne!(sup.state.server(), Some(&ids[0]));
        assert!(sup.recently_failed(&ids[0]));
    }

    #[tokio::test]
    async fn a_lost_network_does_not_move_us_off_the_server() {
        // Пропавшая сеть повторится один в один на любом сервере. Смена
        // адреса вместо соединения — это не помощь, а лишняя путаница.
        let (mut sup, _dir) = make(true);
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        set_probes(&mut sup, &[(0, 200), (1, 10)]);
        connect_to(&mut sup, &ids[0]);

        sup.begin_reconnect(ReconnectCause::NetworkChanged);

        assert_eq!(
            sup.state.server(),
            Some(&ids[0]),
            "причина не в сервере — менять его незачем"
        );
        assert!(!sup.recently_failed(&ids[0]));
    }

    // ──────────────── кого винить в неудачной попытке ────────────────

    #[test]
    fn a_broken_route_is_never_the_servers_fault() {
        // Самая дорогая из бывших поломок. Маршрут по умолчанию удерживал
        // погашенный туннель — то есть отказывала машина, — а демон записывал
        // в отказавшие сервер и уходил к следующему. Тот падал так же.
        let routing = TunnelError::NetworkSetupFailed {
            detail: "маршрут по умолчанию удерживает кто-то ещё".into(),
        };

        assert!(!server_at_fault(&blame(&routing, false)));
        assert!(!server_at_fault(&blame(&routing, true)));
    }

    #[test]
    fn a_core_that_failed_once_is_never_the_servers_fault() {
        // Ядро вышло, не поделив порт с предшественником, — это про машину.
        let core = TunnelError::CoreStartFailed {
            detail: "порт занят".into(),
            permanent: false,
        };
        assert!(!server_at_fault(&blame(&core, false)));
    }

    #[test]
    fn a_silent_server_is_at_fault_only_if_nobody_vouched_for_it() {
        let silent = TunnelError::HandshakeTimeout { seconds: 7 };

        // За сервер не ручались, и он промолчал — вина его.
        assert!(server_at_fault(&blame(&silent, false)));

        // А через этот секунду назад прошёл настоящий запрос. Что бы ни
        // сломалось дальше, сломалось оно не в нём — иначе демон выбрасывал бы
        // на десять минут заведомо рабочие серверы.
        assert!(!server_at_fault(&blame(&silent, true)));
    }

    #[tokio::test]
    async fn a_torn_down_tunnel_gets_time_to_disappear() {
        // Без паузы следующая попытка начинает гонку в тот момент, когда
        // маршрут по умолчанию ещё ведёт в снимаемый TUN. Гонка не достучится
        // ни до кого и потратит впустую пять секунд — вчетверо больше паузы.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let chosen = sup.state.server().cloned().unwrap();

        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: true,
            result: Box::new(Err(TunnelError::NetworkSetupFailed {
                detail: "маршрут по умолчанию удерживает кто-то ещё".into(),
            })),
        });

        assert_eq!(sup.state.server(), Some(&chosen));
        assert!(
            reconnect_delay_for(sup.reconnect_attempt, true) < SETTLE_AFTER_TEARDOWN,
            "иначе проверка ничего не проверяет: обычная лестница и так длиннее"
        );
    }

    #[tokio::test]
    async fn a_machine_fault_does_not_drain_the_pool_of_servers() {
        // Сквозная проверка того, что видно в журнале: без неё каждая неудача
        // съедала по серверу, гонке переставало хватать участников, и
        // подключение растягивалось на минуты.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let chosen = sup.state.server().cloned().unwrap();

        // Гонка сервер подтвердила, а туннель всё равно не встал: маршруты.
        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: true,
            result: Box::new(Err(TunnelError::NetworkSetupFailed {
                detail: "маршрут по умолчанию удерживает кто-то ещё".into(),
            })),
        });

        assert_eq!(
            sup.state.server(),
            Some(&chosen),
            "менять подтверждённый сервер из-за маршрутов незачем"
        );
        assert!(
            !sup.recently_failed(&chosen),
            "исправный сервер не должен попадать в штрафной ящик"
        );
        assert!(
            sup.failed_servers.is_empty(),
            "пул кандидатов обязан остаться целым"
        );
    }

    #[tokio::test]
    async fn the_last_server_left_is_retried_rather_than_abandoned() {
        // Один сервер в подписке — обычное дело. Отказаться от попыток только
        // потому, что заменить его некем, значит оставить пользователя без
        // связи там, где помогло бы простое повторение.
        let (mut sup, _dir) = make(true);
        sup.servers.truncate(1);
        let only = sup.servers[0].id.clone();
        connect_to(&mut sup, &only);

        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::HandshakeTimeout { seconds: 20 })),
        });

        assert_eq!(sup.state.server(), Some(&only));
        assert_eq!(sup.state.kind(), "reconnecting");
    }

    #[tokio::test]
    async fn a_server_that_works_again_leaves_the_penalty_box() {
        // Иначе однажды упавший сервер обходили бы стороной ещё десять минут
        // после того, как он снова начал работать.
        let (mut sup, _dir) = make(true);
        let ids: Vec<ProfileId> = sup.servers.iter().map(|s| s.id.clone()).collect();
        connect_to(&mut sup, &ids[0]);

        sup.failed_servers.insert(ids[0].clone(), Instant::now());
        assert!(sup.recently_failed(&ids[0]));

        connect_to(&mut sup, &ids[0]);
        assert!(!sup.recently_failed(&ids[0]));
    }

    #[tokio::test]
    async fn subscription_url_must_be_http() {
        let (mut sup, _dir) = make(false);
        let response = sup.handle(Request::AddSubscription {
            url: Secret::new("vless://not-a-subscription"),
        });
        assert!(matches!(
            response,
            Response::Error(IpcError::InvalidRequest { .. })
        ));
        assert!(sup.subscriptions.is_empty());
    }

    #[tokio::test]
    async fn subscription_is_stored_masked() {
        let (mut sup, _dir) = make(false);
        let url = "https://panel.example/sub/VERY-SECRET-TOKEN";
        assert_eq!(
            sup.handle(Request::AddSubscription {
                url: Secret::new(url)
            }),
            Response::Accepted
        );

        let entry = sup.subscriptions.first().expect("подписка должна сохраниться");
        assert!(
            !entry.masked_url.contains("VERY-SECRET-TOKEN"),
            "маска не должна раскрывать токен: {}",
            entry.masked_url
        );

        // Снимок состояния тоже не должен содержать настоящую ссылку.
        let json = serde_json::to_string(&sup.snapshot()).unwrap();
        assert!(!json.contains("VERY-SECRET-TOKEN"), "утечка через снимок: {json}");

        // И ответ на перечисление подписок тоже: он уходит непривилегированному
        // клиенту, которому исходная ссылка ни к чему.
        let json = serde_json::to_string(&sup.handle(Request::ListSubscriptions)).unwrap();
        assert!(!json.contains("VERY-SECRET-TOKEN"), "утечка через список: {json}");
    }

    #[tokio::test]
    async fn the_key_comes_out_only_when_asked_for_it() {
        // Список подписок отдаёт маску — этого хватает, чтобы показать
        // подписку. Настоящий ключ выдаётся отдельным запросом и только им:
        // он нужен ровно для «скопировать» и «показать QR».
        let (mut sup, _dir) = make(false);
        let url = "https://panel.example/sub/VERY-SECRET-TOKEN";
        sup.handle(Request::AddSubscription {
            url: Secret::new(url),
        });
        let id = sup.subscriptions[0].id.clone();

        let Response::SubscriptionSecret(secret) =
            sup.handle(Request::RevealSubscription { id: id.clone() })
        else {
            panic!("ключ должен выдаваться по запросу");
        };
        assert_eq!(secret.expose(), url);

        // Но даже в ответе он не раскрывается отладочной печатью.
        assert!(!format!("{secret:?}").contains("VERY-SECRET-TOKEN"));

        // Несуществующая подписка — ошибка запроса, а не пустой ответ:
        // молчаливое «ничего» клиент принял бы за отсутствие ключа.
        assert!(matches!(
            sup.handle(Request::RevealSubscription {
                id: SubscriptionId::from_raw("нет такой")
            }),
            Response::Error(IpcError::InvalidRequest { .. })
        ));
    }

    #[tokio::test]
    async fn the_same_url_added_twice_stays_one_subscription() {
        // Пользователь, вставивший ссылку дважды, ожидает одну подписку.
        // Две одинаковые дали бы каждый сервер парой — и «избранное» с
        // закреплением перестали бы означать что-то определённое.
        let (mut sup, _dir) = make(false);
        let url = "https://panel.example/sub/TOKEN";

        sup.handle(Request::AddSubscription {
            url: Secret::new(url),
        });
        sup.handle(Request::AddSubscription {
            url: Secret::new(url),
        });

        assert_eq!(sup.subscriptions.len(), 1);
    }

    #[tokio::test]
    async fn subscriptions_are_independent() {
        // Смысл нескольких подписок в том, что они не связаны: одна панель
        // легла — вторая продолжает давать серверы.
        let (mut sup, _dir) = make(false);
        sup.handle(Request::AddSubscription {
            url: Secret::new("https://first.example/sub"),
        });
        sup.handle(Request::AddSubscription {
            url: Secret::new("https://second.example/sub"),
        });
        assert_eq!(sup.subscriptions.len(), 2);

        let first = sup.subscriptions[0].id.clone();
        assert_eq!(
            sup.handle(Request::RemoveSubscription { id: first.clone() }),
            Response::Accepted
        );

        assert_eq!(sup.subscriptions.len(), 1);
        assert_ne!(sup.subscriptions[0].id, first);

        // Удаление того, чего нет, — ошибка запроса, а не молчаливый успех:
        // иначе опечатка в идентификаторе выглядит как выполненная команда.
        assert!(matches!(
            sup.handle(Request::RemoveSubscription { id: first }),
            Response::Error(IpcError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn servers_from_several_subscriptions_are_merged_without_duplicates() {
        // Панели перепродают одни и те же узлы, а id считается от адреса и
        // учётных данных — совпадения неизбежны. Два профиля с одним id в
        // списке означали бы, что закреплённый сервер указывает на оба сразу.
        let shared = demo::servers().into_iter().next().unwrap();
        let entry = |id: &str, profiles: Vec<ServerProfile>| SubscriptionEntry {
            id: SubscriptionId::from_raw(id),
            secret: Secret::new("https://panel.example/sub"),
            masked_url: "htt…sub".into(),
            profiles,
            info: SubscriptionInfo::default(),
        };

        let merged = merge_servers(&[
            entry("a", vec![shared.clone()]),
            entry("b", vec![shared.clone()]),
        ]);

        assert_eq!(merged.len(), 1, "один и тот же сервер не должен удвоиться");
        assert_eq!(merged[0].id, shared.id);
    }

    #[tokio::test]
    async fn settings_patch_is_persisted() {
        let (mut sup, dir) = make(false);
        let response = sup.handle(Request::PatchSettings {
            patch: SettingsPatch {
                language: Some("en".into()),
                ..Default::default()
            },
        });
        assert!(matches!(response, Response::Settings(_)));

        let saved: Settings = store::load_or_default(&dir.path().join("settings.json"));
        assert_eq!(saved.language, "en");
    }

    #[tokio::test]
    async fn clearing_subscription_drops_servers_and_disconnects() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));
        assert!(sup.state.is_connected());

        sup.handle(Request::ClearSubscription);
        assert!(sup.servers.is_empty());
        assert_eq!(sup.state.kind(), "disconnecting");
    }

    #[tokio::test]
    async fn repeated_disconnect_is_a_no_op() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle(Request::Disconnect);
        let generation = sup.generation;

        sup.handle(Request::Disconnect);
        assert_eq!(
            sup.generation, generation,
            "повторное отключение не должно порождать новое намерение"
        );
    }

    #[tokio::test]
    async fn stats_are_not_polled_without_subscribers() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));

        // Получателей событий нет — опрашивать ядро незачем.
        sup.tick_stats();
        assert_eq!(sup.stats, Stats::default());
    }

    #[tokio::test]
    async fn counters_are_converted_to_speed_and_totals() {
        use sont_xray::metrics::Counters;

        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));

        // Первое снятие задаёт точку отсчёта: скорости ещё нет, но итоги
        // должны отражать показания ядра.
        sup.apply_counters(Counters {
            uplink: 1_000,
            downlink: 5_000,
        });
        assert_eq!(sup.stats.total_up, 1_000);
        assert_eq!(sup.stats.total_down, 5_000);
        assert_eq!(sup.stats.up_bps, 0);

        // Второе — даёт скорость по разности.
        tokio::time::sleep(Duration::from_millis(60)).await;
        sup.apply_counters(Counters {
            uplink: 2_000,
            downlink: 15_000,
        });
        assert_eq!(sup.stats.total_up, 2_000);
        assert!(sup.stats.up_bps > 0, "скорость должна считаться по разности");
        assert!(sup.stats.down_bps > sup.stats.up_bps);
    }

    #[tokio::test]
    async fn core_restart_does_not_produce_negative_speed() {
        use sont_xray::metrics::Counters;

        let (mut sup, _dir) = make(true);
        sup.apply_counters(Counters {
            uplink: 10_000,
            downlink: 10_000,
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Ядро перезапустилось — счётчики начались заново.
        sup.apply_counters(Counters {
            uplink: 5,
            downlink: 5,
        });
        assert_eq!(sup.stats.up_bps, 0, "разность не должна уходить в минус");
        assert_eq!(sup.stats.total_up, 5);
    }

    #[tokio::test]
    async fn stats_are_reset_between_sessions() {
        use sont_xray::metrics::Counters;

        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));
        sup.apply_counters(Counters {
            uplink: 999,
            downlink: 999,
        });

        sup.handle(Request::Disconnect);
        assert_eq!(
            sup.stats,
            Stats::default(),
            "итоги прошлой сессии не должны перетекать в следующую"
        );
        assert!(sup.metrics_url.is_none());
    }

    // ─────────────────────── автономная работа ───────────────────────

    #[tokio::test]
    async fn explicit_disconnect_stops_the_daemon_from_reconnecting() {
        // Главный инвариант оркестратора: он добивается соединения ровно
        // до тех пор, пока его хочет пользователь.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));
        assert_eq!(sup.desired, Desired::Connected { server: None });

        sup.handle(Request::Disconnect);
        assert_eq!(sup.desired, Desired::Disconnected);

        // Обрыв после явного отключения не должен ничего восстанавливать.
        sup.begin_reconnect(ReconnectCause::CoreExited { code: Some(1) });
        assert_ne!(sup.state.kind(), "reconnecting");
    }

    #[tokio::test]
    async fn dropped_connection_is_restored_without_the_user() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));
        assert!(sup.state.is_connected());

        sup.begin_reconnect(ReconnectCause::CoreExited { code: Some(1) });

        assert_eq!(sup.state.kind(), "reconnecting");
        assert!(
            sup.state.is_blocked(),
            "во время восстановления трафик наружу выпускать нельзя"
        );
        assert_eq!(sup.reconnect_attempt, 1);
    }

    #[tokio::test]
    async fn a_machine_fault_never_makes_the_daemon_shuffle_servers() {
        // Раньше здесь стояло обратное: после трёх неудач подряд демон начинал
        // перебирать адреса, даже если причина была не в сервере. Домысел был
        // честный — отличить одно от другого демон не умел.
        //
        // Теперь умеет, и домысел стал вредом. Перебор ничего не чинит: гонка
        // и так проверяет восемь серверов на каждом круге и сама называет
        // рабочий. Зато сервер в шапке окна менялся каждые несколько секунд —
        // ровно то, что выглядело как пляска с серверами при исправном пинге.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let first = sup.state.server().cloned().unwrap();

        for _ in 0..14 {
            sup.begin_reconnect(ReconnectCause::NetworkChanged);
            assert_eq!(
                sup.state.server(),
                Some(&first),
                "причина не в сервере — менять его незачем ни на какой попытке"
            );
        }

        assert!(
            sup.failed_servers.is_empty(),
            "и в штрафной ящик за отказ машины никто попадать не должен"
        );
    }

    #[tokio::test]
    async fn successful_connection_resets_the_backoff() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.begin_reconnect(ReconnectCause::CoreExited { code: None });
        sup.begin_reconnect(ReconnectCause::CoreExited { code: None });
        assert_eq!(sup.reconnect_attempt, 2);

        let g = sup.generation;
        sup.handle_internal(core_started(g));
        assert_eq!(
            sup.reconnect_attempt, 0,
            "иначе следующий обрыв начнётся с длинной паузы"
        );
    }

    #[tokio::test]
    async fn single_health_failure_does_not_break_a_working_connection() {
        // Мигнувший Wi-Fi не повод рвать соединение.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));

        sup.apply_health(false, None);
        assert!(sup.state.is_connected(), "одна неудача — ещё не обрыв");

        sup.apply_health(true, None);
        assert_eq!(sup.health_failures, 0, "успех обнуляет счётчик");
        assert!(sup.state.is_connected());
    }

    #[tokio::test]
    async fn a_slow_probe_does_not_kill_a_tunnel_that_carries_data() {
        // Ровно то, что было у пользователя: туннель работал, приложения
        // получали данные, а проверочный запрос — холодное соединение через
        // всю цепочку — дважды не укладывался в срок. Демон рвал рабочий
        // туннель, и окно через минуту после «Подключено» показывало
        // «Восстанавливаю».
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));

        // Первая проверка задаёт точку отсчёта.
        sup.apply_health(true, Some(1_000));
        // Дальше запрос не проходит ни разу — а данные от сервера идут.
        sup.apply_health(false, Some(250_000));
        sup.apply_health(false, Some(900_000));
        sup.apply_health(false, Some(1_400_000));

        assert_eq!(sup.state.kind(), "connected", "по туннелю идут данные — он жив");
        assert_eq!(sup.health_failures, 0);
    }

    #[tokio::test]
    async fn a_silent_tunnel_is_still_torn_down() {
        // Правило не должно спасать мёртвый туннель: от мёртвого сервера не
        // приходит ни байта, и счётчик стоит на месте.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));

        sup.apply_health(true, Some(5_000));
        for _ in 0..HEALTH_FAILURES_BEFORE_RECONNECT {
            sup.apply_health(false, Some(5_000));
        }

        assert_eq!(sup.state.kind(), "reconnecting");
    }

    #[tokio::test]
    async fn without_counters_the_probe_alone_decides() {
        // Счётчики прочитать не вышло — судить можно только по запросу. Считать
        // туннель живым вслепую значило бы никогда не заметить обрыв.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));

        for _ in 0..HEALTH_FAILURES_BEFORE_RECONNECT {
            sup.apply_health(false, None);
        }

        assert_eq!(sup.state.kind(), "reconnecting");
    }

    #[tokio::test]
    async fn a_new_core_starts_its_own_count() {
        // Счётчики нового ядра начинаются с нуля. Сравни их с прошлым сеансом —
        // и живой туннель выглядел бы застывшим, пока не догонит старое число.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        sup.apply_health(true, Some(9_000_000));

        sup.begin_reconnect(ReconnectCause::NetworkChanged);

        assert_eq!(sup.last_health_downlink, None);
        assert!(!sup.health_in_flight);
    }

    #[tokio::test]
    async fn repeated_health_failures_trigger_reconnect() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));

        for _ in 0..HEALTH_FAILURES_BEFORE_RECONNECT {
            sup.apply_health(false, None);
        }
        assert_eq!(sup.state.kind(), "reconnecting");
    }

    #[tokio::test]
    async fn stale_health_result_does_not_break_the_new_session() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let stale = sup.generation;
        sup.handle_internal(core_started(stale));

        // Соединение переподняли, и старая проверка опоздала.
        sup.begin_reconnect(ReconnectCause::NetworkChanged);
        let fresh = sup.generation;
        sup.handle_internal(core_started(fresh));

        sup.handle_internal(Internal::HealthChecked {
            generation: stale,
            alive: false,
            downlink: None,
        });
        assert_eq!(
            sup.health_failures, 0,
            "результат прошлого сеанса не должен влиять на текущий"
        );
        assert!(sup.state.is_connected());
    }

    #[tokio::test]
    async fn unrecoverable_error_stops_the_attempts() {
        // Незапускающееся ядро — отсутствующий файл, несошедшийся хэш — само
        // не починится, и бесконечный цикл попыток скрыл бы от пользователя
        // настоящую причину.
        let (mut sup, _dir) = make(false);
        sup.desired = Desired::Connected { server: None };
        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::CoreStartFailed {
                detail: "файла ядра нет".into(),
                permanent: true,
            })),
        });

        assert_eq!(sup.state.kind(), "failed");
        assert_eq!(sup.desired, Desired::Disconnected);
    }

    #[tokio::test]
    async fn a_core_that_failed_once_does_not_cancel_the_intent() {
        // Ровно та поломка, ради которой заведён признак `permanent`.
        //
        // Ядро запустилось и вышло: порт ещё держал погашенный экземпляр.
        // Считая это окончательным отказом, демон снимал намерение — и после
        // смены настройки пользователь оставался без соединения навсегда,
        // хотя достаточно было повторить.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });

        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::CoreStartFailed {
                detail: "ядро завершилось с кодом 23".into(),
                permanent: false,
            })),
        });

        assert!(
            matches!(sup.desired, Desired::Connected { .. }),
            "намерение обязано пережить неудачную попытку"
        );
        assert_eq!(
            sup.state.kind(),
            "reconnecting",
            "демон обязан пробовать дальше, а не объявлять отказ"
        );
    }

    #[tokio::test]
    async fn a_settings_change_never_leaves_the_user_disconnected() {
        // Сквозная проверка пути, на котором ломалось: пользователь меняет
        // настройку, требующую новой конфигурации, ядро не поднимается с
        // первого раза — и соединение обязано восстановиться само.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        assert_eq!(sup.state.kind(), "connected");

        // Смена режима — та самая настройка, что пересобирает ядро.
        sup.handle(Request::PatchSettings {
            patch: SettingsPatch {
                mode: Some(sont_core::ConnectionMode::Proxy),
                ..Default::default()
            },
        });
        assert_eq!(sup.state.kind(), "reconnecting", "настройка пересобирает ядро");

        // Новое ядро вышло, не успев подняться.
        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::CoreStartFailed {
                detail: "порт занят".into(),
                permanent: false,
            })),
        });

        assert!(
            matches!(sup.desired, Desired::Connected { .. }),
            "смена настройки не вправе выключать VPN"
        );
        assert!(
            sup.state.holds_a_route(),
            "демон обязан остаться в попытке, а не осесть в отказе: было {}",
            sup.state.kind()
        );
    }

    #[tokio::test]
    async fn a_server_the_core_cannot_run_is_never_chosen() {
        // Иначе один такой сервер в подписке выключал автоподключение целиком:
        // выбор упирался в него, отказ считался окончательным, намерение
        // снималось.
        let (mut sup, _dir) = make(true);
        assert!(
            sup.candidates().all(|s| sont_xray::supports(&s.transport)),
            "негодный сервер не должен доходить до выбора"
        );

        // И даже когда предпочтения указывают ровно на него.
        sup.settings.preferred_transports = vec![sont_core::TransportKind::Tuic];
        assert!(sup.candidates().all(|s| sont_xray::supports(&s.transport)));
        assert!(
            sup.candidates().next().is_some(),
            "предпочтение, которому никто не отвечает, не должно опустошать список"
        );
    }

    #[test]
    fn only_excluded_sites_become_routes() {
        use sont_core::{SplitTunnelMode, SplitTunnelRules};

        // В режиме `Exclude` перечислено то, что идёт мимо туннеля, — это и
        // ложится на маршруты.
        let mut settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Exclude,
                apps: vec![r"C:\browser.exe".into()],
                sites: vec!["bank.example".into()],
            },
            ..Default::default()
        };
        assert_eq!(bypass_hosts(&settings), ["bank.example"]);

        // В `Include` перечислено обратное — что идёт через туннель. «Всё
        // остальное мимо» маршрутами не выразить.
        settings.split_tunnel.mode = SplitTunnelMode::Include;
        assert!(bypass_hosts(&settings).is_empty());

        settings.split_tunnel.mode = SplitTunnelMode::Off;
        assert!(bypass_hosts(&settings).is_empty());
    }

    #[tokio::test]
    async fn a_missing_key_does_not_cancel_the_intent() {
        // Подписки нет — но она появится, как только пользователь вставит
        // ключ. Снять намерение здесь значит оставить его отключённым до
        // тех пор, пока он сам не заметит и не нажмёт кнопку.
        let (mut sup, _dir) = make(false);
        sup.desired = Desired::Connected { server: None };

        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            vouched: false,
            result: Box::new(Err(TunnelError::NoSubscription)),
        });

        assert_eq!(sup.state.kind(), "failed");
        assert_eq!(
            sup.desired,
            Desired::Connected { server: None },
            "намерение должно пережить поправимый отказ"
        );
    }

    // ─────────────────────── обновление подписок ───────────────────────

    /// Супервизор с одной подпиской, чей ответ панели уже применён.
    fn with_subscription() -> (Supervisor, tempfile::TempDir, SubscriptionId) {
        let (mut sup, dir) = make(false);
        sup.handle(Request::AddSubscription {
            url: Secret::new("https://panel.example/sub/KEY"),
        });
        let id = sup.subscriptions[0].id.clone();
        sup.apply_fetched(
            id.clone(),
            Ok(crate::subscription::Fetched {
                profiles: demo::servers(),
                info: Default::default(),
                skipped: 0,
            }),
        );
        (sup, dir, id)
    }

    #[tokio::test]
    async fn subscriptions_are_refreshed_on_schedule_at_all() {
        // Настройка «обновлять раз в двенадцать часов» существовала — и не
        // делала ничего: подписка читалась только при добавлении и по кнопке.
        // Провайдер сменил ключи Reality, и Sont перестал подключаться к чему
        // бы то ни было, пока Happ с той же подпиской работал.
        let (mut sup, _dir, _id) = with_subscription();
        sup.last_subscription_fetch = Instant::now() - Duration::from_secs(13 * 3600);

        sup.tick_subscriptions();

        assert!(
            sup.last_subscription_fetch.elapsed() < Duration::from_secs(5),
            "срок обновления вышел — обновление обязано начаться"
        );
        assert!(!sup.fetching.is_empty(), "запрос к панели обязан уйти");
    }

    #[tokio::test]
    async fn a_fresh_start_refreshes_subscriptions_right_away() {
        // Демон мог простоять выключенным сколько угодно, и сохранённые ключи
        // к этому времени могли устареть.
        let (sup, _dir) = make(false);
        let hours = u64::from(sup.settings.subscription_refresh_hours);
        assert!(
            sup.last_subscription_fetch.elapsed() >= Duration::from_secs(hours * 3600),
            "первое обновление обязано случиться на первом же тике"
        );
    }

    #[tokio::test]
    async fn silent_servers_trigger_a_refresh_but_not_a_flood() {
        let (mut sup, _dir, id) = with_subscription();
        sup.fetching.remove(&id);
        sup.last_subscription_fetch = Instant::now() - SILENCE_REFRESH_MIN;

        // Серверы отвергли ключ — обновляемся сразу, не дожидаясь расписания.
        sup.handle_internal(Internal::ServersSilent { rejected: true });
        assert!(!sup.fetching.is_empty(), "устаревшие ключи лечатся только обновлением");

        // А пока сети нет, гонка молчит раз за разом — и каждый круг не должен
        // оборачиваться ещё и запросом к панели.
        sup.fetching.clear();
        sup.handle_internal(Internal::ServersSilent { rejected: false });
        assert!(sup.fetching.is_empty(), "повтор раньше срока — это поток запросов к панели");
    }

    #[tokio::test]
    async fn fresh_keys_restart_a_doomed_attempt_at_once() {
        // Идущая попытка несёт прежние ключи и обречена. Дожидаться её отказа
        // значило бы потерять ещё круг с паузой до пятнадцати секунд.
        let (mut sup, _dir, id) = with_subscription();
        sup.handle(Request::Connect { server: None });
        assert_eq!(sup.state.kind(), "connecting");
        let doomed = sup.generation;

        // Панель сменила только ключ Reality. Номера серверов от этого не
        // меняются — сравнивать по ним значило бы не заметить обновления.
        let rotated: Vec<ServerProfile> = demo::servers()
            .into_iter()
            .map(|mut s| {
                if let sont_core::Transport::Vless(v) = &mut s.transport {
                    if let sont_core::Security::Reality(r) = &mut v.security {
                        r.public_key = "rotated-public-key".into();
                    }
                }
                s
            })
            .collect();
        assert_ne!(rotated, demo::servers(), "в наборе обязан быть сервер с Reality");

        sup.apply_fetched(
            id,
            Ok(crate::subscription::Fetched {
                profiles: rotated,
                info: Default::default(),
                skipped: 0,
            }),
        );

        assert_ne!(sup.generation, doomed, "попытка обязана начаться заново");
        assert!(sup.state.holds_a_route());
    }

    #[tokio::test]
    async fn an_unchanged_subscription_leaves_the_attempt_alone() {
        // Панель вернула ровно то же. Идущая попытка ничем не обречена, а
        // начать её заново — выбросить гонку, которой до ответа оставались
        // секунды.
        let (mut sup, _dir, id) = with_subscription();
        sup.handle(Request::Connect { server: None });
        let running = sup.generation;

        sup.apply_fetched(
            id,
            Ok(crate::subscription::Fetched {
                profiles: demo::servers(),
                info: Default::default(),
                skipped: 0,
            }),
        );

        assert_eq!(sup.generation, running, "попытку трогать незачем");
        assert_eq!(sup.state.kind(), "connecting");
    }

    #[tokio::test]
    async fn a_server_gone_after_a_refresh_is_replaced_not_failed() {
        // Номер сервера считается и от ключа, так что после смены ключей
        // прежний номер указывает в никуда. Возвращаться на него — это отказ
        // «сервер не найден» там, где нужен лучший из имеющихся.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));

        let vanished = ProfileId::from_raw("ключ-сменился");
        sup.state = TunnelState::Connected {
            server: vanished.clone(),
            since_unix_ms: 0,
            tun: tun_info(),
        };

        sup.begin_reconnect(ReconnectCause::NetworkChanged);

        let target = sup.state.server().cloned();
        assert_ne!(target, Some(vanished));
        assert!(
            target.is_some_and(|t| sup.servers.iter().any(|s| s.id == t)),
            "восстановление обязано идти на существующий сервер"
        );
        assert_ne!(sup.state.kind(), "failed");
    }

    #[tokio::test]
    async fn the_first_key_brings_the_connection_up_by_itself() {
        // Ровно тот случай, ради которого заведён примиритель: демон
        // стартовал без подписки, автоподключение не удалось, намерение
        // осталось. Ключ добавлен — соединение поднимается само.
        let (mut sup, _dir) = make(false);
        assert!(sup.begin_connect(None).is_err(), "подключаться пока не на чем");
        assert_eq!(sup.state.kind(), "disconnected");

        sup.handle(Request::AddSubscription {
            url: Secret::new("https://panel.example/sub/KEY"),
        });
        let id = sup.subscriptions[0].id.clone();

        // Ответ панели: демо-серверы годятся как разобранная подписка.
        sup.apply_fetched(
            id,
            Ok(crate::subscription::Fetched {
                profiles: demo::servers(),
                info: Default::default(),
                skipped: 0,
            }),
        );

        assert_eq!(
            sup.state.kind(),
            "connecting",
            "серверы появились — соединение должно подниматься без нажатий"
        );
    }

    #[tokio::test]
    async fn the_reconciler_does_not_hammer_a_dead_connection() {
        // Между попытками выдерживается пауза: иначе демон бился бы в
        // неподнимающийся туннель каждую секунду тика.
        let (mut sup, _dir) = make(true);
        sup.desired = Desired::Connected { server: None };
        sup.set_state(TunnelState::Failed {
            error: TunnelError::RetriesExhausted { attempts: 3 },
            blocked: false,
        });
        sup.last_attempt = Instant::now();

        sup.tick_reconcile();
        assert_eq!(sup.state.kind(), "failed", "пауза ещё не вышла");

        sup.last_attempt = Instant::now() - RECONCILE_INTERVAL;
        sup.tick_reconcile();
        assert_eq!(sup.state.kind(), "connecting");
    }

    // ──────────────────── серверы мимо туннеля ────────────────────

    #[tokio::test]
    async fn every_other_server_is_routed_around_the_tunnel() {
        // Без этого замер до чужого сервера уходил в TUN, где соединение
        // принимает пользовательский стек TCP, — и до Сеула «было» 1 мс.
        let hosts = vec![
            "84.201.130.138".to_owned(),
            "155.117.137.56".to_owned(),
            "5.254.121.226".to_owned(),
        ];

        let ips = resolve_peers(&hosts, "84.201.130.138").await;

        assert!(ips.contains(&"155.117.137.56".parse().unwrap()));
        assert!(ips.contains(&"5.254.121.226".parse().unwrap()));
        assert!(
            !ips.contains(&"84.201.130.138".parse().unwrap()),
            "текущий сервер разрешается отдельно и обязательно — здесь его быть не должно"
        );
    }

    #[test]
    fn a_server_that_does_not_resolve_is_skipped_without_waiting_for_dns() {
        // Не разрешилось имя — не попало в обход. Это стоит одного неверного
        // замера, а отказ в подключении из-за чужого сервера был бы нелепостью.
        //
        // И важнее того — ждать системный резолвер мы не обязаны. Windows
        // держит поток на несуществующем имени секунд десять, а разрешение
        // стоит на пути подключения. Предел здесь свой, короткий.
        let hosts = vec![
            "не-существует.invalid".to_owned(),
            "155.117.137.56".to_owned(),
        ];

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let started = Instant::now();
        let ips = runtime.block_on(resolve_peers(&hosts, "84.201.130.138"));
        let spent = started.elapsed();
        // Поток резолвера доживёт своё сам — дожидаться его значило бы
        // проверять терпение системы, а не наш предел.
        runtime.shutdown_background();

        assert_eq!(ips, vec!["155.117.137.56".parse::<std::net::IpAddr>().unwrap()]);
        assert!(
            spent < PEER_RESOLVE_TIMEOUT * 2,
            "разрешение обязано уложиться в свой предел, а заняло {spent:?}"
        );
    }

    #[tokio::test]
    async fn a_shared_address_is_routed_once() {
        // Панели перепродают одни и те же узлы: два сервера подписки на одном
        // адресе — обычное дело, а маршрут на него нужен один.
        let hosts = vec!["155.117.137.56".to_owned(), "155.117.137.56".to_owned()];
        assert_eq!(resolve_peers(&hosts, "x").await.len(), 1);
    }

    #[tokio::test]
    async fn a_lost_attempt_does_not_wedge_the_daemon_forever() {
        // Задача, поднимающая ядро, отчитывается всегда. Погибни она молча — и
        // «подключаюсь» осталось бы навсегда: примиритель считает такое
        // состояние идущей работой и не вмешивается. Выйти можно было бы
        // только руками.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        assert_eq!(sup.state.kind(), "connecting");

        let lost = sup.generation;

        // Отчёта нет, и уже давно.
        sup.last_attempt = Instant::now() - STALLED_ATTEMPT - Duration::from_secs(1);
        sup.tick_reconcile();

        assert_ne!(
            sup.generation, lost,
            "сторож обязан начать попытку заново, а не ждать вечно"
        );
        assert!(sup.state.holds_a_route());
    }

    #[tokio::test]
    async fn the_watchdog_keeps_its_hands_off_a_live_attempt() {
        // Сторож, срабатывающий на живой работе, рвёт подключение вместо того,
        // чтобы его спасать.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let running = sup.generation;

        sup.tick_reconcile();

        assert_eq!(sup.generation, running, "попытка идёт — трогать её нечего");
    }

    #[tokio::test]
    async fn the_watchdog_leaves_a_working_connection_alone() {
        // `Connected` тоже «держит маршрут», и спутать его с зависшей попыткой
        // значит рвать рабочее соединение раз в минуту.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        sup.handle_internal(core_started(sup.generation));
        assert_eq!(sup.state.kind(), "connected");

        let live = sup.generation;
        sup.last_attempt = Instant::now() - STALLED_ATTEMPT - Duration::from_secs(60);
        sup.tick_reconcile();

        assert_eq!(sup.generation, live);
        assert_eq!(sup.state.kind(), "connected");
    }

    #[tokio::test]
    async fn the_reconciler_leaves_a_disconnected_user_alone() {
        // Пользователь отключился сам — навязывать ему соединение обратно
        // демон не вправе.
        let (mut sup, _dir) = make(true);
        sup.desired = Desired::Disconnected;
        sup.last_attempt = Instant::now() - RECONCILE_INTERVAL;

        sup.tick_reconcile();

        assert_eq!(sup.state.kind(), "disconnected");
    }

    #[tokio::test]
    async fn transient_error_keeps_trying() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;

        sup.handle_internal(Internal::CoreStarted {
            generation: g,
            vouched: false,
            result: Box::new(Err(TunnelError::HandshakeTimeout { seconds: 20 })),
        });

        assert_eq!(
            sup.state.kind(),
            "reconnecting",
            "временная ошибка не повод сдаваться"
        );
    }

    #[test]
    fn both_proxy_inbounds_ask_for_their_stable_numbers() {
        // Адреса прокси видит пользователь: они лежат в настройках системы и
        // могут быть прописаны в отдельном приложении вручную. Меняться от
        // подключения к подключению им нельзя, поэтому оба входа просят
        // конкретный номер, а не любой свободный порт.
        //
        // Свободен ли этот номер на машине, где идут тесты, к делу отношения
        // не имеет: занят — отход на свободный порт правильное поведение.
        // Поэтому в каждой ветке проверяется своё утверждение.
        fn free(port: u16) -> bool {
            std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
        }

        let settings = Settings::default();
        let (http_free, socks_free) = (free(PREFERRED_HTTP_PORT), free(PREFERRED_SOCKS_PORT));
        let runtime = runtime_info(&settings);

        if http_free {
            assert_eq!(runtime.http_listen, format!("127.0.0.1:{PREFERRED_HTTP_PORT}"));
        } else {
            assert_ne!(runtime.http_listen, format!("127.0.0.1:{PREFERRED_HTTP_PORT}"));
        }
        if socks_free {
            assert_eq!(
                runtime.probe_listen,
                format!("127.0.0.1:{PREFERRED_SOCKS_PORT}")
            );
        } else {
            assert_ne!(
                runtime.probe_listen,
                format!("127.0.0.1:{PREFERRED_SOCKS_PORT}")
            );
        }

        // А служебному порту статистики постоянство ни к чему: наружу он не
        // объявляется, и фиксированный номер только создавал бы конфликты.
        assert_ne!(runtime.metrics_listen, runtime_info(&settings).metrics_listen);
    }

    #[test]
    fn free_preferred_port_is_used_as_is() {
        // Постоянство адреса удобно: настройки прокси не приходится менять.
        //
        // Свободный порт подбираем, а не берём готовый номер: тест, зависящий
        // от того, занят ли на машине конкретный порт, падает по причинам,
        // не имеющим отношения к проверяемому поведению.
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let free = probe.local_addr().unwrap().port();
        drop(probe);

        assert_eq!(preferred_or_free_port(free), free);
    }

    #[test]
    fn busy_preferred_port_falls_back_instead_of_failing() {
        // Порт может занять другой VPN-клиент или собственное подвисшее ядро.
        // Отказаться от подключения из-за этого — худший исход: агент в сеансе
        // пользователя всё равно переприменит настройки на новый адрес.
        let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let busy = occupied.local_addr().unwrap().port();

        let chosen = preferred_or_free_port(busy);
        assert_ne!(chosen, busy, "занятый порт выбирать нельзя");
        assert_ne!(chosen, 0);
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        // Первая попытка идёт без паузы: восстановление обязано начинаться так
        // же быстро, как подключение по кнопке. Пользователю разницы между
        // ними нет — и там, и там он ждёт сети.
        assert_eq!(reconnect_delay(1), Duration::ZERO);

        assert_eq!(reconnect_delay(2), RECONNECT_BASE_DELAY);
        assert_eq!(reconnect_delay(3), Duration::from_millis(500));
        assert_eq!(reconnect_delay(5), Duration::from_secs(2));
        assert_eq!(reconnect_delay(20), RECONNECT_MAX_DELAY);
        // Переполнение при большом числе попыток не должно ломать расчёт.
        assert_eq!(reconnect_delay(u32::MAX), RECONNECT_MAX_DELAY);
    }

    #[test]
    fn the_outer_timeout_outlives_the_stages_it_guards() {
        // Предохранитель обязан срабатывать после этапов, а не вместо них.
        // Сработай он раньше — и вместо «сервер не отвечает» или «маршрут по
        // умолчанию удерживает кто-то ещё» пользователь получит
        // бессодержательное «не успело», а мы потеряем причину.
        //
        // Запуск ядра здесь учтён. Без него этот же тест проходил, а
        // предохранитель в жизни обрывал проверку маршрутов за шаг до
        // «Подключено». То же самое проверяется и при сборке — см. `const _`.
        assert!(
            CONNECT_TIMEOUT
                > READY_TIMEOUT + SETTLE_GRACE + ROUTING_TIMEOUT + CORE_STARTUP_ALLOWANCE,
            "срок всей последовательности короче суммы её этапов"
        );
    }

    /// Самый долгий запрос через цепочку реле → выход → адрес проверки,
    /// какой записан в журнале пользователя, — и это у лучшего из восьми
    /// серверов, то есть оценка снизу.
    const SLOWEST_SEEN: Duration = Duration::from_millis(4_700);

    #[test]
    fn a_single_check_outlives_a_slow_but_living_path() {
        // Главная причина долгих подключений. Предел одного запроса стоял на
        // двух секундах, а запрос через цепочку серверов идёт до пяти: треть
        // запросов обрывалась за миг до ответа. Первый этап проваливался сразу
        // после того, как гонка подтвердила тот же сервер, а проверка живости
        // рвала рабочий туннель — и окно показывало «восстанавливаю».
        assert!(
            PROBE_REQUEST_TIMEOUT > SLOWEST_SEEN,
            "предел запроса короче медленного живого пути — он будет рвать рабочие соединения"
        );
        // И этап обязан вмещать больше одной такой попытки: одна неудача —
        // ещё не приговор.
        assert!(READY_TIMEOUT >= PROBE_REQUEST_TIMEOUT * 2);
    }

    #[tokio::test]
    async fn a_check_never_outlives_its_stage() {
        // Попытка, начатая за миг до срока этапа, раньше жила своим полным
        // пределом и перехлёстывала срок — и сумма этапов переставала
        // помещаться в предохранитель.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Принимаем и молчим — так выглядит путь, где ответ не придёт.
            let mut held = Vec::new();
            while let Ok((stream, _)) = silent.accept().await {
                held.push(stream);
            }
        });

        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap())
            .build()
            .unwrap();

        let started = Instant::now();
        let outcome = echo_once(&client, started + Duration::from_millis(300)).await;

        assert!(outcome.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "попытка обязана уложиться в остаток этапа, а заняла {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_failure_is_described_down_to_its_real_cause() {
        // `reqwest` в своём тексте пишет только «error sending request for
        // url». Без причины ниже журнал сообщал лишь, что что-то не вышло.
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("error sending request")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let text = describe(Outer(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "operation timed out",
        )));

        assert_eq!(text, "error sending request: operation timed out");
    }

    #[test]
    fn leaving_a_fallen_server_costs_no_waiting() {
        // Пауза наказывает сервер, который только что отказал. Тот, к которому
        // мы уходим, ничем не провинился, и держать перед ним пользователя без
        // сети столько, сколько накопил счётчик неудач предыдущего, незачем.
        assert_eq!(reconnect_delay_for(1, true), Duration::ZERO);
        assert_eq!(reconnect_delay_for(9, true), Duration::ZERO);
    }

    #[test]
    fn a_broken_machine_is_given_time_on_every_attempt() {
        // Ни одна попытка при отказе машины не идёт вплотную к предыдущей:
        // иначе демон крутит гонку каждые семь секунд, пока не вернётся сеть.
        for attempt in 1..12 {
            assert!(
                reconnect_delay_for(attempt, false) >= SETTLE_AFTER_TEARDOWN,
                "попытка {attempt} идёт без паузы"
            );
        }

        // И дальше пауза растёт: если не выходит и на десятой попытке,
        // непрерывный поток запросов этого не исправит.
        assert!(reconnect_delay_for(9, false) > reconnect_delay_for(4, false));
        assert_eq!(reconnect_delay_for(99, false), RECONNECT_MAX_DELAY);
    }

    #[tokio::test]
    async fn a_fallen_server_is_replaced_at_once() {
        // Проверка того же правила на месте: сервер отказал, демон уходит на
        // другой — и уходит немедленно.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let first = sup.state.server().cloned().unwrap();

        // Счётчик уже накопил неудачи: с прежним расчётом это стоило бы паузы.
        sup.reconnect_attempt = 6;
        sup.begin_reconnect(ReconnectCause::CoreExited { code: None });

        let second = sup.state.server().cloned().unwrap();
        assert_ne!(second, first, "упавший сервер обязан смениться");
        assert_eq!(
            reconnect_delay_for(sup.reconnect_attempt, true),
            Duration::ZERO
        );
    }

    // ──────────────────── гонка кандидатов перед запуском ────────────────────

    #[tokio::test]
    async fn a_pinned_server_never_enters_a_race() {
        // Пользователь просил именно этот сервер и должен увидеть именно его
        // отказ, а не молча оказаться в другой стране.
        let (mut sup, _dir) = make(true);
        let pinned = sup.servers[1].clone();

        sup.desired = Desired::Connected {
            server: Some(pinned.id.clone()),
        };
        assert!(sup.race_pool(&pinned).is_empty());

        // То же самое, когда сервер закреплён настройкой.
        sup.desired = Desired::Connected { server: None };
        sup.settings.auto_select_server = false;
        sup.settings.pinned_server = Some(pinned.id.clone());
        assert!(sup.race_pool(&pinned).is_empty());
    }

    #[tokio::test]
    async fn the_race_starts_with_the_ranked_server_and_adds_the_best_of_the_rest() {
        let (mut sup, _dir) = make(true);
        sup.desired = Desired::Connected { server: None };

        let primary = sup.servers[0].clone();
        // Один из серверов недавно падал. В гонку он допускается — она
        // проверяет его настоящим запросом, — но дорожки сначала достаются
        // остальным.
        let disgraced = sup.servers[2].id.clone();
        sup.failed_servers.insert(disgraced.clone(), Instant::now());

        let pool = sup.race_pool(&primary);

        assert_eq!(
            pool.first().map(|s| &s.id),
            Some(&primary.id),
            "выбранный ранжированием сервер обязан участвовать"
        );
        assert!(pool.len() > 1, "гонка из одного участника ничего не решает");
        assert!(pool.len() <= crate::race::LANES);
        assert_eq!(
            pool.iter().filter(|s| s.id == primary.id).count(),
            1,
            "участник не должен занимать две дорожки"
        );
        assert_eq!(
            pool.last().map(|s| &s.id),
            Some(&disgraced),
            "недавно упавший идёт после остальных, но идёт"
        );
    }

    #[tokio::test]
    async fn a_benched_server_keeps_its_lane_when_it_may_be_the_only_one_working() {
        // Случай из журнала пользователя. Проверка живости ложно сочла туннель
        // мёртвым, единственный рабочий сервер подписки ушёл в штрафной ящик —
        // и восемь минут гонка гоняла остальные, не отвечавшие. Стоило штрафу
        // истечь, первая же гонка выбрала его за шесть секунд.
        //
        // Серверов больше, чем дорожек, поэтому решает очерёдность: отлучённый
        // обязан стоять впереди тех, до кого не доходит даже TCP-замер.
        let (mut sup, _dir) = make(true);
        sup.desired = Desired::Connected { server: None };

        let template = sup.servers[0].clone();
        for i in 0..8 {
            sup.servers.push(ServerProfile::new(
                format!("🇳🇱 Запасной {i}"),
                sont_core::Endpoint::new(format!("spare-{i}.demo.invalid"), 443),
                template.transport.clone(),
                template.source.clone(),
            ));
        }
        assert!(sup.servers.len() > crate::race::LANES + 2);

        // Половина запасных молчит даже на замере.
        let spares: Vec<ProfileId> = sup.servers[4..].iter().map(|s| s.id.clone()).collect();
        for id in &spares[..5] {
            sup.probes.insert(id.clone(), silent(id));
        }

        let benched = sup.servers[1].id.clone();
        sup.probes.insert(
            benched.clone(),
            ProbeResult {
                server: benched.clone(),
                rtt_ms: Some(32),
                loss_percent: 0,
                measured_at_unix_ms: 0,
            },
        );
        sup.failed_servers.insert(benched.clone(), Instant::now());

        let pool = sup.race_pool(&template);

        assert_eq!(pool.len(), crate::race::LANES);
        assert!(
            pool.iter().any(|s| s.id == benched),
            "отлучённый сервер обязан попасть в гонку раньше молчащих"
        );
        let position = |id: &ProfileId| pool.iter().position(|s| &s.id == id);
        for id in &spares[..5] {
            if let Some(silent_at) = position(id) {
                assert!(position(&benched) < Some(silent_at));
            }
        }
    }

    #[tokio::test]
    async fn the_race_winner_becomes_the_server_on_display() {
        // Иначе пользователь смотрит на имя сервера, к которому демон уже не
        // подключается, и узнаёт правду только из «Подключено» с третьим
        // названием.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });

        let ranked = sup.state.server().cloned().unwrap();
        let winner = sup.servers.iter().find(|s| s.id != ranked).unwrap().id.clone();

        sup.handle_internal(Internal::ServerChosen {
            generation: sup.generation,
            server: winner.clone(),
        });

        assert_eq!(sup.state.server(), Some(&winner));
        assert_eq!(sup.state.kind(), "connecting", "гонка не меняет этап подключения");
        assert!(
            !sup.recently_failed(&ranked),
            "проигрыш в гонке — не отказ: сервер мог оказаться просто медленнее"
        );
    }

    #[tokio::test]
    async fn a_stale_check_result_does_not_move_a_new_attempt() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let stale = sup.generation;

        // Пользователь передумал и попросил другой сервер.
        let wanted = sup.servers[2].id.clone();
        sup.handle(Request::Connect {
            server: Some(wanted.clone()),
        });

        sup.handle_internal(Internal::ServerChosen {
            generation: stale,
            server: sup.servers[3].id.clone(),
        });

        assert_eq!(sup.state.server(), Some(&wanted));
    }

    #[test]
    fn echoed_ip_is_parsed_from_trace_response() {
        let body = "fl=123abc\nh=1.1.1.1\nip=203.0.113.5\nts=1700000000\nvisit_scheme=https\n";
        assert_eq!(parse_echoed_ip(body), Some("203.0.113.5".to_owned()));
    }

    // ───────────────────── проверка маршрутизации ─────────────────────

    /// Адрес провайдера пользователя — тот, с которым машина выходит
    /// напрямую, пока туннеля нет.
    const ISP: &str = "46.39.228.11";

    #[test]
    fn a_rotating_exit_pool_is_not_mistaken_for_a_broken_route() {
        // Ровно то, что было в журнале. Один и тот же сервер: запрос через
        // ядро вышел с 185.229.191.52, запрос системы — с 79.127.128.118. Оба
        // из пула провайдера, система уже шла через туннель, а прежняя
        // проверка ждала совпадения адресов и объявляла, что маршрут
        // удерживает кто-то ещё.
        assert!(routed("79.127.128.118", "185.229.191.52", Some(ISP)));
        assert!(routed("89.187.174.104", "185.229.191.52", Some(ISP)));
        assert!(routed("185.229.191.129", "185.229.190.245", Some(ISP)));
    }

    #[test]
    fn traffic_still_leaving_directly_is_a_broken_route() {
        // А вот это — настоящий отказ: система выходит ровно так же, как до
        // подъёма туннеля. Маршрут по умолчанию у кого-то другого.
        assert!(!routed(ISP, "185.229.191.52", Some(ISP)));
    }

    #[test]
    fn matching_the_tunnel_exit_is_still_proof() {
        // Совпадение по-прежнему доказывает всё, что нужно, — просто при пуле
        // выходов случается не всегда.
        assert!(routed("185.229.191.148", "185.229.191.148", Some(ISP)));
        assert!(routed("185.229.191.148", "185.229.191.148", None));
    }

    #[test]
    fn without_a_direct_measurement_the_rule_stays_strict() {
        // Прямой выход узнать не вышло — судить не с чем. Засчитать чужой адрес
        // вслепую значило бы объявить работающим туннель, мимо которого идёт
        // весь трафик. Лучше прежняя строгость, чем такое.
        assert!(!routed("79.127.128.118", "185.229.191.52", None));
    }

    // ──────────────── вытеснение идущей попытки ────────────────

    #[tokio::test]
    async fn a_new_attempt_stops_the_one_it_replaces() {
        // Иначе прежняя доработала бы до конца: держала ядро и порт — в
        // журнале это «127.0.0.1:18965: Only one usage of each socket
        // address» у новой, — а дойдя до второго этапа, подняла бы свой
        // адаптер рядом с её.
        let (mut sup, _dir) = make(true);
        let first = sup.supersede_in_flight();
        let second = sup.supersede_in_flight();

        assert!(first.is_cancelled(), "вытесненная попытка обязана остановиться");
        assert!(!second.is_cancelled(), "новую трогать незачем");
    }

    #[tokio::test]
    async fn disconnecting_stops_the_attempt_in_progress() {
        // Пользователь попросил отключиться — идущая попытка не вправе
        // доделать своё и поднять адаптер уже после этого.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let attempt = sup.in_flight.clone().expect("подключение заводит попытку");

        sup.handle(Request::Disconnect);

        assert!(attempt.is_cancelled());
        assert!(sup.in_flight.is_none());
    }

    #[test]
    fn response_without_address_is_rejected() {
        assert_eq!(parse_echoed_ip("fl=123\nh=1.1.1.1\n"), None);
        assert_eq!(parse_echoed_ip(""), None);
        assert_eq!(parse_echoed_ip("ip=\n"), None);
    }

    #[test]
    fn ip_echo_endpoint_needs_no_dns() {
        // Проверка выполняется, когда системный резолвер уже смотрит в
        // туннель. Обращение по домену тогда упирается в DNS и не проходит.
        let host = IP_ECHO_URL
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap();
        assert!(
            host.parse::<std::net::IpAddr>().is_ok(),
            "адрес проверки обязан быть IP-литералом, а не доменом: {host}"
        );
    }

    #[tokio::test]
    async fn daemon_info_reports_protocol_version() {
        let (mut sup, _dir) = make(false);
        let Response::DaemonInfo(info) = sup.handle(Request::DaemonInfo) else {
            panic!("ожидался DaemonInfo");
        };
        assert_eq!(info.protocol_version, sont_core::PROTOCOL_VERSION);
        assert_eq!(info.daemon_version, env!("CARGO_PKG_VERSION"));
    }
}

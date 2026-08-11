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
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Период публикации статистики и проверки живости ядра.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// Как часто проверяем, что туннель ещё проводит трафик.
///
/// Ядро может остаться живым процессом, а соединение с сервером при этом
/// оборваться — упавший процесс мы замечаем сразу, а вот молчащий туннель
/// виден только по проверке.
const HEALTH_INTERVAL: Duration = Duration::from_secs(30);

/// Сколько неудачных проверок подряд считаем обрывом.
///
/// Одна неудача — это чаще всего мигнувший Wi-Fi, и переподключаться из-за
/// неё значит рвать рабочее соединение на ровном месте.
const HEALTH_FAILURES_BEFORE_RECONNECT: u32 = 2;

/// Потолок паузы между попытками переподключения.
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

/// После скольких неудач подряд пробуем другой сервер.
///
/// Упорствовать на одном сервере бессмысленно, если он просто лёг: у
/// пользователя в подписке есть другие.
const SWITCH_SERVER_AFTER: u32 = 3;

/// Пауза перед попыткой номер `attempt`.
///
/// Удвоение с потолком: первые попытки идут быстро, чтобы короткий обрыв
/// закрылся незаметно, а долгая недоступность не превращалась в непрерывный
/// поток запросов к серверу и расход батареи.
fn reconnect_delay(attempt: u32) -> Duration {
    let seconds = 1u64.checked_shl(attempt.saturating_sub(1)).unwrap_or(u64::MAX);
    Duration::from_secs(seconds).min(RECONNECT_MAX_DELAY)
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
    pub subscription_path: PathBuf,
    pub servers_cache_path: PathBuf,
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
    /// Ядро и сетевой слой подняты, связность подтверждена.
    CoreStarted {
        generation: u64,
        result: Result<Started, TunnelError>,
    },
    DisconnectFinished {
        generation: u64,
    },
    SubscriptionFetched(Result<Fetched, FetchError>),
    /// Версия ядра, полученная при старте.
    CoreVersion(Option<String>),
    /// Показания счётчиков ядра.
    CoreStats(sont_xray::metrics::Counters),
    /// Результат проверки живости туннеля.
    HealthChecked { generation: u64, alive: bool },
}

/// Кэш разобранной подписки, переживающий перезапуск демона.
///
/// Без него после каждого старта пришлось бы ждать ответа панели, а если
/// панель недоступна — оставаться без серверов, хотя ключ никуда не делся.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CachedSubscription {
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
    subscription: Option<SubscriptionStatus>,
    /// Сам ключ подписки. Наружу не отдаётся никогда.
    subscription_secret: Option<Secret>,

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
    fetching: bool,

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
    /// Когда в последний раз проверяли живость.
    last_health_check: Instant,
}

impl Supervisor {
    pub fn new(config: SupervisorConfig, events: broadcast::Sender<Event>, logs: LogBuffer) -> Self {
        let settings: Settings = store::load_or_default(&config.settings_path);
        let favorites: HashSet<ProfileId> = store::load_or_default(&config.favorites_path);

        let mut servers = Vec::new();
        let mut probes = HashMap::new();
        let mut subscription = None;

        if config.demo_servers {
            tracing::warn!("включён демонстрационный набор серверов — подключение не выполняется");
            servers = demo::servers();
            probes = servers
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
        } else if let Some(cached) =
            secrets::load_json::<CachedSubscription>(&config.servers_cache_path)
        {
            // Работаем на кэше, пока не придёт свежий ответ панели: иначе
            // после перезапуска демона пользователь остаётся без серверов,
            // хотя ключ на месте.
            tracing::info!(count = cached.profiles.len(), "загружен кэш подписки");
            servers = cached.profiles;
            subscription = Some(SubscriptionStatus {
                id: cached.id,
                masked_url: cached.masked_url,
                info: cached.info,
            });
        }

        let subscription_secret = match secrets::load(&config.subscription_path) {
            Ok(secret) => secret,
            Err(e) => {
                tracing::error!(error = %e, "не удалось прочитать сохранённый ключ подписки");
                None
            }
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
            subscription,
            subscription_secret,
            events,
            internal_tx,
            internal_rx,
            logs,
            config,
            started_at: Instant::now(),
            http,
            fetching: false,
            generation: 0,
            pending_reason: None,
            desired: Desired::Disconnected,
            reconnect_attempt: 0,
            health_failures: 0,
            last_health_check: Instant::now(),
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
    ) {
        tokio::pin!(shutdown);
        let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("supervisor запущен");

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
                    // Надзор идёт первым: статистику упавшего ядра собирать
                    // незачем, а состояние надо поправить немедленно.
                    self.supervise();
                    self.tick_stats();
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

            Request::SetSubscription { url } => self.set_subscription(url),

            Request::ClearSubscription => {
                self.subscription = None;
                self.subscription_secret = None;
                self.servers.clear();
                self.probes.clear();

                if let Err(e) = secrets::clear(&self.config.subscription_path) {
                    tracing::error!(error = %e, "не удалось удалить ключ подписки");
                }
                if let Err(e) = secrets::clear(&self.config.servers_cache_path) {
                    tracing::error!(error = %e, "не удалось удалить кэш подписки");
                }

                self.emit(Event::ServerListUpdated { count: 0 });
                // Оставлять поднятый туннель без подписки бессмысленно.
                if !matches!(self.state, TunnelState::Disconnected { .. }) {
                    self.begin_disconnect(DisconnectReason::Reconfigured);
                }
                Response::Accepted
            }

            Request::RefreshSubscription => match self.begin_fetch() {
                Ok(()) => Response::Accepted,
                Err(e) => Response::Error(e),
            },

            Request::ListServers => Response::Servers(self.server_views()),

            Request::ProbeServers { .. } => {
                if self.servers.is_empty() {
                    return Response::Error(IpcError::Tunnel(TunnelError::NoUsableServers));
                }
                // Замеры появятся вместе с probe::Prober; сейчас отдаём то,
                // что уже известно, не выдавая это за свежий результат.
                for probe in self.probes.values().cloned().collect::<Vec<_>>() {
                    self.emit(Event::Probe(probe));
                }
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

    fn set_subscription(&mut self, url: Secret) -> Response {
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

        let status = SubscriptionStatus {
            id: SubscriptionId::from_url(raw),
            masked_url: url.masked(),
            info: SubscriptionInfo::default(),
        };

        // Ключ от другой подписки — прежние серверы к нему отношения не имеют.
        self.servers.clear();
        self.probes.clear();

        if let Err(e) = secrets::store(&self.config.subscription_path, &url) {
            tracing::error!(error = %e, "не удалось сохранить ключ подписки");
            return Response::Error(IpcError::Internal {
                detail: format!("не удалось сохранить ключ: {e}"),
            });
        }

        self.subscription_secret = Some(url);
        self.subscription = Some(status);
        tracing::info!("ключ подписки сохранён");

        // Событие `SubscriptionUpdated` намеренно не публикуем здесь: оно
        // означает «подписка прочитана» и должно нести настоящие данные.
        // Сообщив о сохранении ключа тем же событием с пустыми показателями,
        // мы заставили бы подписчиков принять заглушку за результат загрузки.
        self.emit(Event::ServerListUpdated { count: 0 });

        // Сразу пробуем прочитать: пользователь должен увидеть результат
        // ввода ключа, а не пустой список с предложением что-то обновить.
        if let Err(e) = self.begin_fetch() {
            return Response::Error(e);
        }

        Response::Accepted
    }

    /// Запускает фоновое получение подписки.
    fn begin_fetch(&mut self) -> Result<(), IpcError> {
        let Some(secret) = self.subscription_secret.clone() else {
            return Err(IpcError::Tunnel(TunnelError::NoSubscription));
        };
        let Some(http) = self.http.clone() else {
            return Err(IpcError::Internal {
                detail: "HTTP-клиент недоступен".into(),
            });
        };

        if self.fetching {
            // Не ошибка: запрос уже идёт, результат придёт событием.
            return Ok(());
        }
        self.fetching = true;

        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let result = http.fetch(&secret).await;
            let _ = tx.send(Internal::SubscriptionFetched(result)).await;
        });

        Ok(())
    }

    /// Применяет результат получения подписки.
    fn apply_fetched(&mut self, result: Result<Fetched, FetchError>) {
        self.fetching = false;

        let fetched = match result {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "не удалось обновить подписку");
                // Старый список серверов остаётся в силе: недоступность
                // панели не повод лишать пользователя работающих серверов.
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
                skipped = fetched.skipped,
                "часть строк подписки не разобрана"
            );
        }
        tracing::info!(count = fetched.profiles.len(), "подписка обновлена");

        // Профиль, который текущее ядро не потянет, лучше отметить сразу:
        // иначе пользователь упрётся в непонятную ошибку при подключении.
        let needs_xray = fetched.profiles.iter().filter(|p| p.transport.requires_xray()).count();
        if needs_xray > 0 {
            tracing::warn!(
                count = needs_xray,
                "серверов с транспортом XHTTP: он поддерживается только ядром Xray"
            );
        }

        // Замеры серверов, которых больше нет в подписке, только занимают
        // место и путают автовыбор.
        let live: HashSet<ProfileId> = fetched.profiles.iter().map(|p| p.id.clone()).collect();
        self.probes.retain(|id, _| live.contains(id));

        self.servers = fetched.profiles;

        let mut info = fetched.info;
        info.server_count = self.servers.len() as u32;

        if let Some(status) = self.subscription.as_mut() {
            status.info = info.clone();
        }

        if let Some(status) = self.subscription.clone() {
            let cache = CachedSubscription {
                id: status.id.clone(),
                masked_url: status.masked_url.clone(),
                profiles: self.servers.clone(),
                info,
            };
            if let Err(e) = secrets::store_json(&self.config.servers_cache_path, &cache) {
                tracing::error!(error = %e, "не удалось сохранить кэш подписки");
            }
            self.emit(Event::SubscriptionUpdated(status));
        }

        self.emit(Event::ServerListUpdated {
            count: self.servers.len() as u32,
        });
    }

    fn patch_settings(&mut self, patch: SettingsPatch) -> Response {
        let outcome = patch.apply(&mut self.settings);

        if let Err(e) = store::save(&self.config.settings_path, &self.settings) {
            tracing::error!(error = %e, "не удалось сохранить настройки");
            return Response::Error(IpcError::Internal {
                detail: format!("не удалось сохранить настройки: {e}"),
            });
        }

        if outcome.needs_core_restart && self.state.is_connected() {
            tracing::info!("настройки требуют перезапуска ядра");
        }
        if outcome.needs_firewall_reapply {
            tracing::info!("настройки требуют переприменения правил firewall");
        }

        Response::Settings(self.settings.clone())
    }

    // ─────────────────────────── переходы ───────────────────────────

    fn begin_connect(&mut self, explicit: Option<ProfileId>) -> Result<(), TunnelError> {
        let id = self.select_server(explicit.clone())?;

        // Намерение пользователя запоминаем до всех проверок: даже если эта
        // попытка не удастся, демон должен продолжать добиваться соединения.
        self.desired = Desired::Connected { server: explicit };
        self.reconnect_attempt = 0;

        self.set_state(TunnelState::Connecting {
            server: id.clone(),
            attempt: 1,
        });
        self.launch(id, None, Duration::ZERO)
    }

    /// Запускает ядро и сетевой слой для выбранного сервера.
    ///
    /// Общий путь для первого подключения и для восстановления: разойдись они,
    /// и восстановление рано или поздно начнёт отличаться от подключения в
    /// мелочах, которые всплывут только у пользователя.
    fn launch(
        &mut self,
        id: ProfileId,
        previous: Option<Started>,
        delay: Duration,
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
            return Err(TunnelError::CoreStartFailed {
                detail: reason.to_owned(),
            });
        }

        self.generation += 1;
        let generation = self.generation;

        // Служебный порт выбираем здесь, а не внутри фоновой задачи: его адрес
        // нужен нам самим, чтобы потом снимать статистику.
        let runtime = runtime_info(&self.settings);
        self.metrics_url = Some(format!("http://{}/debug/vars", runtime.metrics_listen));
        self.proxy = Some(sont_ipc::ProxyEndpoints {
            http: runtime.http_listen.clone(),
            socks: runtime.probe_listen.clone(),
        });
        self.last_counters = None;
        self.stats = Stats::default();
        self.health_failures = 0;
        self.last_health_check = Instant::now();

        let tx = self.internal_tx.clone();
        let launcher = Arc::clone(&self.launcher);
        let settings = self.settings.clone();
        let config_path = self.config.core_config_path.clone();

        tokio::spawn(async move {
            // Прежний сеанс гасим до паузы, а не после: он держит маршруты и
            // TUN-адаптер, и оставлять их на время ожидания незачем.
            if let Some(previous) = previous {
                shutdown_started(previous).await;
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            // Общий предохранитель на всю последовательность.
            //
            // Внутри у каждого этапа свой срок, но сторонний код может
            // заблокироваться так, что до проверки дело не дойдёт. Тогда
            // пользователь остаётся с вечным «подключаюсь» и без единого
            // способа это прервать. Лучше сдаться с внятной причиной.
            let result = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                start_core(&launcher, &profile, &settings, &runtime, &config_path),
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
            let _ = tx.send(Internal::CoreStarted { generation, result }).await;
        });

        Ok(())
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

        // Упорствовать на одном сервере бессмысленно, если он лёг: в подписке
        // есть другие, и пользователю важно вернуться в сеть, а не именно на
        // этот сервер.
        let target = if attempt > SWITCH_SERVER_AFTER {
            self.next_server(current.as_ref())
        } else {
            current
        };

        let Some(target) = target else {
            tracing::error!("восстанавливать соединение не на чем: серверов нет");
            self.fail(TunnelError::NoUsableServers);
            return;
        };

        let delay = reconnect_delay(attempt);
        tracing::warn!(
            attempt,
            server = %target,
            delay_secs = delay.as_secs(),
            ?cause,
            "восстанавливаю соединение"
        );

        self.set_state(TunnelState::Reconnecting {
            server: target.clone(),
            cause,
            attempt,
        });

        let previous = self.active.take();
        if let Err(e) = self.launch(target, previous, delay) {
            // Ошибка на этом шаге означает негодный профиль, а не обрыв:
            // повторять с тем же результатом смысла нет.
            tracing::error!(error = %e, "не удалось начать восстановление");
            self.fail(e);
        }
    }

    /// Следующий сервер по качеству после указанного.
    ///
    /// Перебор по кругу: дойдя до конца списка, возвращаемся к лучшему.
    fn next_server(&self, after: Option<&ProfileId>) -> Option<ProfileId> {
        let mut ranked: Vec<&ServerProfile> = self.servers.iter().collect();
        ranked.sort_by_key(|s| {
            self.probes
                .get(&s.id)
                .map_or(u32::MAX - 1, ProbeResult::score)
        });

        let position = after.and_then(|id| ranked.iter().position(|s| &s.id == id));
        match position {
            Some(i) => ranked.get((i + 1) % ranked.len()).map(|s| s.id.clone()),
            None => ranked.first().map(|s| s.id.clone()),
        }
    }

    /// Переводит соединение в отказ и снимает намерение.
    ///
    /// Используется там, где повторять попытку заведомо бесполезно: демон
    /// перестаёт бороться, а пользователь получает причину.
    fn fail(&mut self, error: TunnelError) {
        let blocked = self.settings.firewall.survives_daemon_crash();
        self.desired = Desired::Disconnected;
        self.reconnect_attempt = 0;
        self.set_state(TunnelState::Failed { error, blocked });
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
        if self.last_health_check.elapsed() < HEALTH_INTERVAL {
            return;
        }
        self.last_health_check = Instant::now();

        let Some(proxy) = self.proxy.clone() else {
            return;
        };
        let generation = self.generation;
        let tx = self.internal_tx.clone();

        tokio::spawn(async move {
            let alive = server_responds(&proxy.socks).await.is_ok();
            let _ = tx
                .send(Internal::HealthChecked { generation, alive })
                .await;
        });
    }

    /// Обрабатывает результат проверки живости.
    fn apply_health(&mut self, alive: bool) {
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
            Internal::CoreStarted { generation, result } => {
                if generation != self.generation {
                    tracing::debug!(
                        generation,
                        current = self.generation,
                        "устаревшее подключение отброшено"
                    );
                    // Всё поднятое отменённой попыткой нужно погасить, иначе
                    // маршруты останутся указывать в брошенный туннель.
                    if let Ok(started) = result {
                        tokio::spawn(shutdown_started(started));
                    }
                    return;
                }

                match result {
                    Ok(started) => {
                        let Some(server) = self.state.server().cloned() else {
                            tokio::spawn(shutdown_started(started));
                            return;
                        };
                        tracing::info!(pid = started.core.pid(), "туннель поднят");
                        self.active = Some(started);
                        // Соединение состоялось — счётчики надзора начинаются
                        // заново, иначе следующий обрыв унаследует длинную
                        // паузу от прошлых неудач.
                        self.reconnect_attempt = 0;
                        self.health_failures = 0;
                        self.last_health_check = Instant::now();
                        self.set_state(TunnelState::Connected {
                            server,
                            since_unix_ms: now_unix_ms(),
                            tun: tun_info(&self.settings),
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
                            self.begin_reconnect(ReconnectCause::CoreExited { code: None });
                        } else {
                            self.fail(error);
                        }
                    }
                }
            }

            Internal::SubscriptionFetched(result) => self.apply_fetched(result),

            Internal::CoreVersion(version) => {
                match &version {
                    Some(v) => tracing::info!(version = %v, "версия ядра"),
                    None => tracing::warn!("не удалось определить версию ядра"),
                }
                self.core_version = version;
            }

            Internal::CoreStats(counters) => self.apply_counters(counters),

            Internal::HealthChecked { generation, alive } => {
                // Результат проверки от прошлого сеанса ничего не говорит о
                // текущем: применять его — значит рвать заново поднятое
                // соединение из-за отказа предыдущего.
                if generation == self.generation {
                    self.apply_health(alive);
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
            return Err(if self.subscription_secret.is_none() {
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

        self.servers
            .iter()
            .min_by_key(|s| {
                self.probes
                    .get(&s.id)
                    .map_or(u32::MAX - 1, ProbeResult::score)
            })
            .map(|s| s.id.clone())
            .ok_or(TunnelError::NoUsableServers)
    }

    fn set_state(&mut self, state: TunnelState) {
        if self.state == state {
            return;
        }
        tracing::info!(from = self.state.kind(), to = state.kind(), "смена состояния");
        self.state = state.clone();
        self.emit(Event::StateChanged(state));
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
            subscription: self.subscription.clone(),
            server_count: self.servers.len() as u32,
            // Адреса отдаём только пока соединение действительно поднято:
            // иначе клиент пропишет в систему прокси, за которым никого нет.
            proxy: self.state.is_connected().then(|| self.proxy.clone()).flatten(),
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

/// Поднимает ядро и убеждается, что трафик через туннель действительно ходит.
///
/// Порядок шагов выбран так, чтобы каждая неудача давала пользователю точную
/// причину: сначала генерация конфигурации, затем её проверка самим ядром,
/// затем запуск, и только потом — проверка связности.
async fn start_core(
    launcher: &CoreLauncher,
    profile: &sont_core::ServerProfile,
    settings: &Settings,
    runtime: &sont_xray::RuntimeInfo,
    config_path: &std::path::Path,
) -> Result<Started, TunnelError> {
    let config = sont_xray::build(profile, settings, runtime).map_err(|e| {
        TunnelError::CoreStartFailed {
            detail: e.to_string(),
        }
    })?;

    write_core_config(config_path, &config).map_err(|e| TunnelError::CoreStartFailed {
        detail: format!("не удалось записать конфигурацию ядра: {e}"),
    })?;

    let mut core = launcher
        .spawn(config_path)
        .await
        .map_err(|e| TunnelError::CoreStartFailed {
            detail: e.to_string(),
        })?;

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
        ready = server_responds(&runtime.probe_listen) => ready,
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
                TunnelError::CoreStartFailed {
                    detail: "нужны права администратора: создание сетевого адаптера требует их".to_owned(),
                }
            } else {
                TunnelError::CoreStartFailed { detail }
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
        return Ok(Started { core, tunnel: None });
    }

    // ── Этап 2: поднимаем сетевой слой ────────────────────────────────
    //
    // Адрес сервера обязан идти мимо туннеля, иначе подключение ядра к нему
    // замкнётся само на себя.
    let bypass = resolve_bypass(&profile.endpoint.host);
    if bypass.is_empty() {
        core.shutdown().await;
        return Err(TunnelError::NetworkSetupFailed {
            detail: format!("не удалось определить адрес сервера {}", profile.endpoint.host),
        });
    }

    let tunnel = match crate::tunnel::Tunnel::start(crate::tunnel::TunnelConfig {
        socks,
        tun_name: runtime.tun_name.clone(),
        mtu: runtime.mtu,
        bypass,
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
    match system_routed_through_tunnel(&tunnel_ip).await {
        Ok(()) => Ok(Started {
            core,
            tunnel: Some(tunnel),
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

/// Ядро и сетевой слой, поднятые вместе.
pub struct Started {
    pub core: CoreProcess,
    /// `None` в режиме прокси: там адаптер не создаётся.
    pub tunnel: Option<crate::tunnel::Tunnel>,
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
fn resolve_bypass(host: &str) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }

    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let mut ips: Vec<std::net::IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Err(e) => {
            tracing::error!(%host, error = %e, "не удалось разрешить адрес сервера");
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
/// Рукопожатие Reality с XHTTP на живом сервере укладывается в доли секунды;
/// если ответа нет и через пятнадцать, дело не в медленной сети.
const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Сколько ждём, пока система переключится на туннель.
///
/// Отдельный, более короткий срок: маршруты Windows устанавливает быстро, и
/// если за это время системный трафик не пошёл через туннель, дело не в
/// задержке, а в том, что маршрут удерживает кто-то другой.
const ROUTING_TIMEOUT: Duration = Duration::from_secs(10);

/// Шаг опроса при проверках.
///
/// Подключение завершается по первой удачной попытке, поэтому шаг напрямую
/// определяет, насколько быстро пользователь увидит «Подключено». Частый
/// опрос localhost ничего не стоит.
const READY_INTERVAL: Duration = Duration::from_millis(200);

/// Пауза перед первой проверкой маршрутизации.
///
/// Ровно чтобы сетевой слой успел начать работу, а не «на всякий случай»:
/// дальше решает опрос.
const SETTLE_GRACE: Duration = Duration::from_millis(200);

/// Предел одной попытки проверки.
///
/// Короче общего срока намеренно: зависший запрос не должен занимать весь
/// цикл, иначе за отведённое время мы сделаем две попытки вместо десятка.
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Адрес, возвращающий внешний IP обратившегося.
///
/// Обращение идёт по IP-литералу, а не по домену, и это принципиально:
/// проверка выполняется в тот момент, когда системный резолвер уже смотрит в
/// туннель. Запрос к домену тогда упирается в DNS и не выполняется вовсе — а
/// прошлая версия проверки не отличала «не получил ответа» от «получил другой
/// адрес» и в обоих случаях винила посторонний VPN-клиент.
const IP_ECHO_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

/// Достаёт внешний адрес из ответа вида `ip=203.0.113.5`.
fn parse_echoed_ip(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("ip="))
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
}

/// Этап 1: отвечает ли сервер. Возвращает внешний адрес, видимый через него.
async fn server_responds(probe_listen: &str) -> Result<String, TunnelError> {
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
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut last_error = String::from("ответа нет");
    let mut tunnel_ip = None;

    while Instant::now() < deadline {
        match client.get(IP_ECHO_URL).send().await {
            Ok(r) if r.status().is_success() => match r.text().await {
                Ok(body) => match parse_echoed_ip(&body) {
                    Some(ip) => {
                        tunnel_ip = Some(ip);
                        break;
                    }
                    None => last_error = "ответ без адреса".to_owned(),
                },
                Err(e) => last_error = e.to_string(),
            },
            Ok(r) => last_error = format!("неожиданный код ответа {}", r.status().as_u16()),
            Err(e) => last_error = e.to_string(),
        }
        tokio::time::sleep(READY_INTERVAL).await;
    }

    let Some(tunnel_ip) = tunnel_ip else {
        tracing::warn!(%last_error, "сервер не отвечает");
        return Err(TunnelError::HandshakeTimeout {
            seconds: READY_TIMEOUT.as_secs(),
        });
    };

    Ok(tunnel_ip)
}

/// Этап 3: пошёл ли системный трафик через туннель.
///
/// Проверка сервера доказывает лишь его исправность. Если маршруты не
/// применились, обычный трафик по-прежнему идёт мимо, и объявлять соединение
/// установленным нельзя: пользователь увидит «Подключено» при неработающем VPN.
async fn system_routed_through_tunnel(tunnel_ip: &str) -> Result<(), TunnelError> {
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

    while Instant::now() < deadline {
        match direct.get(IP_ECHO_URL).send().await {
            Ok(r) => match r.text().await {
                Ok(body) => match parse_echoed_ip(&body) {
                    Some(ip) => {
                        if ip == tunnel_ip {
                            tracing::info!(%ip, "маршрутизация применилась");
                            return Ok(());
                        }
                        tracing::debug!(system = %ip, tunnel = %tunnel_ip, "система идёт мимо туннеля");
                        system_ip = Some(ip);
                    }
                    None => last_error = "ответ без адреса".to_owned(),
                },
                Err(e) => last_error = e.to_string(),
            },
            Err(e) => last_error = e.to_string(),
        }
        tokio::time::sleep(READY_INTERVAL).await;
    }

    // Таблицу маршрутов показываем до остановки ядра: после его завершения
    // маршруты исчезнут вместе с интерфейсом, и понять, кто выиграл маршрут
    // по умолчанию, будет уже нельзя.
    log_default_routes().await;

    match system_ip {
        Some(ip) => {
            tracing::warn!(system = %ip, tunnel = %tunnel_ip, "маршрутизация не применилась");
            Err(TunnelError::NetworkSetupFailed {
                detail: format!(
                    "трафик системы выходит адресом {ip} вместо {tunnel_ip} — \
                     маршрут по умолчанию удерживает кто-то ещё"
                ),
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

fn runtime_info(settings: &Settings) -> sont_xray::RuntimeInfo {
    sont_xray::RuntimeInfo {
        log_level: settings.log_level.clone(),
        // Служебные порты берём свободные: их адреса живут внутри демона, и
        // фиксированный номер породил бы конфликт при быстром переподключении,
        // когда прежний экземпляр ядра ещё не освободил сокет.
        metrics_listen: format!("127.0.0.1:{}", pick_free_port()),
        probe_listen: format!("127.0.0.1:{}", pick_free_port()),
        // HTTP-порт стараемся держать постоянным, но не любой ценой.
        //
        // Постоянство удобно: адрес прописан в настройках прокси Windows и не
        // меняется при переподключении. Но если порт занят — другим клиентом
        // или собственным подвисшим ядром, — упереться в это и вовсе не
        // подключиться было бы хуже. Агент в сеансе пользователя переприменяет
        // настройки при каждой смене состояния, поэтому смену порта система
        // переживает без потерь.
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

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|addr| addr.port())
        .unwrap_or(18964)
}

fn tun_info(settings: &Settings) -> TunInfo {
    let runtime = runtime_info(settings);
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
fn write_core_config(path: &std::path::Path, config: &serde_json::Value) -> std::io::Result<()> {
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
            result: Ok(Started {
                core: CoreProcess::placeholder(),
                tunnel: Some(crate::tunnel::Tunnel::placeholder()),
            }),
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
                subscription_path: dir.path().join("subscription.bin"),
                servers_cache_path: dir.path().join("servers.bin"),
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

    #[tokio::test]
    async fn subscription_url_must_be_http() {
        let (mut sup, _dir) = make(false);
        let response = sup.handle(Request::SetSubscription {
            url: Secret::new("vless://not-a-subscription"),
        });
        assert!(matches!(
            response,
            Response::Error(IpcError::InvalidRequest { .. })
        ));
        assert!(sup.subscription.is_none());
    }

    #[tokio::test]
    async fn subscription_is_stored_masked() {
        let (mut sup, _dir) = make(false);
        let url = "https://panel.example/sub/VERY-SECRET-TOKEN";
        assert_eq!(
            sup.handle(Request::SetSubscription {
                url: Secret::new(url)
            }),
            Response::Accepted
        );

        let status = sup.subscription.as_ref().expect("подписка должна сохраниться");
        assert!(
            !status.masked_url.contains("VERY-SECRET-TOKEN"),
            "маска не должна раскрывать токен: {}",
            status.masked_url
        );

        // Снимок состояния тоже не должен содержать настоящую ссылку.
        let json = serde_json::to_string(&sup.snapshot()).unwrap();
        assert!(!json.contains("VERY-SECRET-TOKEN"), "утечка через снимок: {json}");
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
    async fn repeated_failures_move_to_another_server() {
        // Держаться за упавший сервер бессмысленно, когда в подписке есть
        // другие: пользователю нужна сеть, а не конкретный сервер.
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let first = sup.state.server().cloned().unwrap();

        for _ in 0..=SWITCH_SERVER_AFTER {
            sup.begin_reconnect(ReconnectCause::CoreExited { code: None });
        }

        let now = sup.state.server().cloned().unwrap();
        assert_ne!(now, first, "после серии неудач сервер должен смениться");
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

        sup.apply_health(false);
        assert!(sup.state.is_connected(), "одна неудача — ещё не обрыв");

        sup.apply_health(true);
        assert_eq!(sup.health_failures, 0, "успех обнуляет счётчик");
        assert!(sup.state.is_connected());
    }

    #[tokio::test]
    async fn repeated_health_failures_trigger_reconnect() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;
        sup.handle_internal(core_started(g));

        for _ in 0..HEALTH_FAILURES_BEFORE_RECONNECT {
            sup.apply_health(false);
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
        });
        assert_eq!(
            sup.health_failures, 0,
            "результат прошлого сеанса не должен влиять на текущий"
        );
        assert!(sup.state.is_connected());
    }

    #[tokio::test]
    async fn unrecoverable_error_stops_the_attempts() {
        // Отсутствующая подписка от повторов не появится, а бесконечный цикл
        // попыток скрыл бы от пользователя настоящую причину.
        let (mut sup, _dir) = make(false);
        sup.desired = Desired::Connected { server: None };
        sup.handle_internal(Internal::CoreStarted {
            generation: sup.generation,
            result: Err(TunnelError::NoSubscription),
        });

        assert_eq!(sup.state.kind(), "failed");
        assert_eq!(sup.desired, Desired::Disconnected);
    }

    #[tokio::test]
    async fn transient_error_keeps_trying() {
        let (mut sup, _dir) = make(true);
        sup.handle(Request::Connect { server: None });
        let g = sup.generation;

        sup.handle_internal(Internal::CoreStarted {
            generation: g,
            result: Err(TunnelError::HandshakeTimeout { seconds: 20 }),
        });

        assert_eq!(
            sup.state.kind(),
            "reconnecting",
            "временная ошибка не повод сдаваться"
        );
    }

    #[test]
    fn service_ports_differ_between_launches() {
        // Иначе быстрое переподключение упрётся в сокет, ещё занятый
        // прежним экземпляром ядра.
        let settings = Settings::default();
        let first = runtime_info(&settings);
        let second = runtime_info(&settings);

        assert_ne!(first.probe_listen, second.probe_listen);
        assert_ne!(first.metrics_listen, second.metrics_listen);
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
        assert_eq!(reconnect_delay(1), Duration::from_secs(1));
        assert_eq!(reconnect_delay(2), Duration::from_secs(2));
        assert_eq!(reconnect_delay(4), Duration::from_secs(8));
        assert_eq!(reconnect_delay(10), RECONNECT_MAX_DELAY);
        // Переполнение при большом числе попыток не должно ломать расчёт.
        assert_eq!(reconnect_delay(u32::MAX), RECONNECT_MAX_DELAY);
    }

    #[tokio::test]
    async fn server_rotation_wraps_around() {
        let (sup, _dir) = make(true);
        let mut seen = std::collections::HashSet::new();
        let mut current = sup.next_server(None);

        for _ in 0..sup.servers.len() {
            let id = current.expect("сервер должен находиться");
            assert!(seen.insert(id.clone()), "перебор не должен повторяться");
            current = sup.next_server(Some(&id));
        }

        // Круг замкнулся: снова первый.
        assert_eq!(current, sup.next_server(None));
    }

    #[test]
    fn echoed_ip_is_parsed_from_trace_response() {
        let body = "fl=123abc\nh=1.1.1.1\nip=203.0.113.5\nts=1700000000\nvisit_scheme=https\n";
        assert_eq!(parse_echoed_ip(body), Some("203.0.113.5".to_owned()));
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

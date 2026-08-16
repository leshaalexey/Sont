//! Сообщения протокола.

use serde::{Deserialize, Serialize};
use sont_core::{
    ProbeResult, ProfileId, ReconnectCause, Secret, ServerProfile, Settings, SettingsPatch, Stats,
    SubscriptionId, SubscriptionInfo, TransportKind, TunnelError, TunnelState,
};

/// Кадр, летящий по каналу в любую сторону.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum Frame {
    /// Рукопожатие. Клиент шлёт первым, демон отвечает своим.
    Hello(Hello),
    Request {
        id: u64,
        #[serde(flatten)]
        payload: Request,
    },
    Response {
        id: u64,
        #[serde(flatten)]
        payload: Response,
    },
    /// Событие от демона. Без `id` — это не ответ ни на что.
    Event(Event),
}

/// Рукопожатие.
///
/// Демон и tray обновляются раздельно, поэтому несовпадение версий — штатная
/// ситуация. Обнаружить её надо здесь и показать пользователю понятный текст,
/// а не ловить потом невнятные ошибки десериализации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,
    /// Версия отправителя, для диагностики.
    pub agent_version: String,
}

impl Hello {
    pub fn new(agent_version: impl Into<String>) -> Self {
        Self {
            protocol_version: sont_core::PROTOCOL_VERSION,
            agent_version: agent_version.into(),
        }
    }

    pub fn is_compatible(&self) -> bool {
        self.protocol_version == sont_core::PROTOCOL_VERSION
    }
}

// ───────────────────────────── запросы ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    /// Текущее состояние целиком — то, чем UI наполняет экран при открытии.
    GetStatus,
    /// Подписаться на поток событий. До этого демон событий не шлёт и,
    /// в частности, не считает статистику.
    SubscribeEvents,
    Connect {
        /// `None` — выбрать сервер по настройкам (закреплённый или автовыбор).
        #[serde(default)]
        server: Option<ProfileId>,
    },
    Disconnect,
    /// Добавить подписку. Демон проверяет URL и сразу пытается её прочитать.
    ///
    /// Повторное добавление той же ссылки — не ошибка и не дубликат: ключ
    /// перезаписывается, а подписка перечитывается. Пользователь, вставивший
    /// ссылку дважды, ожидает именно этого.
    AddSubscription {
        url: Secret,
    },
    /// Удалить одну подписку и пришедшие из неё серверы.
    RemoveSubscription {
        id: SubscriptionId,
    },
    ListSubscriptions,
    /// Отдать ключ подписки в открытом виде.
    ///
    /// Единственный способ получить его наружу, и он намеренно отдельный:
    /// обычный `ListSubscriptions` возвращает маску, потому что показать
    /// подписку в списке можно и без ключа. Ключ нужен ровно для двух
    /// действий пользователя — скопировать и показать QR, чтобы перенести
    /// подписку на телефон, — и запрашивается только в этот момент.
    ///
    /// Демон в ответ ничего не пишет в журнал: строка запроса и так видна в
    /// отладочном выводе IPC, а вот ответ туда попасть не должен.
    RevealSubscription {
        id: SubscriptionId,
    },
    /// Удалить все подписки и все серверы.
    ClearSubscription,
    RefreshSubscription {
        /// `None` — перечитать все.
        #[serde(default)]
        id: Option<SubscriptionId>,
    },
    ListServers,
    ProbeServers {
        /// `None` — замерить все.
        #[serde(default)]
        servers: Option<Vec<ProfileId>>,
    },
    /// Настройки прокси в системе прописаны — можно доводить дело до конца.
    ///
    /// Шлёт тот, кто их прописал: агент в сеансе пользователя или CLI. Демон в
    /// ответ обрывает установленные соединения, чтобы приложения переоткрыли
    /// их уже через прокси.
    ///
    /// Отдельный запрос, а не действие по факту подключения, потому что
    /// момент важен: оборви соединения раньше, чем адрес объявлен, — и
    /// приложения переподключатся мимо прокси, то есть ровно туда, откуда мы
    /// их уводим. Знать этот момент может только тот, кто объявляет.
    ProxyAnnounced,
    GetSettings,
    PatchSettings {
        #[serde(flatten)]
        patch: SettingsPatch,
    },
    GetLogs {
        #[serde(default = "default_log_tail")]
        tail: u32,
    },
    /// Собрать архив для поддержки. Секреты из него вырезаются.
    CollectDiagnostics,
    DaemonInfo,
}

fn default_log_tail() -> u32 {
    200
}

// ───────────────────────────── ответы ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum Response {
    /// Команда принята. Долгие операции (подключение, замеры) отвечают этим
    /// сразу, а результат приходит событиями.
    Accepted,
    Status(StatusSnapshot),
    Servers(Vec<ServerView>),
    Subscriptions(Vec<SubscriptionStatus>),
    /// Ключ подписки в открытом виде — ответ на `RevealSubscription`.
    ///
    /// `Secret` печатает маску в `Debug`, поэтому случайная отладочная печать
    /// ответа его не раскроет.
    SubscriptionSecret(Secret),
    Settings(Settings),
    Logs(Vec<String>),
    DiagnosticsPath(String),
    DaemonInfo(DaemonInfo),
    Error(IpcError),
}

/// Полный снимок состояния для UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub state: TunnelState,
    pub stats: Stats,
    /// Все подписки пользователя.
    ///
    /// Список, а не одна: у одного провайдера может лежать сервер, а у
    /// другого — резерв на случай, когда первый недоступен целиком. Ради
    /// этого случая режим и существует, и заставлять пользователя вручную
    /// переставлять ключ в такой момент — ровно тогда, когда у него нет
    /// интернета, — бессмысленно.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subscriptions: Vec<SubscriptionStatus>,
    /// Сколько серверов сейчас известно.
    pub server_count: u32,
    /// Адреса локальных прокси, пока соединение поднято.
    ///
    /// Доступны в обоих режимах: в режиме прокси через них идёт весь трафик,
    /// в режиме туннеля ими можно пользоваться точечно, направив в туннель
    /// отдельное приложение.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyEndpoints>,
}

/// Адреса локальных прокси, поднятых ядром.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEndpoints {
    pub http: String,
    pub socks: String,
}

/// Состояние подписки в виде, пригодном для показа.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionStatus {
    pub id: SubscriptionId,
    /// URL под маской: `htt…oken`. Настоящий URL наружу не отдаётся никогда —
    /// UI нечего с ним делать, а утечь он может.
    pub masked_url: String,
    pub info: SubscriptionInfo,
}

/// Сервер в том виде, в каком его видит UI.
///
/// Осознанно без учётных данных: `ServerProfile` содержит UUID и пароли, и
/// отправлять их непривилегированному процессу незачем — он с ними ничего не
/// делает, а хранить лишнюю копию секрета в чужом адресном пространстве плохо.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerView {
    pub id: ProfileId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Хост показываем: пользователь имеет право видеть, куда подключается.
    pub host: String,
    pub port: u16,
    pub transport: TransportKind,
    /// Из какой подписки пришёл сервер.
    ///
    /// С одной подпиской поле было бы лишним, с несколькими — необходимым:
    /// иначе в общем списке не видно, чей сервер лёг и какую подписку менять.
    pub subscription: SubscriptionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeResult>,
    pub favorite: bool,
}

impl ServerView {
    /// Проекция профиля без учётных данных.
    pub fn from_profile(profile: &ServerProfile, probe: Option<ProbeResult>, favorite: bool) -> Self {
        Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            country: profile.country.map(|c| c.as_str().to_owned()),
            host: profile.endpoint.host.clone(),
            port: profile.endpoint.port,
            transport: profile.transport.kind(),
            subscription: profile.source.clone(),
            probe,
            favorite,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub daemon_version: String,
    pub protocol_version: u32,
    /// Версия ядра, если оно найдено и прошло проверку целостности.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_version: Option<String>,
    pub platform: String,
    pub uptime_secs: u64,
}

// ───────────────────────────── события ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum Event {
    StateChanged(TunnelState),
    Stats(Stats),
    ServerListUpdated { count: u32 },
    SubscriptionUpdated(SubscriptionStatus),
    Probe(ProbeResult),
    /// Сервер, на котором держалось соединение, перестал работать.
    ///
    /// Отдельное событие, а не оттенок `StateChanged`. Смена состояния
    /// отвечает на вопрос «подключены ли мы», и на неё подписан тот, кому
    /// нужно нарисовать иконку. А здесь другой факт: конкретный сервер
    /// выбыл, и демон уходит на другой. Его хочет знать тот, кто ведёт учёт
    /// качества серверов и объясняет пользователю, почему адрес сменился, —
    /// из «reconnecting» этого не восстановить.
    ServerFailed(ServerFailure),
    /// Ошибка, не привязанная к конкретному запросу.
    Error(IpcError),
    Log { line: String },
}

/// Подробности выбывания сервера.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerFailure {
    /// Кто выбыл.
    pub server: ProfileId,
    /// Имя на момент падения: сервер может исчезнуть из подписки раньше, чем
    /// пользователь посмотрит на журнал, и тогда по одному id ничего не понять.
    pub name: String,
    pub cause: ReconnectCause,
    /// На кого демон переключается. `None` — заменить некем.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switching_to: Option<ProfileId>,
    /// Задержка до нового сервера на последнем замере, мс.
    ///
    /// То самое основание, по которому он выбран. Без него сообщение «перешёл
    /// на другой сервер» ничего не объясняет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switching_to_rtt_ms: Option<u32>,
}

// ───────────────────────────── ошибки ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum IpcError {
    /// Версии протокола не совпали.
    ProtocolMismatch { daemon: u32, client: u32 },
    /// Пир не прошёл проверку личности.
    Unauthorized { detail: String },
    /// Запрос не разобрался или содержит недопустимые значения.
    InvalidRequest { detail: String },
    /// Демон ещё не готов обслуживать запросы.
    NotReady,
    /// Ошибка самого туннеля.
    Tunnel(TunnelError),
    Internal { detail: String },
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolMismatch { daemon, client } => write!(
                f,
                "версии протокола не совпадают: демон {daemon}, приложение {client}"
            ),
            Self::Unauthorized { detail } => write!(f, "доступ запрещён: {detail}"),
            Self::InvalidRequest { detail } => write!(f, "некорректный запрос: {detail}"),
            Self::NotReady => f.write_str("демон ещё не готов"),
            Self::Tunnel(e) => write!(f, "{e}"),
            Self::Internal { detail } => write!(f, "внутренняя ошибка демона: {detail}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<TunnelError> for IpcError {
    fn from(e: TunnelError) -> Self {
        Self::Tunnel(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::{Endpoint, Security, Stream, Transport};

    fn roundtrip(frame: &Frame) {
        let json = serde_json::to_string(frame).unwrap();
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, frame, "не пережил round-trip: {json}");
    }

    #[test]
    fn every_frame_shape_roundtrips() {
        roundtrip(&Frame::Hello(Hello::new("0.1.0")));
        roundtrip(&Frame::Request {
            id: 7,
            payload: Request::Connect {
                server: Some(ProfileId::from_raw("abc")),
            },
        });
        roundtrip(&Frame::Request {
            id: 8,
            payload: Request::GetStatus,
        });
        roundtrip(&Frame::Response {
            id: 7,
            payload: Response::Accepted,
        });
        roundtrip(&Frame::Response {
            id: 9,
            payload: Response::Error(IpcError::NotReady),
        });
        roundtrip(&Frame::Event(Event::StateChanged(TunnelState::default())));
        roundtrip(&Frame::Event(Event::Stats(Stats::default())));
    }

    #[test]
    fn patch_settings_flattens_without_collision() {
        // `patch` разложен в тело запроса — проверяем, что он не конфликтует
        // с полями `method`/`id` конверта.
        let frame = Frame::Request {
            id: 1,
            payload: Request::PatchSettings {
                patch: SettingsPatch {
                    language: Some("en".into()),
                    ..Default::default()
                },
            },
        };
        roundtrip(&frame);
    }

    #[test]
    fn protocol_mismatch_is_detected() {
        let mut hello = Hello::new("0.1.0");
        assert!(hello.is_compatible());
        hello.protocol_version = sont_core::PROTOCOL_VERSION + 1;
        assert!(!hello.is_compatible());
    }

    #[test]
    fn server_view_does_not_carry_credentials() {
        let profile = ServerProfile::new(
            "🇳🇱 Amsterdam",
            Endpoint::new("nl.example.com", 443),
            Transport::Vless(sont_core::transport::Vless {
                uuid: Secret::new("SECRET-UUID-VALUE"),
                flow: None,
                stream: Stream::Tcp,
                security: Security::None,
            }),
            SubscriptionId::from_url("https://panel.example/sub"),
        );

        let view = ServerView::from_profile(&profile, None, false);
        let json = serde_json::to_string(&view).unwrap();

        assert!(
            !json.contains("SECRET-UUID-VALUE"),
            "учётные данные не должны покидать демон: {json}"
        );
        assert_eq!(view.country.as_deref(), Some("NL"));
        assert_eq!(view.host, "nl.example.com");
    }

    #[test]
    fn subscription_url_is_never_serialized_raw() {
        let status = SubscriptionStatus {
            id: SubscriptionId::from_url("https://panel.example/sub/SECRET-TOKEN"),
            masked_url: Secret::new("https://panel.example/sub/SECRET-TOKEN").masked(),
            info: SubscriptionInfo::default(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("SECRET-TOKEN"), "утечка URL подписки: {json}");
    }

    #[test]
    fn log_tail_has_a_default() {
        let req: Request = serde_json::from_str(r#"{"method":"get_logs","params":{}}"#).unwrap();
        assert_eq!(req, Request::GetLogs { tail: 200 });
    }
}

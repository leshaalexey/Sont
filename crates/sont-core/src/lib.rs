//! Доменные типы Sont.
//!
//! Крейт намеренно не зависит ни от tokio, ни от чего-либо платформенного: он
//! компилируется и в привилегированный демон, и в непривилегированное
//! tray-приложение, чтобы рассинхрон моделей ловился компилятором, а не в рантайме.

pub mod error;
pub mod hash;
pub mod profile;
pub mod secret;
pub mod settings;
pub mod state;
pub mod stats;
pub mod transport;

pub use error::{DisconnectReason, ReconnectCause, TunnelError};
pub use profile::{CountryCode, Endpoint, ProfileId, ServerProfile, SubscriptionId};
pub use secret::Secret;
pub use settings::{
    ApplyOutcome, ConnectionMode, DnsMode, DnsSettings, FirewallMode, Settings, SettingsPatch,
    SplitTunnelMode, SplitTunnelRules,
};
pub use state::{TunInfo, TunnelState};
pub use stats::{ProbeResult, Stats, SubscriptionInfo};
pub use transport::{Security, Stream, Transport, TransportKind};

/// Версия IPC-протокола.
///
/// Демон и tray-приложение обновляются раздельно (демон — переустановкой
/// пакета, tray — своим апдейтером), поэтому несовпадение версий это штатная
/// ситуация, которую нужно обнаружить на рукопожатии и показать пользователю,
/// а не выяснять по непонятным ошибкам десериализации.
/// # Когда поднимать
///
/// При любом изменении состава сообщений или их полей. Версия существует не
/// для порядка, а чтобы старый демон и новый клиент обнаружили несовместимость
/// на рукопожатии, а не в виде необъяснимых отказов посреди работы.
///
/// История:
/// * 1 — первоначальный набор.
/// * 2 — добавлены режим подключения (`mode`) и адреса локальных прокси.
/// * 3 — подписок стало несколько: `subscription` в снимке состояния заменён
///   списком, добавлены запросы на добавление и удаление отдельной подписки,
///   а к событиям — падение сервера.
/// * 4 — настройки дирижёра (интервал замеров, порог переключения, число
///   попыток), выдача ключа подписки по запросу и причина переподключения
///   «нашёлся сервер быстрее».
pub const PROTOCOL_VERSION: u32 = 4;

//! Ошибки и причины смены состояния.
//!
//! Все типы здесь сериализуемы: они уходят по IPC в UI, который должен показать
//! пользователю осмысленный текст, а не «что-то пошло не так». Поэтому вместо
//! цепочки `source` — плоские варианты с машинно-различимым дискриминантом и
//! отдельным полем `detail` для технических подробностей.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Почему соединение завершилось.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DisconnectReason {
    /// Пользователь нажал «Отключить».
    UserRequest,
    /// Демон останавливается (выключение системы, перезапуск службы).
    DaemonShutdown,
    /// Настройки изменились так, что нужен полный перезапуск.
    Reconfigured,
    /// Соединение оборвалось и восстановить его не удалось.
    Failed { detail: String },
}

/// Почему демон переподключается.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum ReconnectCause {
    /// Ядро завершилось само.
    CoreExited { code: Option<i32> },
    /// Проверка связности сквозь туннель не прошла N раз подряд.
    HealthCheckFailed { consecutive_failures: u32 },
    /// Сменился сетевой интерфейс или маршрут по умолчанию.
    NetworkChanged,
    /// Машина вышла из сна.
    SystemResumed,
    /// Пользователь выбрал другой сервер.
    ServerSwitched,
    /// Настройки изменились так, что нужна новая конфигурация ядра.
    ///
    /// Не отказ и не выбор пользователя: соединение исправно, но собрано по
    /// устаревшим настройкам. Отдельная причина нужна интерфейсу — переход
    /// в «переподключаюсь» сразу после переключателя иначе выглядит сбоем.
    Reconfigured,
    /// Нашёлся сервер заметно быстрее текущего.
    ///
    /// Отдельная причина, а не оттенок `ServerSwitched`: там решение принял
    /// пользователь, а здесь демон сам, и разрыв всех соединений произошёл без
    /// спроса. Такое надо и объяснить в интерфейсе, и уметь отличить в
    /// журнале от смены сервера руками.
    BetterServerFound {
        /// На сколько миллисекунд новый сервер быстрее.
        gain_ms: u32,
    },
}

/// Ошибка, из-за которой соединение не удалось установить или удержать.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum TunnelError {
    /// Подписка не задана — пользователь ещё не ввёл ключ.
    NoSubscription,
    /// Подписка задана, но серверов из неё получить не удалось.
    SubscriptionUnavailable { detail: String },
    /// Подписка разобралась, но не дала ни одного пригодного сервера.
    NoUsableServers,
    /// Запрошенного сервера нет в текущем списке.
    UnknownServer { id: String },
    /// Ядро не удалось запустить (нет бинаря, не сошёлся хэш, нет прав).
    CoreStartFailed { detail: String },
    /// Ядро запустилось, но туннель не поднялся за отведённое время.
    HandshakeTimeout { seconds: u64 },
    /// Не удалось применить сетевые настройки: TUN, маршруты, DNS, firewall.
    NetworkSetupFailed { detail: String },
    /// Исчерпан бюджет попыток переподключения.
    RetriesExhausted { attempts: u32 },
    /// Внутренняя ошибка демона.
    Internal { detail: String },
}

impl TunnelError {
    /// Имеет ли смысл повторять попытку автоматически.
    ///
    /// Разделение принципиально для UI: при `false` крутить бесконечный
    /// ретрай бессмысленно и пользователя нужно попросить что-то сделать.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::NoSubscription
            | Self::NoUsableServers
            | Self::UnknownServer { .. }
            | Self::CoreStartFailed { .. } => false,
            Self::SubscriptionUnavailable { .. }
            | Self::HandshakeTimeout { .. }
            | Self::NetworkSetupFailed { .. }
            | Self::RetriesExhausted { .. }
            | Self::Internal { .. } => true,
        }
    }

    /// Требуется ли действие пользователя.
    pub fn needs_user_action(&self) -> bool {
        matches!(
            self,
            Self::NoSubscription | Self::NoUsableServers | Self::CoreStartFailed { .. }
        )
    }
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSubscription => f.write_str("ключ подписки не задан"),
            Self::SubscriptionUnavailable { detail } => {
                write!(f, "не удалось получить подписку: {detail}")
            }
            Self::NoUsableServers => f.write_str("в подписке нет поддерживаемых серверов"),
            Self::UnknownServer { id } => write!(f, "сервер {id} отсутствует в списке"),
            Self::CoreStartFailed { detail } => write!(f, "ядро не запустилось: {detail}"),
            Self::HandshakeTimeout { seconds } => {
                write!(f, "туннель не поднялся за {seconds} с")
            }
            Self::NetworkSetupFailed { detail } => {
                write!(f, "не удалось настроить сеть: {detail}")
            }
            Self::RetriesExhausted { attempts } => {
                write!(f, "переподключение не удалось после {attempts} попыток")
            }
            Self::Internal { detail } => write!(f, "внутренняя ошибка: {detail}"),
        }
    }
}

impl std::error::Error for TunnelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_subscription_is_not_retryable() {
        assert!(!TunnelError::NoSubscription.is_retryable());
        assert!(TunnelError::NoSubscription.needs_user_action());
    }

    #[test]
    fn transient_failures_are_retryable() {
        let e = TunnelError::HandshakeTimeout { seconds: 15 };
        assert!(e.is_retryable());
        assert!(!e.needs_user_action());
    }

    #[test]
    fn errors_roundtrip_through_serde() {
        let e = TunnelError::NetworkSetupFailed {
            detail: "WFP: FWP_E_ALREADY_EXISTS".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<TunnelError>(&json).unwrap(), e);
    }

    #[test]
    fn display_is_human_readable() {
        let e = TunnelError::HandshakeTimeout { seconds: 15 };
        assert_eq!(e.to_string(), "туннель не поднялся за 15 с");
    }
}

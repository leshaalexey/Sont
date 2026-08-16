//! Конечный автомат соединения.
//!
//! Единственный владелец этого состояния — задача supervisor в демоне. UI
//! получает его копии событиями и ничего не выводит самостоятельно: любая
//! попытка «догадаться» о состоянии на стороне клиента рано или поздно
//! разъезжается с реальностью.

use serde::{Deserialize, Serialize};

use crate::error::{DisconnectReason, ReconnectCause, TunnelError};
use crate::profile::ProfileId;

/// Параметры поднятого TUN-интерфейса.
///
/// Интерфейс создаёт само ядро; демон только находит его, чтобы построить
/// вокруг правила firewall, маршрутов и DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunInfo {
    pub name: String,
    /// Индекс интерфейса (Windows: IfIndex, Unix: ifindex).
    pub index: u32,
    /// LUID на Windows — именно по нему адресуются WFP-фильтры.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub luid: Option<u64>,
    pub addresses: Vec<String>,
    pub mtu: u32,
}

/// Состояние туннеля.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<DisconnectReason>,
        /// Держит ли firewall блокировку прямо сейчас.
        ///
        /// «Не подключён» и «трафик заблокирован» — разные вещи. Без этого
        /// флага пользователь в режиме lockdown видит «Отключено» и не
        /// понимает, почему интернет не работает.
        blocked: bool,
    },
    Connecting {
        server: ProfileId,
        attempt: u32,
    },
    Connected {
        server: ProfileId,
        /// Момент установления соединения, Unix-время в миллисекундах.
        since_unix_ms: u64,
        tun: TunInfo,
    },
    Reconnecting {
        server: ProfileId,
        cause: ReconnectCause,
        attempt: u32,
    },
    Disconnecting,
    Failed {
        error: TunnelError,
        blocked: bool,
    },
}

impl Default for TunnelState {
    fn default() -> Self {
        Self::Disconnected {
            reason: None,
            blocked: false,
        }
    }
}

impl TunnelState {
    /// Туннель поднят и трафик идёт.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Держит ли демон путь для трафика — уже или вот-вот.
    ///
    /// Отличается от [`Self::is_connected`] тем, что включает попытку
    /// подключения, и нужно там, где важно намерение, а не факт.
    ///
    /// Единственный такой случай — объявление адреса локального прокси
    /// системе. Объявлять его строго по факту соединения нельзя: сначала
    /// снимается прежний путь, и только через несколько секунд появляется
    /// новый. В это окно приложения успевают переустановить соединения
    /// напрямую — и остаются в нём надолго, потому что уже открытые сокеты
    /// на появившийся прокси никто не переносит, а HTTP/2 и WebSocket живут
    /// часами. Прокси, объявленный на пару секунд раньше ядра, даёт отказ в
    /// соединении — и приложение повторяет попытку. Прокси, объявленный
    /// позже, даёт молчаливый обход.
    pub fn holds_a_route(&self) -> bool {
        matches!(
            self,
            Self::Connected { .. } | Self::Connecting { .. } | Self::Reconnecting { .. }
        )
    }

    /// Идёт работа: пользователю нужно показывать индикатор процесса.
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            Self::Connecting { .. } | Self::Reconnecting { .. } | Self::Disconnecting
        )
    }

    /// Блокирует ли firewall трафик прямо сейчас.
    ///
    /// В `Connecting` и `Reconnecting` блокировка всегда активна, если
    /// kill-switch включён: разрыв между «сняли фильтры» и «подняли туннель» —
    /// это и есть окно утечки, ради закрытия которого всё затевалось.
    pub fn is_blocked(&self) -> bool {
        match self {
            Self::Disconnected { blocked, .. } | Self::Failed { blocked, .. } => *blocked,
            Self::Connecting { .. } | Self::Reconnecting { .. } => true,
            Self::Connected { .. } | Self::Disconnecting => false,
        }
    }

    /// Сервер, с которым связано текущее состояние.
    pub fn server(&self) -> Option<&ProfileId> {
        match self {
            Self::Connecting { server, .. }
            | Self::Connected { server, .. }
            | Self::Reconnecting { server, .. } => Some(server),
            Self::Disconnected { .. } | Self::Disconnecting | Self::Failed { .. } => None,
        }
    }

    /// Короткий машинный дискриминант — для иконки в трее и для тестов.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Disconnected { .. } => "disconnected",
            Self::Connecting { .. } => "connecting",
            Self::Connected { .. } => "connected",
            Self::Reconnecting { .. } => "reconnecting",
            Self::Disconnecting => "disconnecting",
            Self::Failed { .. } => "failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun() -> TunInfo {
        TunInfo {
            name: "sont0".into(),
            index: 12,
            luid: Some(0x0100_0000_0000_0000),
            addresses: vec!["172.19.0.1/30".into()],
            mtu: 1420,
        }
    }

    #[test]
    fn default_is_disconnected_and_unblocked() {
        let s = TunnelState::default();
        assert_eq!(s.kind(), "disconnected");
        assert!(!s.is_blocked());
        assert!(!s.is_connected());
    }

    #[test]
    fn connecting_is_always_blocked() {
        // Окно между снятием фильтров и поднятием туннеля — это утечка.
        let s = TunnelState::Connecting {
            server: ProfileId::from_raw("srv"),
            attempt: 1,
        };
        assert!(s.is_blocked());
        assert!(s.is_busy());
    }

    #[test]
    fn a_route_is_held_through_the_whole_reconnect() {
        // Адрес локального прокси объявляется системе по этому признаку.
        // Сузить его до «подключено» значит открыть окно, в которое
        // приложения уходят напрямую и там остаются.
        let connecting = TunnelState::Connecting {
            server: ProfileId::from_raw("srv"),
            attempt: 1,
        };
        let reconnecting = TunnelState::Reconnecting {
            server: ProfileId::from_raw("srv"),
            cause: ReconnectCause::CoreExited { code: Some(1) },
            attempt: 2,
        };
        assert!(connecting.holds_a_route());
        assert!(reconnecting.holds_a_route());

        // А здесь пути нет и не предвидится: объявлять адрес, за которым
        // никого не будет, — это «пропал интернет» без всякой связи с VPN.
        assert!(!TunnelState::default().holds_a_route());
        assert!(!TunnelState::Disconnecting.holds_a_route());
        assert!(!TunnelState::Failed {
            error: crate::TunnelError::NoUsableServers,
            blocked: false,
        }
        .holds_a_route());
    }

    #[test]
    fn connected_is_not_blocked() {
        let s = TunnelState::Connected {
            server: ProfileId::from_raw("srv"),
            since_unix_ms: 1_700_000_000_000,
            tun: tun(),
        };
        assert!(!s.is_blocked());
        assert!(s.is_connected());
        assert!(!s.is_busy());
    }

    #[test]
    fn lockdown_failure_stays_blocked() {
        let s = TunnelState::Failed {
            error: TunnelError::RetriesExhausted { attempts: 5 },
            blocked: true,
        };
        assert!(s.is_blocked(), "в режиме lockdown отказ не открывает трафик");
        assert!(!s.is_connected());
    }

    #[test]
    fn state_roundtrips_through_serde() {
        let s = TunnelState::Connected {
            server: ProfileId::from_raw("srv"),
            since_unix_ms: 1_700_000_000_000,
            tun: tun(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<TunnelState>(&json).unwrap(), s);
    }

    #[test]
    fn server_is_exposed_only_where_meaningful() {
        let id = ProfileId::from_raw("srv");
        assert_eq!(
            TunnelState::Connecting {
                server: id.clone(),
                attempt: 1
            }
            .server(),
            Some(&id)
        );
        assert_eq!(TunnelState::Disconnecting.server(), None);
    }
}

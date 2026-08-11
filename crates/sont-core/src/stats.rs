//! Телеметрия соединения: трафик, задержки, состояние подписки.
//!
//! Всё это остаётся на машине пользователя. Наружу ничего не отправляется —
//! у VPN-клиента не может быть аналитики «для улучшения продукта».

use serde::{Deserialize, Serialize};

use crate::profile::ProfileId;

/// Мгновенная статистика трафика. Публикуется событием раз в секунду и только
/// пока есть хотя бы один подписчик.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    /// Текущая скорость, байт/с.
    pub up_bps: u64,
    pub down_bps: u64,
    /// Накопительно за сессию, байт.
    pub total_up: u64,
    pub total_down: u64,
    /// Задержка до сервера по последнему замеру, мс.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// Число открытых соединений через туннель.
    pub connections: u32,
}

/// Результат замера сервера.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub server: ProfileId,
    /// Медиана RTT по нескольким замерам, мс. `None` — сервер недоступен.
    pub rtt_ms: Option<u32>,
    /// Доля неудачных попыток, 0..=100.
    pub loss_percent: u8,
    /// Когда замерено, Unix-время в миллисекундах.
    pub measured_at_unix_ms: u64,
}

impl ProbeResult {
    pub fn is_reachable(&self) -> bool {
        self.rtt_ms.is_some()
    }

    /// Оценка для сортировки: чем меньше, тем лучше.
    ///
    /// Потери штрафуются нелинейно: сервер с 200 мс и без потерь для
    /// пользователя заметно лучше, чем сервер с 50 мс и 20% потерь, потому что
    /// на потерях TCP начинает пробуксовывать.
    pub fn score(&self) -> u32 {
        match self.rtt_ms {
            None => u32::MAX,
            Some(rtt) => {
                let penalty = u32::from(self.loss_percent).saturating_mul(20);
                rtt.saturating_add(penalty)
            }
        }
    }
}

/// Состояние подписки: сколько трафика израсходовано и когда истекает.
///
/// Панели отдают это заголовком `subscription-userinfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    /// Израсходовано, байт.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<u64>,
    /// Лимит, байт. `None` или `Some(0)` — безлимит.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Когда истекает, Unix-время в секундах.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    /// Когда подписка последний раз успешно обновлялась.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at_unix: Option<u64>,
    /// Сколько серверов удалось разобрать при последнем обновлении.
    pub server_count: u32,
}

impl SubscriptionInfo {
    /// Сколько байт осталось. `None` — лимита нет или данных недостаточно.
    pub fn remaining_bytes(&self) -> Option<u64> {
        let total = self.total.filter(|t| *t > 0)?;
        let used = self.upload.unwrap_or(0).saturating_add(self.download.unwrap_or(0));
        Some(total.saturating_sub(used))
    }

    /// Доля израсходованного трафика, 0..=100.
    pub fn used_percent(&self) -> Option<u8> {
        let total = self.total.filter(|t| *t > 0)?;
        let used = self.upload.unwrap_or(0).saturating_add(self.download.unwrap_or(0));
        let pct = used.saturating_mul(100) / total;
        Some(pct.min(100) as u8)
    }

    /// Истекла ли подписка на указанный момент.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at_unix.is_some_and(|exp| exp <= now_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(rtt: Option<u32>, loss: u8) -> ProbeResult {
        ProbeResult {
            server: ProfileId::from_raw("srv"),
            rtt_ms: rtt,
            loss_percent: loss,
            measured_at_unix_ms: 0,
        }
    }

    #[test]
    fn unreachable_server_sorts_last() {
        assert_eq!(probe(None, 100).score(), u32::MAX);
        assert!(probe(Some(500), 0).score() < probe(None, 0).score());
    }

    #[test]
    fn loss_outweighs_raw_latency() {
        let fast_but_lossy = probe(Some(50), 20);
        let slow_but_clean = probe(Some(200), 0);
        assert!(
            slow_but_clean.score() < fast_but_lossy.score(),
            "потери мешают сильнее, чем лишние 150 мс"
        );
    }

    #[test]
    fn unlimited_subscription_has_no_remaining() {
        let info = SubscriptionInfo {
            total: Some(0),
            download: Some(1_000),
            ..Default::default()
        };
        assert_eq!(info.remaining_bytes(), None);
        assert_eq!(info.used_percent(), None);
    }

    #[test]
    fn remaining_traffic_is_computed_from_both_directions() {
        let info = SubscriptionInfo {
            upload: Some(300),
            download: Some(700),
            total: Some(2_000),
            ..Default::default()
        };
        assert_eq!(info.remaining_bytes(), Some(1_000));
        assert_eq!(info.used_percent(), Some(50));
    }

    #[test]
    fn overuse_does_not_underflow() {
        let info = SubscriptionInfo {
            download: Some(5_000),
            total: Some(1_000),
            ..Default::default()
        };
        assert_eq!(info.remaining_bytes(), Some(0));
        assert_eq!(info.used_percent(), Some(100));
    }

    #[test]
    fn expiry_is_inclusive() {
        let info = SubscriptionInfo {
            expires_at_unix: Some(1_000),
            ..Default::default()
        };
        assert!(!info.is_expired(999));
        assert!(info.is_expired(1_000));
        assert!(info.is_expired(1_001));
    }

    #[test]
    fn subscription_without_expiry_never_expires() {
        assert!(!SubscriptionInfo::default().is_expired(u64::MAX));
    }
}

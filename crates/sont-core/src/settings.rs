//! Пользовательские настройки демона.
//!
//! Живут на стороне демона и являются единственным источником истины. UI их
//! только читает и патчит — своей копии не держит.

use serde::{Deserialize, Serialize};

use crate::transport::TransportKind;

/// Как трафик попадает в туннель.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// Весь трафик системы через TUN-адаптер.
    ///
    /// Полный охват и возможность kill-switch, но нужны права администратора,
    /// а в системе появляется новое сетевое подключение.
    #[default]
    Tunnel,

    /// Локальный прокси, о котором приложения узнают из настроек системы.
    ///
    /// Не требует прав администратора и не создаёт сетевых адаптеров. Плата:
    /// охват неполный — приложение, не умеющее ходить через прокси, пойдёт
    /// напрямую, и ни оно, ни пользователь об этом не узнают. Отдельно мимо
    /// прокси идёт QUIC, которым браузеры пользуются постоянно.
    Proxy,
}

impl ConnectionMode {
    /// Нужны ли права администратора.
    pub fn requires_privileges(self) -> bool {
        matches!(self, Self::Tunnel)
    }

    /// Охватывает ли режим весь трафик системы.
    ///
    /// От этого зависит, можно ли обещать пользователю защиту: kill-switch и
    /// защита от утечек осмысленны только при полном охвате.
    pub fn covers_all_traffic(self) -> bool {
        matches!(self, Self::Tunnel)
    }
}

/// Режим kill-switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// Блокировки нет. При обрыве туннеля трафик пойдёт напрямую.
    Off,
    /// Блокировка на время сессии, снимается автоматически, если демон упал.
    ///
    /// Значение по умолчанию: защищает от обрыва туннеля, но не оставляет
    /// пользователя без интернета, если упал сам демон.
    #[default]
    Auto,
    /// Жёсткая блокировка: переживает падение демона и действует до загрузки
    /// системы. Снимается только явным отключением или `sontd firewall reset`.
    Lockdown,
}

impl FirewallMode {
    /// Нужно ли вообще трогать firewall.
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Переживают ли фильтры падение демона.
    pub fn survives_daemon_crash(self) -> bool {
        matches!(self, Self::Lockdown)
    }
}

/// Куда направлять DNS-запросы.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DnsMode {
    /// Резолвинг через туннель серверами по умолчанию.
    #[default]
    Tunnel,
    /// Свои серверы (в том числе DoH/DoT-URL), но всё равно через туннель.
    Custom { servers: Vec<String> },
    /// Системный резолвер. Осознанная утечка — только для отладки.
    System,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(default, flatten)]
    pub mode: DnsMode,
    /// Блокировать открытый DNS (53/udp, 53/tcp, 853) мимо туннеля на уровне
    /// firewall. Без этого утечки почти гарантированы.
    #[serde(default = "yes")]
    pub block_plain_dns: bool,
    /// Режим fake-ip: ускоряет отклик и убирает лишний round-trip, но ломает
    /// приложения, которые сами сверяют A-запись с реальным адресом.
    #[serde(default)]
    pub fake_ip: bool,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            mode: DnsMode::default(),
            block_plain_dns: true,
            fake_ip: false,
        }
    }
}

/// Как трактовать список приложений в раздельном туннелировании.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    #[default]
    Off,
    /// Всё в туннель, перечисленные приложения — мимо.
    Exclude,
    /// Всё мимо туннеля, в туннель — только перечисленные приложения.
    Include,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SplitTunnelRules {
    #[serde(default)]
    pub mode: SplitTunnelMode,
    /// Абсолютные пути к исполняемым файлам.
    ///
    /// Именно пути, а не имена: `chrome.exe` в `Downloads` не должен получать
    /// правила настоящего браузера.
    #[serde(default)]
    pub apps: Vec<String>,
}

impl SplitTunnelRules {
    /// Действуют ли правила на самом деле.
    ///
    /// Пустой список в режиме `Include` означал бы «весь трафик мимо туннеля»,
    /// то есть выключенный VPN. Такую конфигурацию считаем неактивной.
    pub fn is_active(&self) -> bool {
        match self.mode {
            SplitTunnelMode::Off => false,
            SplitTunnelMode::Exclude | SplitTunnelMode::Include => !self.apps.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Как трафик попадает в туннель.
    pub mode: ConnectionMode,
    /// Подключаться при старте демона.
    pub auto_connect: bool,
    /// Запускать tray-приложение при входе пользователя в систему.
    pub tray_autostart: bool,
    /// Выбирать сервер автоматически по замерам задержки.
    pub auto_select_server: bool,
    /// Закреплённый пользователем сервер (используется, если автовыбор выключен).
    pub pinned_server: Option<crate::profile::ProfileId>,
    pub firewall: FirewallMode,
    pub dns: DnsSettings,
    pub split_tunnel: SplitTunnelRules,
    /// Разрешить доступ к локальной сети в обход туннеля (принтеры, NAS).
    pub allow_lan: bool,
    /// Предпочитаемые протоколы. Пустой список — использовать все доступные.
    pub preferred_transports: Vec<TransportKind>,
    /// Как часто перечитывать подписку.
    pub subscription_refresh_hours: u32,
    /// Уровень логирования ядра и демона.
    pub log_level: String,
    /// Язык интерфейса, BCP-47.
    pub language: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: ConnectionMode::default(),
            auto_connect: false,
            tray_autostart: true,
            auto_select_server: true,
            pinned_server: None,
            firewall: FirewallMode::default(),
            dns: DnsSettings::default(),
            split_tunnel: SplitTunnelRules::default(),
            allow_lan: true,
            preferred_transports: Vec::new(),
            subscription_refresh_hours: 12,
            log_level: "info".to_owned(),
            language: "ru".to_owned(),
        }
    }
}

/// Частичное обновление настроек.
///
/// Отдельный тип, а не `Settings` целиком: иначе два открытых окна настроек
/// затирают правки друг друга, а старая версия UI молча сбрасывает поля,
/// про которые ничего не знает.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsPatch {
    pub mode: Option<ConnectionMode>,
    pub auto_connect: Option<bool>,
    pub tray_autostart: Option<bool>,
    pub auto_select_server: Option<bool>,
    /// `Some(None)` снимает закрепление, `None` оставляет как было.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_server: Option<Option<crate::profile::ProfileId>>,
    pub firewall: Option<FirewallMode>,
    pub dns: Option<DnsSettings>,
    pub split_tunnel: Option<SplitTunnelRules>,
    pub allow_lan: Option<bool>,
    pub preferred_transports: Option<Vec<TransportKind>>,
    pub subscription_refresh_hours: Option<u32>,
    pub log_level: Option<String>,
    pub language: Option<String>,
}

impl SettingsPatch {
    /// Применяет патч и сообщает, требует ли изменение перезапуска ядра.
    ///
    /// Разница существенная: смену языка применяем мгновенно, а смену DNS или
    /// правил раздельного туннелирования — только пересборкой конфига ядра.
    pub fn apply(self, settings: &mut Settings) -> ApplyOutcome {
        let mut outcome = ApplyOutcome::default();

        if let Some(v) = self.mode {
            // Смена режима меняет и состав входов ядра, и то, поднимается ли
            // сетевой слой вообще, — переподключение обязательно.
            outcome.needs_core_restart |= settings.mode != v;
            outcome.needs_firewall_reapply |= settings.mode != v;
            settings.mode = v;
        }
        if let Some(v) = self.auto_connect {
            settings.auto_connect = v;
        }
        if let Some(v) = self.tray_autostart {
            settings.tray_autostart = v;
        }
        if let Some(v) = self.auto_select_server {
            outcome.needs_core_restart |= settings.auto_select_server != v;
            settings.auto_select_server = v;
        }
        if let Some(v) = self.pinned_server {
            settings.pinned_server = v;
        }
        if let Some(v) = self.firewall {
            outcome.needs_firewall_reapply |= settings.firewall != v;
            settings.firewall = v;
        }
        if let Some(v) = self.dns {
            outcome.needs_core_restart |= settings.dns != v;
            outcome.needs_firewall_reapply |= settings.dns.block_plain_dns != v.block_plain_dns;
            settings.dns = v;
        }
        if let Some(v) = self.split_tunnel {
            // Раздельное туннелирование задаёт и правила ядра, и исключения в
            // firewall — они обязаны меняться вместе, иначе kill-switch убьёт
            // ровно тот трафик, который пользователь просил пустить мимо.
            outcome.needs_core_restart |= settings.split_tunnel != v;
            outcome.needs_firewall_reapply |= settings.split_tunnel != v;
            settings.split_tunnel = v;
        }
        if let Some(v) = self.allow_lan {
            outcome.needs_core_restart |= settings.allow_lan != v;
            outcome.needs_firewall_reapply |= settings.allow_lan != v;
            settings.allow_lan = v;
        }
        if let Some(v) = self.preferred_transports {
            outcome.needs_core_restart |= settings.preferred_transports != v;
            settings.preferred_transports = v;
        }
        if let Some(v) = self.subscription_refresh_hours {
            settings.subscription_refresh_hours = v;
        }
        if let Some(v) = self.log_level {
            outcome.needs_core_restart |= settings.log_level != v;
            settings.log_level = v;
        }
        if let Some(v) = self.language {
            settings.language = v;
        }

        outcome
    }
}

/// Что нужно сделать после применения патча.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub needs_core_restart: bool,
    pub needs_firewall_reapply: bool,
}

fn yes() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_patch_changes_nothing() {
        let mut s = Settings::default();
        let before = s.clone();
        let outcome = SettingsPatch::default().apply(&mut s);
        assert_eq!(s, before);
        assert_eq!(outcome, ApplyOutcome::default());
    }

    #[test]
    fn language_change_does_not_restart_core() {
        let mut s = Settings::default();
        let outcome = SettingsPatch {
            language: Some("en".into()),
            ..Default::default()
        }
        .apply(&mut s);
        assert_eq!(s.language, "en");
        assert!(!outcome.needs_core_restart);
        assert!(!outcome.needs_firewall_reapply);
    }

    #[test]
    fn split_tunnel_change_touches_core_and_firewall() {
        let mut s = Settings::default();
        let outcome = SettingsPatch {
            split_tunnel: Some(SplitTunnelRules {
                mode: SplitTunnelMode::Exclude,
                apps: vec!["C:\\Program Files\\App\\app.exe".into()],
            }),
            ..Default::default()
        }
        .apply(&mut s);
        assert!(outcome.needs_core_restart);
        assert!(
            outcome.needs_firewall_reapply,
            "исключения в firewall обязаны меняться вместе с правилами ядра"
        );
    }

    #[test]
    fn setting_same_value_is_not_a_change() {
        let mut s = Settings::default();
        let outcome = SettingsPatch {
            firewall: Some(FirewallMode::Auto),
            allow_lan: Some(true),
            ..Default::default()
        }
        .apply(&mut s);
        assert_eq!(outcome, ApplyOutcome::default());
    }

    #[test]
    fn pinned_server_can_be_cleared() {
        let mut s = Settings {
            pinned_server: Some(crate::profile::ProfileId::from_raw("abc")),
            ..Default::default()
        };
        SettingsPatch {
            pinned_server: Some(None),
            ..Default::default()
        }
        .apply(&mut s);
        assert_eq!(s.pinned_server, None);
    }

    #[test]
    fn empty_include_list_is_not_active() {
        let rules = SplitTunnelRules {
            mode: SplitTunnelMode::Include,
            apps: vec![],
        };
        assert!(
            !rules.is_active(),
            "пустой Include означал бы полностью выключенный VPN"
        );
    }

    #[test]
    fn tunnel_mode_is_the_default_and_covers_everything() {
        // Умолчание должно давать защиту, а не удобство: режим прокси
        // оставляет часть трафика в обход, и выбирать его должен пользователь
        // осознанно.
        let s = Settings::default();
        assert_eq!(s.mode, ConnectionMode::Tunnel);
        assert!(s.mode.covers_all_traffic());
        assert!(s.mode.requires_privileges());
    }

    #[test]
    fn proxy_mode_needs_no_privileges_but_covers_less() {
        assert!(!ConnectionMode::Proxy.requires_privileges());
        assert!(!ConnectionMode::Proxy.covers_all_traffic());
    }

    #[test]
    fn switching_mode_requires_reconnect() {
        let mut s = Settings::default();
        let outcome = SettingsPatch {
            mode: Some(ConnectionMode::Proxy),
            ..Default::default()
        }
        .apply(&mut s);
        assert!(outcome.needs_core_restart);
        assert_eq!(s.mode, ConnectionMode::Proxy);
    }

    #[test]
    fn defaults_are_safe() {
        let s = Settings::default();
        assert_eq!(s.firewall, FirewallMode::Auto);
        assert!(s.dns.block_plain_dns);
        assert!(!s.dns.fake_ip);
        assert_eq!(s.split_tunnel.mode, SplitTunnelMode::Off);
    }

    #[test]
    fn settings_roundtrip_through_serde() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Settings>(&json).unwrap(), s);
    }

    #[test]
    fn unknown_patch_fields_are_rejected() {
        // Защита от рассинхрона версий: старый демон не должен молча
        // проглатывать поле, которого не понимает.
        let err = serde_json::from_str::<SettingsPatch>(r#"{"nonexistent_option": true}"#);
        assert!(err.is_err());
    }
}

//! Типизированное описание протокола подключения к серверу.
//!
//! Это граница безопасности всего приложения. IPC принимает от UI только эти
//! структуры и никогда — сырой JSON для ядра: иначе любой процесс в сессии
//! пользователя, дотянувшийся до сокета демона, получает исполнение
//! произвольного кода от имени SYSTEM/root (у ядер прокси есть outbound-ы,
//! умеющие запускать процессы).
//!
//! Всё, что приходит из подписки, обязано быть разобрано в эти типы. То, что
//! не разобралось, отбрасывается с предупреждением, а не прокидывается дальше.

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// Протокол подключения.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Transport {
    Vless(Vless),
    Vmess(Vmess),
    Shadowsocks(Shadowsocks),
    Hysteria2(Hysteria2),
    Tuic(Tuic),
    WireGuard(WireGuard),
}

/// Дискриминант без полезной нагрузки — для фильтров в UI и настроек
/// предпочитаемых протоколов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Vless,
    Vmess,
    Shadowsocks,
    Hysteria2,
    Tuic,
    WireGuard,
}

impl Transport {
    pub fn kind(&self) -> TransportKind {
        match self {
            Self::Vless(_) => TransportKind::Vless,
            Self::Vmess(_) => TransportKind::Vmess,
            Self::Shadowsocks(_) => TransportKind::Shadowsocks,
            Self::Hysteria2(_) => TransportKind::Hysteria2,
            Self::Tuic(_) => TransportKind::Tuic,
            Self::WireGuard(_) => TransportKind::WireGuard,
        }
    }

    /// Работает ли протокол поверх UDP.
    ///
    /// Нужно kill-switch-слою: разрешение для эндпоинта надо открывать на том
    /// же протоколе, иначе QUIC-based соединение (Hysteria2, TUIC) молча
    /// не поднимется под блокировкой.
    pub fn is_udp_based(&self) -> bool {
        matches!(
            self,
            Self::Hysteria2(_) | Self::Tuic(_) | Self::WireGuard(_)
        )
    }

    /// Требует ли профиль ядра Xray.
    ///
    /// XHTTP реализован только в Xray; upstream sing-box его не умеет. Знать
    /// это нужно до попытки подключения: иначе пользователь получает
    /// невнятную ошибку запуска ядра вместо понятного «этот сервер требует
    /// другого ядра».
    pub fn requires_xray(&self) -> bool {
        let stream = match self {
            Self::Vless(v) => &v.stream,
            Self::Vmess(v) => &v.stream,
            _ => return false,
        };
        matches!(stream, Stream::Xhttp { .. })
    }
}

impl TransportKind {
    pub const ALL: [TransportKind; 6] = [
        TransportKind::Vless,
        TransportKind::Vmess,
        TransportKind::Shadowsocks,
        TransportKind::Hysteria2,
        TransportKind::Tuic,
        TransportKind::WireGuard,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Shadowsocks => "shadowsocks",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::WireGuard => "wireguard",
        }
    }
}

// ───────────────────────────── протоколы ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vless {
    pub uuid: Secret,
    /// XTLS-flow, например `xtls-rprx-vision`. Пусто — обычный VLESS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default)]
    pub stream: Stream,
    #[serde(default)]
    pub security: Security,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vmess {
    pub uuid: Secret,
    #[serde(default)]
    pub alter_id: u16,
    /// Шифр VMess: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`.
    #[serde(default = "default_vmess_cipher")]
    pub cipher: String,
    #[serde(default)]
    pub stream: Stream,
    #[serde(default)]
    pub security: Security,
}

fn default_vmess_cipher() -> String {
    "auto".to_owned()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Shadowsocks {
    /// Например `2022-blake3-aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`.
    pub method: String,
    pub password: Secret,
    /// Имя плагина SIP003 из ссылки: `obfs-local`, `v2ray-plugin`, `shadow-tls`.
    ///
    /// Хранится не для того, чтобы его запускать, а чтобы честно отказать.
    /// Плагин — это отдельный исполняемый файл, который Shadowsocks запускает
    /// рядом с собой; у Xray такого механизма нет вовсе. Выбросив это поле при
    /// разборе, мы получили бы профиль, который выглядит рабочим, принимается
    /// ядром — и молча не соединяется, потому что сервер ждёт обфускации,
    /// которой нет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2 {
    pub password: Secret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,
    /// Ограничения полосы, Мбит/с. `None` — режим BBR без ограничений.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
    #[serde(default)]
    pub tls: Tls,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hysteria2Obfs {
    /// На сегодня осмысленное значение одно — `salamander`.
    pub kind: String,
    pub password: Secret,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tuic {
    pub uuid: Secret,
    pub password: Secret,
    #[serde(default = "default_congestion_control")]
    pub congestion_control: String,
    #[serde(default = "default_udp_relay_mode")]
    pub udp_relay_mode: String,
    #[serde(default)]
    pub tls: Tls,
}

fn default_congestion_control() -> String {
    "bbr".to_owned()
}

fn default_udp_relay_mode() -> String {
    "native".to_owned()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireGuard {
    pub private_key: Secret,
    pub peer_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<Secret>,
    /// Адреса интерфейса, CIDR-нотация.
    pub local_address: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// «Reserved»-байты, используемые обфусцированными вариантами.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,
}

// ───────────────────────── транспорт и TLS ─────────────────────────

/// Транспортный слой поверх TCP/QUIC.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Stream {
    #[default]
    Tcp,
    Ws {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// Размер early-data в байтах (`ed=` в ссылках).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_early_data: Option<u32>,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
    },
    HttpUpgrade {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    Http {
        #[serde(default)]
        path: String,
        #[serde(default)]
        host: Vec<String>,
    },
    /// XHTTP (в ранних версиях — SplitHTTP).
    ///
    /// Транспорт Xray. Upstream sing-box его не поддерживает, поэтому профиль
    /// с ним пригоден не для любого ядра — см. [`Transport::requires_xray`].
    Xhttp {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// `auto`, `packet-up`, `stream-up`, `stream-one`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
    },
}

/// Слой шифрования: без него, обычный TLS или Reality.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Security {
    #[default]
    None,
    Tls(Tls),
    Reality(Reality),
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Tls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// uTLS-отпечаток: `chrome`, `firefox`, `safari`, `randomized`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Отключение проверки сертификата. Значение по умолчанию — `false`,
    /// и менять его может только явный параметр из подписки.
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reality {
    pub sni: String,
    /// Публичный ключ сервера (`pbk`). Не секрет — он публичный по определению.
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_roundtrips_through_serde() {
        let t = Transport::Vless(Vless {
            uuid: Secret::new("11111111-2222-3333-4444-555555555555"),
            flow: Some("xtls-rprx-vision".into()),
            stream: Stream::Tcp,
            security: Security::Reality(Reality {
                sni: "www.example.com".into(),
                public_key: "pubkey".into(),
                short_id: "ab12".into(),
                fingerprint: Some("chrome".into()),
            }),
        });

        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(serde_json::from_str::<Transport>(&json).unwrap(), t);
    }

    #[test]
    fn quic_protocols_are_marked_udp() {
        let hy2 = Transport::Hysteria2(Hysteria2 {
            password: Secret::new("pw"),
            obfs: None,
            up_mbps: None,
            down_mbps: None,
            tls: Tls::default(),
        });
        assert!(hy2.is_udp_based());

        let ss = Transport::Shadowsocks(Shadowsocks {
            method: "aes-256-gcm".into(),
            password: Secret::new("pw"),
            plugin: None,
        });
        assert!(!ss.is_udp_based());
    }

    #[test]
    fn debug_output_hides_credentials() {
        let t = Transport::Shadowsocks(Shadowsocks {
            method: "aes-256-gcm".into(),
            password: Secret::new("hunter2"),
            plugin: None,
        });
        assert!(!format!("{t:?}").contains("hunter2"));
    }
}

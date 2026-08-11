//! Сервер как единица выбора пользователя.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::Fnv1a;
use crate::transport::Transport;

/// Стабильный идентификатор сервера.
///
/// Считается от параметров эндпоинта и учётных данных, но **не** от
/// отображаемого имени. Панели регулярно переименовывают серверы («🇳🇱 NL-1»
/// → «🇳🇱 Netherlands #1»), и если завязать id на имя, то при каждом обновлении
/// подписки у пользователя слетает избранное и закреплённый сервер.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Только для тестов и миграций: собрать id из готовой строки.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Идентификатор источника — одной подписки.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    /// Считается от URL подписки, но сам URL при этом не раскрывает: наружу
    /// уходит только хэш.
    pub fn from_url(url: &str) -> Self {
        let mut h = Fnv1a::new();
        h.field(url);
        Self(h.finish_hex())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Адрес сервера. Хост оставляем строкой: у многих конфигов это домен,
/// и резолвить его должно ядро — в том числе через туннель.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            // IPv6-литерал
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Двухбуквенный код страны в верхнем регистре.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    pub fn new(code: &str) -> Option<Self> {
        let bytes = code.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
        Some(Self([
            bytes[0].to_ascii_uppercase(),
            bytes[1].to_ascii_uppercase(),
        ]))
    }

    /// Достаёт страну из флага-эмодзи в начале имени сервера.
    ///
    /// Флаг — это пара Regional Indicator Symbols (U+1F1E6..U+1F1FF), каждый
    /// из которых соответствует букве. Панели почти всегда ставят его первым
    /// символом имени, и это куда надёжнее, чем гадать по тексту названия.
    pub fn from_flag_emoji(name: &str) -> Option<Self> {
        const BASE: u32 = 0x1F1E6;
        let mut chars = name.chars().skip_while(|c| c.is_whitespace());
        let a = chars.next()? as u32;
        let b = chars.next()? as u32;
        if !(BASE..=0x1F1FF).contains(&a) || !(BASE..=0x1F1FF).contains(&b) {
            return None;
        }
        let first = b'A' + (a - BASE) as u8;
        let second = b'A' + (b - BASE) as u8;
        Some(Self([first, second]))
    }

    pub fn as_str(&self) -> &str {
        // Конструкторы гарантируют ASCII.
        std::str::from_utf8(&self.0).expect("CountryCode всегда ASCII")
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Сервер из подписки.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerProfile {
    pub id: ProfileId,
    /// Отображаемое имя — из `#fragment` ссылки.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<CountryCode>,
    pub endpoint: Endpoint,
    pub transport: Transport,
    pub source: SubscriptionId,
}

impl ServerProfile {
    /// Собирает профиль, вычисляя стабильный `id`.
    pub fn new(
        name: impl Into<String>,
        endpoint: Endpoint,
        transport: Transport,
        source: SubscriptionId,
    ) -> Self {
        let name = name.into();
        let id = Self::compute_id(&endpoint, &transport);
        let country = CountryCode::from_flag_emoji(&name);
        Self {
            id,
            name,
            country,
            endpoint,
            transport,
            source,
        }
    }

    /// Хэш от того, что действительно определяет «этот же сервер»: адрес,
    /// порт, вид протокола и учётные данные.
    fn compute_id(endpoint: &Endpoint, transport: &Transport) -> ProfileId {
        use crate::transport::Transport as T;

        let mut h = Fnv1a::new();
        h.field(&endpoint.host);
        h.field(&endpoint.port.to_string());
        h.field(transport.kind().as_str());

        // Учётные данные входят в хэш, чтобы смена ключа пользователя давала
        // новые профили, а не молча переиспользовала старую статистику.
        match transport {
            T::Vless(v) => h.field(v.uuid.expose()),
            T::Vmess(v) => h.field(v.uuid.expose()),
            T::Shadowsocks(s) => h.field(s.password.expose()).field(&s.method),
            T::Hysteria2(v) => h.field(v.password.expose()),
            T::Tuic(v) => h.field(v.uuid.expose()),
            T::WireGuard(v) => h.field(&v.peer_public_key),
        };

        ProfileId(h.finish_hex())
    }

    /// Имя без флага-эмодзи и лишних пробелов — для компактного показа.
    pub fn display_name(&self) -> &str {
        self.name
            .trim_start_matches(|c: char| {
                matches!(c as u32, 0x1F1E6..=0x1F1FF) || c.is_whitespace()
            })
            .trim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use crate::transport::{Security, Shadowsocks, Stream, Transport, Vless};

    fn sub() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub/token")
    }

    fn vless(uuid: &str) -> Transport {
        Transport::Vless(Vless {
            uuid: Secret::new(uuid),
            flow: None,
            stream: Stream::Tcp,
            security: Security::None,
        })
    }

    #[test]
    fn id_is_stable_across_renames() {
        let ep = Endpoint::new("nl.example.com", 443);
        let t = vless("uuid-1");

        let a = ServerProfile::new("🇳🇱 NL-1", ep.clone(), t.clone(), sub());
        let b = ServerProfile::new("🇳🇱 Netherlands #1", ep, t, sub());

        assert_eq!(a.id, b.id, "переименование не должно менять идентификатор");
    }

    #[test]
    fn id_changes_when_credentials_change() {
        let ep = Endpoint::new("nl.example.com", 443);
        let a = ServerProfile::new("NL", ep.clone(), vless("uuid-1"), sub());
        let b = ServerProfile::new("NL", ep, vless("uuid-2"), sub());
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn id_changes_with_port() {
        let t = vless("uuid-1");
        let a = ServerProfile::new("NL", Endpoint::new("nl", 443), t.clone(), sub());
        let b = ServerProfile::new("NL", Endpoint::new("nl", 8443), t, sub());
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn different_protocols_on_same_endpoint_are_distinct() {
        let ep = Endpoint::new("nl", 443);
        let a = ServerProfile::new("NL", ep.clone(), vless("x"), sub());
        let b = ServerProfile::new(
            "NL",
            ep,
            Transport::Shadowsocks(Shadowsocks {
                method: "aes-256-gcm".into(),
                password: Secret::new("x"),
            }),
            sub(),
        );
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn country_is_parsed_from_flag() {
        let p = ServerProfile::new(
            "🇳🇱 Amsterdam",
            Endpoint::new("nl", 443),
            vless("u"),
            sub(),
        );
        assert_eq!(p.country.map(|c| c.as_str().to_owned()), Some("NL".into()));
        assert_eq!(p.display_name(), "Amsterdam");
    }

    #[test]
    fn missing_flag_yields_no_country() {
        let p = ServerProfile::new("Amsterdam", Endpoint::new("nl", 443), vless("u"), sub());
        assert_eq!(p.country, None);
        assert_eq!(p.display_name(), "Amsterdam");
    }

    #[test]
    fn ipv6_endpoint_is_bracketed() {
        assert_eq!(Endpoint::new("2001:db8::1", 443).to_string(), "[2001:db8::1]:443");
        assert_eq!(Endpoint::new("example.com", 443).to_string(), "example.com:443");
    }

    #[test]
    fn country_code_rejects_garbage() {
        assert!(CountryCode::new("N").is_none());
        assert!(CountryCode::new("N1").is_none());
        assert_eq!(CountryCode::new("nl").map(|c| c.as_str().to_owned()), Some("NL".into()));
    }
}

//! Разбор ссылок на отдельные серверы.

mod hysteria2;
mod shadowsocks;
mod tuic;
mod vless;
mod vmess;

use std::collections::HashMap;

use percent_encoding::percent_decode_str;
use sont_core::{Endpoint, ServerProfile, SubscriptionId};
use url::Url;

use crate::LinkError;

/// Разбирает одну ссылку.
pub fn parse_link(line: &str, source: &SubscriptionId) -> Result<ServerProfile, LinkError> {
    let (scheme, _) = line
        .split_once("://")
        .ok_or_else(|| LinkError::Malformed("нет разделителя ://".to_owned()))?;

    match scheme.to_ascii_lowercase().as_str() {
        "vless" => vless::parse(line, source),
        "vmess" => vmess::parse(line, source),
        "ss" => shadowsocks::parse(line, source),
        // hy2 — распространённый короткий псевдоним.
        "hysteria2" | "hy2" => hysteria2::parse(line, source),
        "tuic" => tuic::parse(line, source),
        other => Err(LinkError::UnknownScheme(other.to_owned())),
    }
}

// ─────────────────────────── общие помощники ───────────────────────────

/// Параметры запроса с приведёнными к нижнему регистру именами.
///
/// Панели расходятся в регистре: встречаются и `type`, и `Type`, и
/// `serviceName`, и `servicename`. Приводим имена к одному виду, чтобы это не
/// превращалось в набор частных случаев в каждом парсере.
pub(crate) struct Query(HashMap<String, String>);

impl Query {
    pub fn from_url(url: &Url) -> Self {
        Self(
            url.query_pairs()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    pub fn get_owned(&self, key: &str) -> Option<String> {
        self.get(key).map(str::to_owned)
    }

    /// Значение как флаг. Панели пишут и `1`, и `true`.
    pub fn flag(&self, key: &str) -> bool {
        matches!(
            self.get(key).map(str::to_ascii_lowercase).as_deref(),
            Some("1" | "true" | "yes")
        )
    }

    /// Список, разделённый запятыми (`alpn=h2,http/1.1`).
    pub fn list(&self, key: &str) -> Vec<String> {
        self.get(key)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Имя сервера из `#fragment`.
///
/// Фрагмент почти всегда процентно закодирован — там эмодзи-флаги и кириллица.
///
/// Отдельный случай — несколько `#` подряд: панели встречаются такие, что
/// пишут `#идентификатор@домен#Настоящее имя`. По RFC всё после первого `#` —
/// это фрагмент целиком, поэтому отображаемым именем берём последнюю часть:
/// именно её панель и предполагала показать.
pub(crate) fn fragment_name(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(|f| f.rsplit('#').next().unwrap_or(f))
        .map(|f| percent_decode_str(f).decode_utf8_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// Адрес сервера из части authority.
pub(crate) fn endpoint(url: &Url) -> Result<Endpoint, LinkError> {
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(LinkError::MissingField("хост"))?;

    let port = url.port().ok_or(LinkError::MissingField("порт"))?;

    // url оставляет IPv6-литерал в скобках; ядру он нужен без них.
    let host = host.trim_start_matches('[').trim_end_matches(']');

    Ok(Endpoint::new(host, port))
}

/// Транспортный слой по параметрам ссылки.
pub(crate) fn stream_from_query(q: &Query) -> Result<sont_core::Stream, LinkError> {
    use sont_core::Stream;

    let kind = q
        .get("type")
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "tcp".to_owned());

    let stream = match kind.as_str() {
        // `raw` — новое имя того же самого в свежих панелях.
        "tcp" | "raw" | "none" => Stream::Tcp,

        "ws" | "websocket" => Stream::Ws {
            path: q.get_owned("path").unwrap_or_else(|| "/".to_owned()),
            host: q.get_owned("host"),
            // `ed` задаёт размер early-data.
            max_early_data: q.get("ed").and_then(|v| v.parse().ok()),
        },

        "grpc" => Stream::Grpc {
            service_name: q
                .get_owned("servicename")
                .or_else(|| q.get_owned("path"))
                .unwrap_or_default(),
        },

        "httpupgrade" => Stream::HttpUpgrade {
            path: q.get_owned("path").unwrap_or_else(|| "/".to_owned()),
            host: q.get_owned("host"),
        },

        "http" | "h2" => Stream::Http {
            path: q.get_owned("path").unwrap_or_else(|| "/".to_owned()),
            host: q.list("host"),
        },

        // `splithttp` — прежнее имя того же транспорта, встречается в
        // ссылках, выданных до переименования.
        "xhttp" | "splithttp" => Stream::Xhttp {
            path: q.get_owned("path").unwrap_or_else(|| "/".to_owned()),
            host: q.get_owned("host"),
            mode: q.get_owned("mode"),
        },

        other => {
            return Err(LinkError::BadValue {
                field: "type",
                value: other.to_owned(),
            })
        }
    };

    Ok(stream)
}

/// Слой шифрования по параметрам ссылки.
pub(crate) fn security_from_query(q: &Query) -> Result<sont_core::Security, LinkError> {
    use sont_core::transport::Reality;
    use sont_core::Security;

    let kind = q
        .get("security")
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "none".to_owned());

    match kind.as_str() {
        "none" | "" => Ok(Security::None),

        "tls" => Ok(Security::Tls(tls_from_query(q))),

        "reality" => Ok(Security::Reality(Reality {
            // Без SNI Reality не работает: именно им прикрывается соединение.
            sni: q
                .get_owned("sni")
                .or_else(|| q.get_owned("peer"))
                .ok_or(LinkError::MissingField("sni для reality"))?,
            public_key: q
                .get_owned("pbk")
                .ok_or(LinkError::MissingField("pbk для reality"))?,
            short_id: q.get_owned("sid").unwrap_or_default(),
            fingerprint: q.get_owned("fp"),
        })),

        other => Err(LinkError::BadValue {
            field: "security",
            value: other.to_owned(),
        }),
    }
}

pub(crate) fn tls_from_query(q: &Query) -> sont_core::transport::Tls {
    sont_core::transport::Tls {
        sni: q.get_owned("sni").or_else(|| q.get_owned("peer")),
        alpn: q.list("alpn"),
        fingerprint: q.get_owned("fp"),
        // Отключение проверки сертификата включается только явным параметром.
        insecure: q.flag("allowinsecure") || q.flag("insecure") || q.flag("skip-cert-verify"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    #[test]
    fn unknown_scheme_is_reported() {
        let err = parse_link("trojan://pw@example.com:443", &source()).unwrap_err();
        assert_eq!(err, LinkError::UnknownScheme("trojan".into()));
    }

    #[test]
    fn line_without_scheme_separator_is_rejected() {
        assert!(matches!(
            parse_link("просто текст", &source()),
            Err(LinkError::Malformed(_))
        ));
    }

    #[test]
    fn hy2_alias_is_accepted() {
        let profile = parse_link("hy2://pw@example.com:443#Test", &source()).unwrap();
        assert_eq!(profile.transport.kind(), sont_core::TransportKind::Hysteria2);
    }

    #[test]
    fn scheme_is_case_insensitive() {
        assert!(parse_link("VLESS://uuid@example.com:443?type=tcp#T", &source()).is_ok());
    }

    #[test]
    fn query_keys_are_case_insensitive() {
        let url = Url::parse("vless://u@h:443?Type=ws&Path=/x&ServiceName=svc").unwrap();
        let q = Query::from_url(&url);
        assert_eq!(q.get("type"), Some("ws"));
        assert_eq!(q.get("path"), Some("/x"));
        assert_eq!(q.get("servicename"), Some("svc"));
    }

    #[test]
    fn empty_query_values_are_treated_as_absent() {
        let url = Url::parse("vless://u@h:443?sni=&fp=chrome").unwrap();
        let q = Query::from_url(&url);
        assert_eq!(q.get("sni"), None);
        assert_eq!(q.get("fp"), Some("chrome"));
    }

    #[test]
    fn flags_accept_both_conventions() {
        let url = Url::parse("x://u@h:443?a=1&b=true&c=0&d=false").unwrap();
        let q = Query::from_url(&url);
        assert!(q.flag("a"));
        assert!(q.flag("b"));
        assert!(!q.flag("c"));
        assert!(!q.flag("d"));
        assert!(!q.flag("missing"));
    }

    #[test]
    fn alpn_list_is_split_and_trimmed() {
        let url = Url::parse("x://u@h:443?alpn=h2,%20http%2F1.1").unwrap();
        let q = Query::from_url(&url);
        assert_eq!(q.list("alpn"), vec!["h2", "http/1.1"]);
    }

    #[test]
    fn fragment_is_percent_decoded() {
        let url = Url::parse("vless://u@h:443#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam").unwrap();
        assert_eq!(fragment_name(&url, "запасное"), "🇳🇱 Amsterdam");
    }

    #[test]
    fn missing_fragment_falls_back() {
        let url = Url::parse("vless://u@h:443").unwrap();
        assert_eq!(fragment_name(&url, "запасное"), "запасное");
    }

    #[test]
    fn ipv6_host_loses_its_brackets() {
        let url = Url::parse("vless://u@[2001:db8::1]:443").unwrap();
        let ep = endpoint(&url).unwrap();
        assert_eq!(ep.host, "2001:db8::1");
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn missing_port_is_an_error() {
        let url = Url::parse("vless://u@example.com").unwrap();
        assert_eq!(endpoint(&url), Err(LinkError::MissingField("порт")));
    }

    #[test]
    fn reality_requires_public_key() {
        let url = Url::parse("vless://u@h:443?security=reality&sni=a.com").unwrap();
        let q = Query::from_url(&url);
        assert_eq!(
            security_from_query(&q),
            Err(LinkError::MissingField("pbk для reality"))
        );
    }

    #[test]
    fn reality_requires_sni() {
        let url = Url::parse("vless://u@h:443?security=reality&pbk=key").unwrap();
        let q = Query::from_url(&url);
        assert_eq!(
            security_from_query(&q),
            Err(LinkError::MissingField("sni для reality"))
        );
    }

    #[test]
    fn insecure_defaults_to_false() {
        let url = Url::parse("vless://u@h:443?security=tls&sni=a.com").unwrap();
        let q = Query::from_url(&url);
        let sont_core::Security::Tls(tls) = security_from_query(&q).unwrap() else {
            panic!("ожидался TLS");
        };
        assert!(!tls.insecure, "проверка сертификата не должна отключаться сама");
    }

    #[test]
    fn ws_defaults_to_root_path() {
        let url = Url::parse("vless://u@h:443?type=ws").unwrap();
        let q = Query::from_url(&url);
        assert_eq!(
            stream_from_query(&q).unwrap(),
            sont_core::Stream::Ws {
                path: "/".into(),
                host: None,
                max_early_data: None
            }
        );
    }

    #[test]
    fn unknown_transport_type_is_rejected() {
        let url = Url::parse("vless://u@h:443?type=carrier-pigeon").unwrap();
        let q = Query::from_url(&url);
        assert!(matches!(
            stream_from_query(&q),
            Err(LinkError::BadValue { field: "type", .. })
        ));
    }
}

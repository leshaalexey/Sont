//! `vmess://` — base64 от JSON-объекта.
//!
//! Единственная схема из поддерживаемых, где полезная нагрузка не URI. Формат
//! исторический и неаккуратный: числовые поля приходят то числами, то
//! строками, а часть панелей опускает половину полей.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use sont_core::transport::{Tls, Vmess};
use sont_core::{Endpoint, Secret, Security, ServerProfile, Stream, SubscriptionId, Transport};

use crate::LinkError;

/// Поле, которое панели присылают то числом, то строкой.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Loose {
    Str(String),
    Num(u64),
}

impl Loose {
    fn as_string(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Num(n) => n.to_string(),
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Str(s) => s.trim().parse().ok(),
            Self::Num(n) => Some(*n),
        }
    }
}

#[derive(Debug, Deserialize)]
struct VmessJson {
    #[serde(default)]
    ps: String,
    add: String,
    port: Loose,
    id: String,
    #[serde(default)]
    aid: Option<Loose>,
    /// Шифр. В новых конфигах часто отсутствует — тогда `auto`.
    #[serde(default)]
    scy: Option<String>,
    /// Транспорт: tcp, ws, grpc, h2, httpupgrade.
    #[serde(default)]
    net: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    /// `tls`, `reality` или пусто.
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    alpn: Option<String>,
    #[serde(default)]
    fp: Option<String>,
}

pub fn parse(line: &str, source: &SubscriptionId) -> Result<ServerProfile, LinkError> {
    let payload = line
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| LinkError::Malformed("нет разделителя ://".to_owned()))?;

    // Фрагмент в vmess-ссылках встречается редко, но встречается.
    let payload = payload.split('#').next().unwrap_or(payload).trim();

    let decoded = STANDARD
        .decode(payload)
        .or_else(|_| STANDARD_NO_PAD.decode(payload))
        .or_else(|_| URL_SAFE_NO_PAD.decode(payload))
        .map_err(|e| LinkError::Base64(e.to_string()))?;

    let json: VmessJson = serde_json::from_slice(&decoded)
        .map_err(|e| LinkError::Malformed(format!("тело vmess не разбирается как JSON: {e}")))?;

    if json.id.is_empty() {
        return Err(LinkError::MissingField("id"));
    }

    let port = json
        .port
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .ok_or(LinkError::BadValue {
            field: "port",
            value: json.port.as_string(),
        })?;

    let host_header = json.host.filter(|h| !h.is_empty());
    let path = json.path.filter(|p| !p.is_empty());

    let stream = match json.net.as_deref().unwrap_or("tcp") {
        "tcp" | "raw" | "" => Stream::Tcp,
        "ws" => Stream::Ws {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host: host_header.clone(),
            max_early_data: None,
        },
        "grpc" => Stream::Grpc {
            service_name: path.unwrap_or_default(),
        },
        "h2" | "http" => Stream::Http {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host: host_header.clone().into_iter().collect(),
        },
        "httpupgrade" => Stream::HttpUpgrade {
            path: path.unwrap_or_else(|| "/".to_owned()),
            host: host_header.clone(),
        },
        other => {
            return Err(LinkError::BadValue {
                field: "net",
                value: other.to_owned(),
            })
        }
    };

    let security = match json.tls.as_deref().unwrap_or("") {
        "" | "none" => Security::None,
        "tls" => Security::Tls(Tls {
            // SNI явный, иначе Host-заголовок, иначе адрес сервера.
            sni: json
                .sni
                .filter(|s| !s.is_empty())
                .or(host_header),
            alpn: json
                .alpn
                .map(|a| {
                    a.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            fingerprint: json.fp.filter(|f| !f.is_empty()),
            insecure: false,
        }),
        other => {
            return Err(LinkError::BadValue {
                field: "tls",
                value: other.to_owned(),
            })
        }
    };

    let endpoint = Endpoint::new(json.add.clone(), port);
    let name = if json.ps.trim().is_empty() {
        json.add
    } else {
        json.ps.trim().to_owned()
    };

    let transport = Transport::Vmess(Vmess {
        uuid: Secret::new(json.id),
        alter_id: json
            .aid
            .and_then(|a| a.as_u64())
            .and_then(|a| u16::try_from(a).ok())
            .unwrap_or(0),
        cipher: json
            .scy
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "auto".to_owned()),
        stream,
        security,
    });

    Ok(ServerProfile::new(name, endpoint, transport, source.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    fn link(json: &str) -> String {
        format!("vmess://{}", STANDARD.encode(json))
    }

    #[test]
    fn websocket_with_tls() {
        let l = link(
            r#"{"v":"2","ps":"🇯🇵 Tokyo","add":"jp.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","host":"jp.example.com","path":"/ray","tls":"tls","sni":"jp.example.com"}"#,
        );
        let p = parse(&l, &source()).unwrap();

        assert_eq!(p.name, "🇯🇵 Tokyo");
        assert_eq!(p.country.map(|c| c.as_str().to_owned()), Some("JP".into()));
        assert_eq!(p.endpoint, Endpoint::new("jp.example.com", 443));

        let Transport::Vmess(v) = &p.transport else {
            panic!("ожидался VMess");
        };
        assert_eq!(v.alter_id, 0);
        assert_eq!(v.cipher, "auto");
        assert_eq!(
            v.stream,
            Stream::Ws {
                path: "/ray".into(),
                host: Some("jp.example.com".into()),
                max_early_data: None
            }
        );
    }

    #[test]
    fn numeric_port_and_alter_id_are_accepted() {
        // Половина панелей шлёт эти поля числами, а не строками.
        let l = link(
            r#"{"ps":"N","add":"example.com","port":8443,"id":"uuid","aid":64,"net":"tcp"}"#,
        );
        let p = parse(&l, &source()).unwrap();
        assert_eq!(p.endpoint.port, 8443);

        let Transport::Vmess(v) = &p.transport else {
            panic!()
        };
        assert_eq!(v.alter_id, 64);
    }

    #[test]
    fn minimal_object_uses_defaults() {
        let l = link(r#"{"add":"example.com","port":"443","id":"uuid"}"#);
        let p = parse(&l, &source()).unwrap();

        assert_eq!(p.name, "example.com", "без ps имя берётся из адреса");
        let Transport::Vmess(v) = &p.transport else {
            panic!()
        };
        assert_eq!(v.cipher, "auto");
        assert_eq!(v.stream, Stream::Tcp);
        assert_eq!(v.security, Security::None);
    }

    #[test]
    fn base64_without_padding_is_accepted() {
        let json = r#"{"add":"example.com","port":"443","id":"uuid"}"#;
        let l = format!("vmess://{}", STANDARD_NO_PAD.encode(json));
        assert!(parse(&l, &source()).is_ok());
    }

    #[test]
    fn missing_id_is_rejected() {
        let l = link(r#"{"add":"example.com","port":"443","id":""}"#);
        assert_eq!(parse(&l, &source()), Err(LinkError::MissingField("id")));
    }

    #[test]
    fn nonsense_port_is_rejected() {
        let l = link(r#"{"add":"example.com","port":"99999","id":"uuid"}"#);
        assert!(matches!(
            parse(&l, &source()),
            Err(LinkError::BadValue { field: "port", .. })
        ));
    }

    #[test]
    fn broken_base64_is_reported_as_such() {
        assert!(matches!(
            parse("vmess://не base64!!!", &source()),
            Err(LinkError::Base64(_))
        ));
    }

    #[test]
    fn valid_base64_that_is_not_json_is_reported() {
        let l = format!("vmess://{}", STANDARD.encode("совсем не json"));
        assert!(matches!(parse(&l, &source()), Err(LinkError::Malformed(_))));
    }

    #[test]
    fn trailing_fragment_is_ignored() {
        let json = r#"{"add":"example.com","port":"443","id":"uuid"}"#;
        let l = format!("vmess://{}#Ignored", STANDARD.encode(json));
        assert!(parse(&l, &source()).is_ok());
    }
}

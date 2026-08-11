//! `vless://UUID@host:port?...#name`

use percent_encoding::percent_decode_str;
use sont_core::transport::Vless;
use sont_core::{Secret, ServerProfile, SubscriptionId, Transport};
use url::Url;

use super::{endpoint, fragment_name, security_from_query, stream_from_query, Query};
use crate::LinkError;

pub fn parse(line: &str, source: &SubscriptionId) -> Result<ServerProfile, LinkError> {
    let url = Url::parse(line).map_err(|e| LinkError::Malformed(e.to_string()))?;

    let uuid = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    if uuid.is_empty() {
        return Err(LinkError::MissingField("uuid"));
    }

    let ep = endpoint(&url)?;
    let q = Query::from_url(&url);

    let transport = Transport::Vless(Vless {
        uuid: Secret::new(uuid),
        flow: q.get_owned("flow"),
        stream: stream_from_query(&q)?,
        security: security_from_query(&q)?,
    });

    let name = fragment_name(&url, &ep.host);
    Ok(ServerProfile::new(name, ep, transport, source.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::{Security, Stream};

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    fn parse_ok(line: &str) -> ServerProfile {
        parse(line, &source()).unwrap_or_else(|e| panic!("не разобралось: {e}"))
    }

    #[test]
    fn reality_with_vision_flow() {
        // Самая распространённая сегодня форма.
        let p = parse_ok(
            "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=a1b2&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20NL",
        );

        assert_eq!(p.endpoint.host, "nl.example.com");
        assert_eq!(p.endpoint.port, 443);
        assert_eq!(p.name, "🇳🇱 NL");
        assert_eq!(p.country.map(|c| c.as_str().to_owned()), Some("NL".into()));

        let Transport::Vless(v) = &p.transport else {
            panic!("ожидался VLESS");
        };
        assert_eq!(v.uuid.expose(), "11111111-2222-3333-4444-555555555555");
        assert_eq!(v.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(v.stream, Stream::Tcp);

        let Security::Reality(r) = &v.security else {
            panic!("ожидался Reality");
        };
        assert_eq!(r.sni, "www.microsoft.com");
        assert_eq!(r.public_key, "PUBKEY");
        assert_eq!(r.short_id, "a1b2");
        assert_eq!(r.fingerprint.as_deref(), Some("chrome"));
    }

    #[test]
    fn websocket_over_tls() {
        let p = parse_ok(
            "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&path=%2Fws%3Fed%3D2048&host=cdn.example.com&alpn=h2,http%2F1.1#WS",
        );

        let Transport::Vless(v) = &p.transport else {
            panic!("ожидался VLESS");
        };
        assert_eq!(
            v.stream,
            Stream::Ws {
                path: "/ws?ed=2048".into(),
                host: Some("cdn.example.com".into()),
                max_early_data: None,
            }
        );

        let Security::Tls(tls) = &v.security else {
            panic!("ожидался TLS");
        };
        assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
        assert!(!tls.insecure);
    }

    #[test]
    fn grpc_service_name() {
        let p = parse_ok(
            "vless://uuid@example.com:443?type=grpc&serviceName=my-grpc&security=tls&sni=example.com#gRPC",
        );
        let Transport::Vless(v) = &p.transport else {
            panic!()
        };
        assert_eq!(
            v.stream,
            Stream::Grpc {
                service_name: "my-grpc".into()
            }
        );
    }

    #[test]
    fn plain_tcp_without_security() {
        let p = parse_ok("vless://uuid@example.com:8080?type=tcp#Plain");
        let Transport::Vless(v) = &p.transport else {
            panic!()
        };
        assert_eq!(v.security, Security::None);
        assert_eq!(v.flow, None);
    }

    #[test]
    fn missing_uuid_is_rejected() {
        assert_eq!(
            parse("vless://@example.com:443", &source()),
            Err(LinkError::MissingField("uuid"))
        );
    }

    #[test]
    fn name_falls_back_to_host() {
        let p = parse_ok("vless://uuid@example.com:443");
        assert_eq!(p.name, "example.com");
    }

    #[test]
    fn early_data_size_is_captured() {
        let p = parse_ok("vless://uuid@example.com:443?type=ws&ed=2560#ED");
        let Transport::Vless(v) = &p.transport else {
            panic!()
        };
        assert!(matches!(
            v.stream,
            Stream::Ws {
                max_early_data: Some(2560),
                ..
            }
        ));
    }

    #[test]
    fn insecure_flag_is_honoured_when_explicit() {
        let p = parse_ok("vless://uuid@example.com:443?security=tls&allowInsecure=1#I");
        let Transport::Vless(v) = &p.transport else {
            panic!()
        };
        let Security::Tls(tls) = &v.security else {
            panic!()
        };
        assert!(tls.insecure);
    }

    #[test]
    fn xhttp_over_reality() {
        // Форма, встреченная у реального провайдера: XHTTP поверх Reality,
        // пустой sid и составной фрагмент с двумя `#`.
        let p = parse_ok(
            "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:8443?type=xhttp&security=reality&encryption=none&fp=firefox&sni=api.dropbox.com&sid=&pbk=PUBKEY&path=%2F#e582c8a8-a5ec-46c6-aca6-55028629396d@example.io#Provider_AT",
        );

        assert_eq!(p.endpoint.host, "198.51.100.7");
        assert_eq!(p.endpoint.port, 8443);
        assert_eq!(
            p.name, "Provider_AT",
            "именем должна стать последняя часть составного фрагмента"
        );

        let Transport::Vless(v) = &p.transport else {
            panic!("ожидался VLESS");
        };
        assert_eq!(
            v.stream,
            Stream::Xhttp {
                path: "/".into(),
                host: None,
                mode: None
            }
        );

        let Security::Reality(r) = &v.security else {
            panic!("ожидался Reality");
        };
        assert_eq!(r.sni, "api.dropbox.com");
        assert_eq!(r.public_key, "PUBKEY");
        assert_eq!(r.short_id, "", "пустой sid допустим");
        assert_eq!(r.fingerprint.as_deref(), Some("firefox"));

        assert!(
            p.transport.requires_xray(),
            "XHTTP умеет только Xray — это должно быть видно до подключения"
        );
    }

    #[test]
    fn splithttp_is_accepted_as_the_former_name_of_xhttp() {
        let p = parse_ok("vless://uuid@example.com:443?type=splithttp&path=%2Fx&mode=stream-up#S");
        let Transport::Vless(v) = &p.transport else {
            panic!()
        };
        assert_eq!(
            v.stream,
            Stream::Xhttp {
                path: "/x".into(),
                host: None,
                mode: Some("stream-up".into())
            }
        );
    }

    #[test]
    fn common_transports_do_not_require_xray() {
        for link in [
            "vless://uuid@example.com:443?type=tcp#T",
            "vless://uuid@example.com:443?type=ws#W",
            "vless://uuid@example.com:443?type=grpc&serviceName=s#G",
        ] {
            assert!(
                !parse_ok(link).transport.requires_xray(),
                "не должно требовать Xray: {link}"
            );
        }
    }

    #[test]
    fn credentials_do_not_appear_in_debug_output() {
        let p = parse_ok("vless://SECRET-UUID@example.com:443#X");
        assert!(!format!("{p:?}").contains("SECRET-UUID"));
    }
}

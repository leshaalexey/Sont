//! `tuic://uuid:password@host:port?...#name`

use percent_encoding::percent_decode_str;
use sont_core::transport::Tuic;
use sont_core::{Secret, ServerProfile, SubscriptionId, Transport};
use url::Url;

use super::{endpoint, fragment_name, tls_from_query, Query};
use crate::LinkError;

pub fn parse(line: &str, source: &SubscriptionId) -> Result<ServerProfile, LinkError> {
    let url = Url::parse(line).map_err(|e| LinkError::Malformed(e.to_string()))?;

    let uuid = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    if uuid.is_empty() {
        return Err(LinkError::MissingField("uuid"));
    }

    let password = url
        .password()
        .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned())
        .ok_or(LinkError::MissingField("пароль"))?;

    let ep = endpoint(&url)?;
    let q = Query::from_url(&url);

    let mut tls = tls_from_query(&q);
    if tls.sni.is_none() {
        tls.sni = Some(ep.host.clone());
    }
    // TUIC работает поверх QUIC, а тот требует ALPN. Ссылки его часто
    // опускают, и без подстановки соединение не устанавливается.
    if tls.alpn.is_empty() {
        tls.alpn = vec!["h3".to_owned()];
    }

    let transport = Transport::Tuic(Tuic {
        uuid: Secret::new(uuid),
        password: Secret::new(password),
        congestion_control: q
            .get_owned("congestion_control")
            .or_else(|| q.get_owned("congestion-control"))
            .unwrap_or_else(|| "bbr".to_owned()),
        udp_relay_mode: q
            .get_owned("udp_relay_mode")
            .or_else(|| q.get_owned("udp-relay-mode"))
            .unwrap_or_else(|| "native".to_owned()),
        tls,
    });

    let name = fragment_name(&url, &ep.host);
    Ok(ServerProfile::new(name, ep, transport, source.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    fn tuic(p: &ServerProfile) -> &Tuic {
        let Transport::Tuic(t) = &p.transport else {
            panic!("ожидался TUIC");
        };
        t
    }

    #[test]
    fn basic_link() {
        let p = parse(
            "tuic://11111111-2222-3333-4444-555555555555:secret@sg.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=sg.example.com&alpn=h3#Singapore",
            &source(),
        )
        .unwrap();

        assert_eq!(p.name, "Singapore");
        assert_eq!(p.endpoint.port, 443);

        let t = tuic(&p);
        assert_eq!(t.uuid.expose(), "11111111-2222-3333-4444-555555555555");
        assert_eq!(t.password.expose(), "secret");
        assert_eq!(t.congestion_control, "bbr");
        assert_eq!(t.udp_relay_mode, "native");
        assert_eq!(t.tls.alpn, vec!["h3"]);
    }

    #[test]
    fn alpn_defaults_to_h3() {
        // QUIC без ALPN не договорится, а ссылки его часто не содержат.
        let p = parse("tuic://uuid:pw@example.com:443#T", &source()).unwrap();
        assert_eq!(tuic(&p).tls.alpn, vec!["h3"]);
    }

    #[test]
    fn sni_defaults_to_host() {
        let p = parse("tuic://uuid:pw@example.com:443#T", &source()).unwrap();
        assert_eq!(tuic(&p).tls.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn dashed_parameter_names_are_accepted() {
        let p = parse(
            "tuic://uuid:pw@example.com:443?congestion-control=cubic&udp-relay-mode=quic#T",
            &source(),
        )
        .unwrap();
        assert_eq!(tuic(&p).congestion_control, "cubic");
        assert_eq!(tuic(&p).udp_relay_mode, "quic");
    }

    #[test]
    fn missing_password_is_rejected() {
        assert_eq!(
            parse("tuic://uuid@example.com:443", &source()),
            Err(LinkError::MissingField("пароль"))
        );
    }

    #[test]
    fn missing_uuid_is_rejected() {
        assert_eq!(
            parse("tuic://:pw@example.com:443", &source()),
            Err(LinkError::MissingField("uuid"))
        );
    }

    #[test]
    fn credentials_are_not_exposed_in_debug() {
        let p = parse("tuic://uuid:SECRETPW@example.com:443", &source()).unwrap();
        assert!(!format!("{p:?}").contains("SECRETPW"));
    }

    #[test]
    fn protocol_is_marked_udp_based() {
        let p = parse("tuic://uuid:pw@example.com:443", &source()).unwrap();
        assert!(p.transport.is_udp_based());
    }
}

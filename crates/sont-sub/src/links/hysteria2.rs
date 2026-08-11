//! `hysteria2://auth@host:port?...#name` (и псевдоним `hy2://`)

use percent_encoding::percent_decode_str;
use sont_core::transport::{Hysteria2, Hysteria2Obfs};
use sont_core::{Secret, ServerProfile, SubscriptionId, Transport};
use url::Url;

use super::{endpoint, fragment_name, tls_from_query, Query};
use crate::LinkError;

pub fn parse(line: &str, source: &SubscriptionId) -> Result<ServerProfile, LinkError> {
    let url = Url::parse(line).map_err(|e| LinkError::Malformed(e.to_string()))?;

    // Аутентификация может быть записана и как `pass@`, и как `user:pass@`.
    // Ядру нужна строка целиком в том же виде.
    let user = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    let auth = match url.password() {
        Some(pass) => {
            let pass = percent_decode_str(pass).decode_utf8_lossy().into_owned();
            format!("{user}:{pass}")
        }
        None => user,
    };

    if auth.is_empty() {
        return Err(LinkError::MissingField("пароль"));
    }

    let ep = endpoint(&url)?;
    let q = Query::from_url(&url);

    let obfs = match q.get("obfs") {
        Some(kind) if !kind.eq_ignore_ascii_case("none") => Some(Hysteria2Obfs {
            kind: kind.to_ascii_lowercase(),
            password: Secret::new(
                q.get_owned("obfs-password")
                    .or_else(|| q.get_owned("obfs_password"))
                    .ok_or(LinkError::MissingField("obfs-password"))?,
            ),
        }),
        _ => None,
    };

    let mut tls = tls_from_query(&q);
    // Hysteria2 всегда поверх TLS, и без SNI проверка сертификата не пройдёт.
    // Если SNI не задан явно, берём адрес сервера.
    if tls.sni.is_none() {
        tls.sni = Some(ep.host.clone());
    }

    let transport = Transport::Hysteria2(Hysteria2 {
        password: Secret::new(auth),
        obfs,
        up_mbps: q.get("upmbps").or_else(|| q.get("up")).and_then(parse_mbps),
        down_mbps: q
            .get("downmbps")
            .or_else(|| q.get("down"))
            .and_then(parse_mbps),
        tls,
    });

    let name = fragment_name(&url, &ep.host);
    Ok(ServerProfile::new(name, ep, transport, source.clone()))
}

/// Полоса может быть записана как `100` или как `100 mbps`.
fn parse_mbps(value: &str) -> Option<u32> {
    let digits: String = value.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok().filter(|v| *v > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    fn hy2(p: &ServerProfile) -> &Hysteria2 {
        let Transport::Hysteria2(h) = &p.transport else {
            panic!("ожидался Hysteria2");
        };
        h
    }

    #[test]
    fn basic_link() {
        let p = parse(
            "hysteria2://mypassword@de.example.com:443?sni=de.example.com#%F0%9F%87%A9%F0%9F%87%AA%20DE",
            &source(),
        )
        .unwrap();

        assert_eq!(p.endpoint.host, "de.example.com");
        assert_eq!(p.name, "🇩🇪 DE");
        assert_eq!(hy2(&p).password.expose(), "mypassword");
        assert_eq!(hy2(&p).tls.sni.as_deref(), Some("de.example.com"));
        assert!(hy2(&p).obfs.is_none());
    }

    #[test]
    fn sni_defaults_to_host() {
        // Без SNI проверка сертификата не пройдёт, а ссылки часто его опускают.
        let p = parse("hy2://pw@example.com:443#X", &source()).unwrap();
        assert_eq!(hy2(&p).tls.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn salamander_obfuscation() {
        let p = parse(
            "hysteria2://pw@example.com:443?obfs=salamander&obfs-password=obfspw#O",
            &source(),
        )
        .unwrap();

        let obfs = hy2(&p).obfs.as_ref().expect("обфускация должна быть разобрана");
        assert_eq!(obfs.kind, "salamander");
        assert_eq!(obfs.password.expose(), "obfspw");
    }

    #[test]
    fn obfs_without_password_is_rejected() {
        // Молча выключить обфускацию нельзя: сервер её ждёт, и соединение
        // просто не поднимется без внятной причины.
        assert_eq!(
            parse("hysteria2://pw@example.com:443?obfs=salamander#O", &source()),
            Err(LinkError::MissingField("obfs-password"))
        );
    }

    #[test]
    fn obfs_none_is_treated_as_absent() {
        let p = parse("hysteria2://pw@example.com:443?obfs=none#O", &source()).unwrap();
        assert!(hy2(&p).obfs.is_none());
    }

    #[test]
    fn user_colon_password_form() {
        let p = parse("hysteria2://user:pass@example.com:443#U", &source()).unwrap();
        assert_eq!(hy2(&p).password.expose(), "user:pass");
    }

    #[test]
    fn bandwidth_limits_are_parsed() {
        let p = parse(
            "hysteria2://pw@example.com:443?upmbps=50&downmbps=200#B",
            &source(),
        )
        .unwrap();
        assert_eq!(hy2(&p).up_mbps, Some(50));
        assert_eq!(hy2(&p).down_mbps, Some(200));
    }

    #[test]
    fn bandwidth_with_units_is_parsed() {
        let p = parse("hysteria2://pw@example.com:443?up=100%20mbps#B", &source()).unwrap();
        assert_eq!(hy2(&p).up_mbps, Some(100));
    }

    #[test]
    fn insecure_flag_is_honoured() {
        let p = parse("hysteria2://pw@example.com:443?insecure=1#I", &source()).unwrap();
        assert!(hy2(&p).tls.insecure);
    }

    #[test]
    fn missing_password_is_rejected() {
        assert_eq!(
            parse("hysteria2://@example.com:443", &source()),
            Err(LinkError::MissingField("пароль"))
        );
    }

    #[test]
    fn protocol_is_marked_udp_based() {
        // От этого зависят разрешения kill-switch: QUIC ходит по UDP.
        let p = parse("hy2://pw@example.com:443", &source()).unwrap();
        assert!(p.transport.is_udp_based());
    }
}

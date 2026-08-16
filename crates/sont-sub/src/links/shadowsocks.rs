//! `ss://` — SIP002 и исторический формат.
//!
//! Разбирается вручную, а не через `url`: в старом формате вся строка
//! `method:password@host:port` закодирована в base64 целиком, и как URI такое
//! не читается.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use sont_core::transport::Shadowsocks;
use sont_core::{Endpoint, Secret, ServerProfile, SubscriptionId, Transport};

use crate::LinkError;

pub fn parse(line: &str, source: &SubscriptionId) -> Result<ServerProfile, LinkError> {
    let rest = line
        .split_once("://")
        .map(|(_, r)| r)
        .ok_or_else(|| LinkError::Malformed("нет разделителя ://".to_owned()))?;

    // Имя отделяем первым делом: в нём бывают любые символы, включая `@`.
    let (body, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (rest, None),
    };

    // Параметры отделяем от тела, но не выбрасываем: в них лежит `plugin`, от
    // которого зависит, сможем ли мы вообще подключиться к этому серверу.
    let (body, query) = match body.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (body, None),
    };
    let plugin = query.and_then(plugin_name);

    let (method, password, endpoint) = if let Some((userinfo, hostpart)) = body.rsplit_once('@') {
        // SIP002: userinfo отдельно, адрес в открытом виде.
        let creds = decode_userinfo(userinfo)?;
        let (method, password) = split_credentials(&creds)?;
        (method, password, parse_host_port(hostpart)?)
    } else {
        // Исторический формат: base64 от всей строки целиком.
        let decoded = decode_base64(body)?;
        let (userinfo, hostpart) = decoded
            .rsplit_once('@')
            .ok_or_else(|| LinkError::Malformed("нет разделителя @ в теле ss".to_owned()))?;
        let (method, password) = split_credentials(userinfo)?;
        (method, password, parse_host_port(hostpart)?)
    };

    if method.is_empty() {
        return Err(LinkError::MissingField("метод шифрования"));
    }

    let name = fragment
        .map(|f| percent_decode_str(f).decode_utf8_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| endpoint.host.clone());

    let transport = Transport::Shadowsocks(Shadowsocks {
        method,
        password: Secret::new(password),
        plugin,
    });

    Ok(ServerProfile::new(name, endpoint, transport, source.clone()))
}

/// Имя плагина SIP003 из строки запроса.
///
/// Значение выглядит как `obfs-local;obfs=http;obfs-host=example.com` — до
/// первой точки с запятой имя, дальше аргументы. Аргументы не разбираем: для
/// решения «сможем ли мы подключиться» достаточно самого факта плагина, а имя
/// нужно, чтобы отказ был не «этот сервер не поддерживается», а с названием.
fn plugin_name(query: &str) -> Option<String> {
    let raw = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "plugin")
        .map(|(_, value)| value)?;

    let decoded = percent_decode_str(raw).decode_utf8_lossy().into_owned();
    let name = decoded.split(';').next().unwrap_or(&decoded).trim();

    // `plugin=` без значения встречается и означает «плагина нет».
    (!name.is_empty()).then(|| name.to_owned())
}

/// Userinfo в SIP002 — base64url от `method:password`, но часть панелей
/// оставляет его в открытом виде с процентным кодированием.
fn decode_userinfo(userinfo: &str) -> Result<String, LinkError> {
    if let Ok(decoded) = decode_base64(userinfo) {
        if decoded.contains(':') {
            return Ok(decoded);
        }
    }

    let plain = percent_decode_str(userinfo)
        .decode_utf8_lossy()
        .into_owned();
    if plain.contains(':') {
        return Ok(plain);
    }

    Err(LinkError::Malformed(
        "не удалось прочитать учётные данные ss".to_owned(),
    ))
}

fn decode_base64(s: &str) -> Result<String, LinkError> {
    let bytes = STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| LinkError::Base64(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| LinkError::Base64(e.to_string()))
}

/// Делит `method:password` по первому двоеточию.
///
/// Именно по первому: пароли шифров 2022 — это base64, в котором двоеточий
/// не бывает, а вот в произвольных паролях они встречаются.
fn split_credentials(creds: &str) -> Result<(String, String), LinkError> {
    creds
        .split_once(':')
        .map(|(m, p)| (m.trim().to_owned(), p.to_owned()))
        .ok_or(LinkError::MissingField("метод и пароль ss"))
}

fn parse_host_port(s: &str) -> Result<Endpoint, LinkError> {
    let s = s.trim();

    // IPv6 записывается в скобках: [2001:db8::1]:8388
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| LinkError::Malformed("незакрытая скобка IPv6".to_owned()))?;
        let port = tail
            .strip_prefix(':')
            .ok_or(LinkError::MissingField("порт"))?;
        return Ok(Endpoint::new(host, parse_port(port)?));
    }

    let (host, port) = s.rsplit_once(':').ok_or(LinkError::MissingField("порт"))?;
    if host.is_empty() {
        return Err(LinkError::MissingField("хост"));
    }
    Ok(Endpoint::new(host, parse_port(port)?))
}

fn parse_port(s: &str) -> Result<u16, LinkError> {
    s.trim().parse().map_err(|_| LinkError::BadValue {
        field: "port",
        value: s.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    fn creds(p: &ServerProfile) -> (&str, &str) {
        let Transport::Shadowsocks(ss) = &p.transport else {
            panic!("ожидался Shadowsocks");
        };
        (ss.method.as_str(), ss.password.expose())
    }

    #[test]
    fn sip002_with_base64_userinfo() {
        let userinfo = STANDARD.encode("aes-256-gcm:пароль");
        let line = format!("ss://{userinfo}@fi.example.com:8388#%F0%9F%87%AB%F0%9F%87%AE%20Helsinki");
        let p = parse(&line, &source()).unwrap();

        assert_eq!(p.endpoint, Endpoint::new("fi.example.com", 8388));
        assert_eq!(p.name, "🇫🇮 Helsinki");
        assert_eq!(creds(&p), ("aes-256-gcm", "пароль"));
    }

    #[test]
    fn legacy_fully_encoded_form() {
        let body = STANDARD.encode("chacha20-ietf-poly1305:pw@example.com:8388");
        let line = format!("ss://{body}#Legacy");
        let p = parse(&line, &source()).unwrap();

        assert_eq!(p.endpoint, Endpoint::new("example.com", 8388));
        assert_eq!(creds(&p), ("chacha20-ietf-poly1305", "pw"));
    }

    #[test]
    fn shadowsocks_2022_password_survives_intact() {
        // Пароль шифров 2022 сам по себе base64 — его нельзя обрезать или
        // перекодировать, иначе соединение не поднимется.
        let password = "8JCcqBH2VkFPRXhHZ0VBQUFBQUFBQUE=";
        let userinfo = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{password}"));
        let line = format!("ss://{userinfo}@example.com:443#SS2022");

        let p = parse(&line, &source()).unwrap();
        assert_eq!(creds(&p), ("2022-blake3-aes-128-gcm", password));
    }

    #[test]
    fn plain_percent_encoded_userinfo() {
        // Часть панелей не кодирует userinfo в base64.
        let line = "ss://aes-128-gcm:my%3Apass@example.com:443#Plain";
        let p = parse(line, &source()).unwrap();
        assert_eq!(creds(&p), ("aes-128-gcm", "my:pass"));
    }

    #[test]
    fn password_containing_at_sign() {
        // Разделение по последнему `@` — иначе пароль обрежется.
        let userinfo = STANDARD.encode("aes-256-gcm:p@ssw0rd");
        let line = format!("ss://{userinfo}@example.com:443#At");
        let p = parse(&line, &source()).unwrap();
        assert_eq!(creds(&p), ("aes-256-gcm", "p@ssw0rd"));
    }

    #[test]
    fn ipv6_address_is_parsed() {
        let userinfo = STANDARD.encode("aes-256-gcm:pw");
        let line = format!("ss://{userinfo}@[2001:db8::1]:8388#v6");
        let p = parse(&line, &source()).unwrap();
        assert_eq!(p.endpoint, Endpoint::new("2001:db8::1", 8388));
    }

    fn plugin_of(p: &ServerProfile) -> Option<&str> {
        let Transport::Shadowsocks(ss) = &p.transport else {
            panic!("ожидался Shadowsocks");
        };
        ss.plugin.as_deref()
    }

    #[test]
    fn plugin_is_remembered_not_discarded() {
        // Выбросив плагин, мы получили бы профиль, который выглядит рабочим и
        // принимается ядром, — и молча не соединяется, потому что сервер ждёт
        // обфускации, которой нет. Запоминаем, чтобы отказать понятно.
        let userinfo = STANDARD.encode("aes-256-gcm:pw");
        let line = format!("ss://{userinfo}@example.com:443?plugin=obfs-local%3Bobfs%3Dhttp#Plugin");
        let p = parse(&line, &source()).unwrap();

        assert_eq!(p.endpoint.port, 443);
        assert_eq!(plugin_of(&p), Some("obfs-local"));
    }

    #[test]
    fn plugin_arguments_do_not_leak_into_the_name() {
        let userinfo = STANDARD.encode("aes-256-gcm:pw");
        let line = format!(
            "ss://{userinfo}@example.com:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls#WS"
        );
        assert_eq!(plugin_of(&parse(&line, &source()).unwrap()), Some("v2ray-plugin"));
    }

    #[test]
    fn no_plugin_means_none() {
        let userinfo = STANDARD.encode("aes-256-gcm:pw");

        // Совсем без параметров.
        let line = format!("ss://{userinfo}@example.com:443#Plain");
        assert_eq!(plugin_of(&parse(&line, &source()).unwrap()), None);

        // Параметры есть, плагина среди них нет.
        let line = format!("ss://{userinfo}@example.com:443?group=ru#Plain");
        assert_eq!(plugin_of(&parse(&line, &source()).unwrap()), None);

        // Пустое значение — то же самое, что его отсутствие.
        let line = format!("ss://{userinfo}@example.com:443?plugin=#Plain");
        assert_eq!(plugin_of(&parse(&line, &source()).unwrap()), None);
    }

    #[test]
    fn name_falls_back_to_host() {
        let userinfo = STANDARD.encode("aes-256-gcm:pw");
        let line = format!("ss://{userinfo}@example.com:443");
        assert_eq!(parse(&line, &source()).unwrap().name, "example.com");
    }

    #[test]
    fn missing_port_is_rejected() {
        let userinfo = STANDARD.encode("aes-256-gcm:pw");
        let line = format!("ss://{userinfo}@example.com");
        assert!(parse(&line, &source()).is_err());
    }

    #[test]
    fn garbage_is_rejected_not_panicking() {
        assert!(parse("ss://???", &source()).is_err());
        assert!(parse("ss://", &source()).is_err());
    }

    #[test]
    fn password_is_not_exposed_in_debug() {
        let userinfo = STANDARD.encode("aes-256-gcm:SECRETPW");
        let line = format!("ss://{userinfo}@example.com:443#X");
        let p = parse(&line, &source()).unwrap();
        assert!(!format!("{p:?}").contains("SECRETPW"));
    }
}

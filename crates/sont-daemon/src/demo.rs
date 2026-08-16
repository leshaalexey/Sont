//! Демонстрационный набор серверов для `sontd run --demo-servers`.
//!
//! Существует ровно для одной цели: проверить связку «tray → IPC → демон» до
//! того, как появится настоящий разбор подписок. Ничего из этого не попадает в
//! рабочий режим — без флага список серверов пуст, и демон честно сообщает,
//! что подписка не задана.
//!
//! Модуль удаляется целиком, как только заработает `sont-sub`.

use sont_core::{Endpoint, Secret, Security, ServerProfile, Stream, SubscriptionId, Transport};

/// Собирает несколько серверов с разными протоколами.
pub fn servers() -> Vec<ServerProfile> {
    let source = SubscriptionId::from_url("demo://local");

    vec![
        ServerProfile::new(
            "🇳🇱 Амстердам",
            Endpoint::new("nl-1.demo.invalid", 443),
            Transport::Vless(sont_core::transport::Vless {
                uuid: Secret::new("00000000-0000-0000-0000-000000000001"),
                flow: Some("xtls-rprx-vision".into()),
                stream: Stream::Tcp,
                security: Security::Reality(sont_core::transport::Reality {
                    sni: "www.microsoft.com".into(),
                    public_key: "demo-public-key".into(),
                    short_id: "a1b2".into(),
                    fingerprint: Some("chrome".into()),
                }),
            }),
            source.clone(),
        ),
        ServerProfile::new(
            "🇩🇪 Франкфурт",
            Endpoint::new("de-1.demo.invalid", 8443),
            Transport::Vless(sont_core::transport::Vless {
                uuid: Secret::new("00000000-0000-0000-0000-000000000002"),
                flow: None,
                stream: Stream::Ws {
                    path: "/ws".into(),
                    host: Some("de-1.demo.invalid".into()),
                    max_early_data: None,
                },
                security: Security::Tls(sont_core::transport::Tls {
                    sni: Some("de-1.demo.invalid".into()),
                    ..Default::default()
                }),
            }),
            source.clone(),
        ),
        ServerProfile::new(
            "🇫🇮 Хельсинки",
            Endpoint::new("fi-1.demo.invalid", 443),
            Transport::Shadowsocks(sont_core::transport::Shadowsocks {
                method: "2022-blake3-aes-128-gcm".into(),
                password: Secret::new("demo-password"),
                plugin: None,
            }),
            source.clone(),
        ),
        ServerProfile::new(
            "🇯🇵 Токио",
            Endpoint::new("jp-1.demo.invalid", 443),
            Transport::Vmess(sont_core::transport::Vmess {
                uuid: Secret::new("00000000-0000-0000-0000-000000000004"),
                alter_id: 0,
                cipher: "auto".into(),
                stream: Stream::Ws {
                    path: "/ray".into(),
                    host: Some("jp-1.demo.invalid".into()),
                    max_early_data: None,
                },
                security: Security::Tls(sont_core::transport::Tls {
                    sni: Some("jp-1.demo.invalid".into()),
                    ..Default::default()
                }),
            }),
            source,
        ),
    ]
}

/// Правдоподобная задержка для сервера — чтобы список в UI не был пустым.
///
/// Считается детерминированно от идентификатора: одинаковый порядок при
/// каждом запуске упрощает ручную проверку.
pub fn fake_rtt(id: &sont_core::ProfileId) -> u32 {
    let byte = id.as_str().bytes().map(u32::from).sum::<u32>();
    20 + (byte % 180)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_servers_have_distinct_ids() {
        let servers = servers();
        let mut ids: Vec<_> = servers.iter().map(|s| s.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), servers.len(), "идентификаторы должны различаться");
    }

    #[test]
    fn demo_hosts_use_reserved_tld() {
        // .invalid зарезервирован RFC 2606 и гарантированно не резолвится —
        // демонстрационный сервер не должен случайно указать на чужую машину.
        for s in servers() {
            assert!(
                s.endpoint.host.ends_with(".invalid"),
                "демо-хост должен быть заведомо нерезолвимым: {}",
                s.endpoint.host
            );
        }
    }

    #[test]
    fn countries_are_recognised() {
        for s in servers() {
            assert!(s.country.is_some(), "не распознана страна для {}", s.name);
        }
    }

    #[test]
    fn every_demo_server_is_supported_by_the_core() {
        // Демонстрационный набор обязан отражать то, что продукт реально
        // умеет. Сервер, к которому ядро не подключится, — это не демонстрация,
        // а ловушка: пользователь нажимает «подключить» и получает отказ.
        for s in servers() {
            assert!(
                sont_xray::supports(&s.transport),
                "{} использует протокол, не поддерживаемый ядром: {:?}",
                s.name,
                sont_xray::unsupported_reason(&s.transport)
            );
        }
    }

    #[test]
    fn fake_rtt_is_deterministic_and_plausible() {
        let servers = servers();
        let id = &servers[0].id;
        assert_eq!(fake_rtt(id), fake_rtt(id));
        assert!((20..200).contains(&fake_rtt(id)));
    }
}

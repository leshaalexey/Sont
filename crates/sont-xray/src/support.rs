//! Что именно умеет Xray.
//!
//! Знание о возможностях ядра живёт рядом с генератором его конфигурации, а не
//! в доменных типах: доменная модель описывает протоколы вообще, а не то, чем
//! мы их сегодня поднимаем. Сменится ядро — меняется только этот модуль.

use sont_core::transport::Shadowsocks;
use sont_core::Transport;

/// Может ли Xray подключиться к такому серверу.
pub fn supports(transport: &Transport) -> bool {
    unsupported_reason(transport).is_none()
}

/// Причина, по которой сервер не поддерживается. `None` — поддерживается.
///
/// Возвращаем текст, а не флаг: пользователю, у которого часть серверов
/// подписки не работает, нужно объяснение, а не молча укороченный список. И
/// текст с подробностями, а не общий: «метод aes-256-cfb больше не
/// поддерживается» отвечает на вопрос «а что делать», а «сервер не
/// поддерживается» — нет.
pub fn unsupported_reason(transport: &Transport) -> Option<String> {
    match transport {
        Transport::Vless(_) | Transport::Vmess(_) | Transport::WireGuard(_) => None,

        Transport::Shadowsocks(ss) => shadowsocks_reason(ss),

        // Оба протокола существуют вне экосистемы Xray и реализованы в
        // sing-box. Пытаться собрать для них конфиг бессмысленно: ядро
        // откажется его принимать.
        Transport::Tuic(_) => Some("TUIC не поддерживается ядром Xray".to_owned()),
        Transport::Hysteria2(_) => Some("Hysteria2 не поддерживается ядром Xray".to_owned()),
    }
}

/// Методы шифрования Shadowsocks, которые умеет Xray.
///
/// Список закрытый, а не «всё, кроме заведомо плохого». Неизвестный метод —
/// это либо опечатка панели, либо шифр, выброшенный из ядра; и в том, и в
/// другом случае лучше сказать об этом заранее, чем отдать ядру конфиг, на
/// котором оно откажется стартовать, а пользователь увидит «не удалось
/// запустить ядро» без единой подсказки.
const METHODS: [&str; 9] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

fn shadowsocks_reason(ss: &Shadowsocks) -> Option<String> {
    // Плагин — отдельный исполняемый файл, который Shadowsocks запускает рядом
    // с собой. У Xray такого механизма нет: без плагина сервер ждёт обфускации,
    // которой не будет, и соединение молча не поднимется.
    if let Some(plugin) = &ss.plugin {
        return Some(format!(
            "Shadowsocks с плагином {plugin} не поддерживается ядром Xray"
        ));
    }

    let method = ss.method.trim().to_ascii_lowercase();

    // Шифрование можно и отключить: такие серверы встречаются там, где
    // шифрование даёт транспорт уровнем выше.
    if matches!(method.as_str(), "none" | "plain") {
        return None;
    }

    if METHODS.contains(&method.as_str()) {
        return None;
    }

    Some(format!(
        "метод шифрования {} не поддерживается ядром Xray",
        ss.method
    ))
}

/// Работают ли на этой платформе правила маршрутизации по процессам.
///
/// Раздельное туннелирование опирается на поле `process` в правилах Xray,
/// а оно реализовано только для Windows и Linux. На macOS функцию нужно
/// прятать, а не показывать неработающей.
pub fn process_routing_available() -> bool {
    cfg!(any(target_os = "windows", target_os = "linux"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::transport::{Hysteria2, Shadowsocks, Tls, Tuic, Vless};
    use sont_core::{Secret, Security, Stream};

    fn vless() -> Transport {
        Transport::Vless(Vless {
            uuid: Secret::new("uuid"),
            flow: None,
            stream: Stream::Tcp,
            security: Security::None,
        })
    }

    fn ss(method: &str, plugin: Option<&str>) -> Transport {
        Transport::Shadowsocks(Shadowsocks {
            method: method.to_owned(),
            password: Secret::new("pw"),
            plugin: plugin.map(str::to_owned),
        })
    }

    #[test]
    fn xray_native_protocols_are_supported() {
        assert!(supports(&vless()));
        assert!(supports(&ss("aes-256-gcm", None)));
    }

    #[test]
    fn every_cipher_xray_implements_is_accepted() {
        // Список закрытый, поэтому его легко нечаянно урезать. Проверка не
        // даёт этого сделать молча.
        for method in METHODS {
            assert!(supports(&ss(method, None)), "отвергнут {method}");
        }
        // Регистр и пробелы в подписках встречаются, и это не повод отказывать.
        assert!(supports(&ss(" AES-256-GCM ", None)));
        // Шифрование можно и отключить.
        assert!(supports(&ss("none", None)));
        assert!(supports(&ss("plain", None)));
    }

    #[test]
    fn a_cipher_dropped_from_the_core_is_named_in_the_refusal() {
        // Потоковые шифры из ядра выброшены. Без этой проверки конфиг с ними
        // уходит ядру, оно отказывается стартовать, а пользователь видит «не
        // удалось запустить ядро» без единой подсказки, что делать.
        for method in ["aes-256-cfb", "rc4-md5", "chacha20"] {
            let reason = unsupported_reason(&ss(method, None))
                .unwrap_or_else(|| panic!("{method} должен быть отвергнут"));
            assert!(reason.contains(method), "в отказе нет метода: {reason}");
        }
    }

    #[test]
    fn a_plugin_is_refused_by_name() {
        // Плагин SIP003 — отдельный исполняемый файл рядом с Shadowsocks.
        // У Xray такого механизма нет, и без плагина сервер ждёт обфускации,
        // которой не будет: соединение поднимется и молча не заработает.
        let reason = unsupported_reason(&ss("aes-256-gcm", Some("obfs-local")))
            .expect("сервер с плагином должен быть отвергнут");
        assert!(reason.contains("obfs-local"), "в отказе нет плагина: {reason}");
    }

    #[test]
    fn tuic_is_rejected_with_an_explanation() {
        let t = Transport::Tuic(Tuic {
            uuid: Secret::new("u"),
            password: Secret::new("p"),
            congestion_control: "bbr".into(),
            udp_relay_mode: "native".into(),
            tls: Tls::default(),
        });
        assert!(!supports(&t));
        assert!(unsupported_reason(&t).unwrap().contains("TUIC"));
    }

    #[test]
    fn hysteria2_is_rejected_with_an_explanation() {
        let t = Transport::Hysteria2(Hysteria2 {
            password: Secret::new("p"),
            obfs: None,
            up_mbps: None,
            down_mbps: None,
            tls: Tls::default(),
        });
        assert!(!supports(&t));
        assert!(unsupported_reason(&t).unwrap().contains("Hysteria2"));
    }

    #[test]
    fn xhttp_is_supported_since_that_is_why_xray_was_chosen() {
        let t = Transport::Vless(Vless {
            uuid: Secret::new("uuid"),
            flow: None,
            stream: Stream::Xhttp {
                path: "/".into(),
                host: None,
                mode: None,
            },
            security: Security::None,
        });
        assert!(supports(&t));
    }

    #[cfg(windows)]
    #[test]
    fn process_routing_is_available_on_windows() {
        assert!(process_routing_available());
    }
}

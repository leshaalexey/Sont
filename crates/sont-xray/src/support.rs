//! Что именно умеет Xray.
//!
//! Знание о возможностях ядра живёт рядом с генератором его конфигурации, а не
//! в доменных типах: доменная модель описывает протоколы вообще, а не то, чем
//! мы их сегодня поднимаем. Сменится ядро — меняется только этот модуль.

use sont_core::{Transport, TransportKind};

/// Может ли Xray подключиться к такому серверу.
pub fn supports(transport: &Transport) -> bool {
    unsupported_reason(transport).is_none()
}

/// Причина, по которой сервер не поддерживается. `None` — поддерживается.
///
/// Возвращаем текст, а не флаг: пользователю, у которого часть серверов
/// подписки не работает, нужно объяснение, а не молча укороченный список.
pub fn unsupported_reason(transport: &Transport) -> Option<&'static str> {
    match transport.kind() {
        TransportKind::Vless
        | TransportKind::Vmess
        | TransportKind::Shadowsocks
        | TransportKind::WireGuard => None,

        // Оба протокола существуют вне экосистемы Xray и реализованы в
        // sing-box. Пытаться собрать для них конфиг бессмысленно: ядро
        // откажется его принимать.
        TransportKind::Tuic => Some("TUIC не поддерживается ядром Xray"),
        TransportKind::Hysteria2 => Some("Hysteria2 не поддерживается ядром Xray"),
    }
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

    #[test]
    fn xray_native_protocols_are_supported() {
        assert!(supports(&vless()));
        assert!(supports(&Transport::Shadowsocks(Shadowsocks {
            method: "aes-256-gcm".into(),
            password: Secret::new("pw"),
        })));
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

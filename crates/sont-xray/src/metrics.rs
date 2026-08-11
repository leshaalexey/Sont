//! Разбор счётчиков Xray.
//!
//! Ядро отдаёт статистику по `/debug/vars` служебного порта в формате Go
//! expvar. Здесь только разбор ответа — забирает его демон, у которого уже
//! есть HTTP-клиент.

use serde::Deserialize;

/// Накопительные счётчики трафика через прокси-outbound.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Deserialize)]
struct Vars {
    #[serde(default)]
    stats: Stats,
}

#[derive(Deserialize, Default)]
struct Stats {
    #[serde(default)]
    outbound: std::collections::HashMap<String, Link>,
}

#[derive(Deserialize, Default)]
struct Link {
    #[serde(default)]
    uplink: u64,
    #[serde(default)]
    downlink: u64,
}

/// Достаёт счётчики указанного outbound из ответа `/debug/vars`.
///
/// Возвращает `None`, если ответ не разобрался или нужного outbound в нём нет:
/// сразу после старта ядра счётчиков ещё не существует, и это нормальное
/// состояние, а не сбой.
pub fn parse(body: &str, outbound_tag: &str) -> Option<Counters> {
    let vars: Vars = serde_json::from_str(body).ok()?;
    let link = vars.stats.outbound.get(outbound_tag)?;
    Some(Counters {
        uplink: link.uplink,
        downlink: link.downlink,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "cmdline": ["xray"],
        "stats": {
            "inbound": { "tun-in": { "uplink": 10, "downlink": 20 } },
            "outbound": {
                "proxy": { "uplink": 1024, "downlink": 8192 },
                "direct": { "uplink": 1, "downlink": 2 }
            }
        }
    }"#;

    #[test]
    fn reads_the_requested_outbound() {
        assert_eq!(
            parse(SAMPLE, "proxy"),
            Some(Counters {
                uplink: 1024,
                downlink: 8192
            })
        );
    }

    #[test]
    fn distinguishes_outbounds() {
        assert_eq!(
            parse(SAMPLE, "direct"),
            Some(Counters {
                uplink: 1,
                downlink: 2
            })
        );
    }

    #[test]
    fn missing_outbound_is_not_an_error() {
        // Сразу после старта ядра счётчиков ещё нет.
        assert_eq!(parse(SAMPLE, "нет такого"), None);
    }

    #[test]
    fn empty_stats_are_handled() {
        assert_eq!(parse(r#"{"cmdline":["xray"]}"#, "proxy"), None);
    }

    #[test]
    fn malformed_body_yields_none_rather_than_panicking() {
        assert_eq!(parse("не json", "proxy"), None);
        assert_eq!(parse("", "proxy"), None);
    }

    #[test]
    fn partial_link_object_defaults_to_zero() {
        let body = r#"{"stats":{"outbound":{"proxy":{"uplink":5}}}}"#;
        assert_eq!(
            parse(body, "proxy"),
            Some(Counters {
                uplink: 5,
                downlink: 0
            })
        );
    }
}

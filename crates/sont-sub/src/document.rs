//! Разбор тела подписки целиком.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use sont_core::{ServerProfile, SubscriptionId};

use crate::links::parse_link;
use crate::LinkError;

/// Итог разбора документа.
#[derive(Debug, Default)]
pub struct ParseReport {
    pub profiles: Vec<ServerProfile>,
    /// Строки, которые разобрать не удалось, вместе с причиной.
    ///
    /// Их наличие не повод считать всю подписку негодной: панели регулярно
    /// подмешивают в список служебные строки и протоколы, которых мы не
    /// поддерживаем. Но показать пользователю, что часть серверов потерялась,
    /// нужно — иначе он будет гадать, почему их меньше, чем в личном кабинете.
    pub skipped: Vec<SkippedLink>,
}

#[derive(Debug)]
pub struct SkippedLink {
    /// Схема ссылки, если её удалось определить. Сама ссылка не сохраняется:
    /// в ней учётные данные, а отчёт попадает в логи.
    pub scheme: String,
    pub reason: LinkError,
}

impl ParseReport {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

/// Разбирает тело подписки.
///
/// Формат определяется автоматически: сначала пробуем прочитать тело как
/// base64, и если внутри оказался осмысленный список ссылок — работаем с ним,
/// иначе считаем тело открытым текстом.
pub fn parse_document(body: &str, source: &SubscriptionId) -> ParseReport {
    let text = decode_if_base64(body).unwrap_or_else(|| body.to_owned());

    let mut report = ParseReport::default();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let line = line.trim();
        // Пустые строки и комментарии — норма для многих панелей.
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        match parse_link(line, source) {
            Ok(profile) => {
                // Один и тот же сервер часто присутствует в подписке дважды —
                // например, под разными именами для разных клиентов.
                if seen.insert(profile.id.clone()) {
                    report.profiles.push(profile);
                }
            }
            Err(reason) => {
                let scheme = line
                    .split_once("://")
                    .map_or_else(|| "<нет схемы>".to_owned(), |(s, _)| s.to_lowercase());
                tracing::debug!(%scheme, %reason, "ссылка пропущена");
                report.skipped.push(SkippedLink { scheme, reason });
            }
        }
    }

    report
}

/// Пробует прочитать тело как base64.
///
/// Возвращает `None`, если это не base64 или внутри не оказалось ссылок —
/// тогда тело обрабатывается как открытый текст.
fn decode_if_base64(body: &str) -> Option<String> {
    // Панели переносят строки внутри base64 по-разному, а некоторые
    // добавляют пробелы. Для декодирования всё это лишнее.
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }

    // Порядок важен: сначала варианты с padding, затем без. URL-safe алфавит
    // встречается у панелей, отдающих подписку через сокращатели ссылок.
    let decoded = STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| URL_SAFE.decode(&compact))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&compact))
        .ok()?;

    let text = String::from_utf8(decoded).ok()?;

    // Проверка на осмысленность: без неё случайная строка, оказавшаяся
    // валидным base64, превратится в мусор, и мы решим, что подписка пуста,
    // вместо того чтобы разобрать её как открытый текст.
    text.contains("://").then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::TransportKind;

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub/token")
    }

    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=abcdefg&sid=a1b2&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam";
    const SS: &str = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@fi.example.com:8388#Helsinki";
    const HY2: &str = "hysteria2://secret@de.example.com:443?sni=de.example.com#Frankfurt";

    #[test]
    fn plain_list_is_parsed() {
        let body = format!("{VLESS}\n{SS}\n{HY2}\n");
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 3);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn base64_list_is_parsed() {
        let plain = format!("{VLESS}\n{SS}\n");
        let body = STANDARD.encode(&plain);
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 2);
    }

    #[test]
    fn base64_without_padding_is_parsed() {
        // Часть панелей отдаёт base64 без выравнивания.
        let plain = format!("{VLESS}\n{SS}\n");
        let body = STANDARD_NO_PAD.encode(&plain);
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 2);
    }

    #[test]
    fn base64_with_line_breaks_is_parsed() {
        // Некоторые панели переносят base64 по 76 символов.
        let plain = format!("{VLESS}\n{SS}\n");
        let encoded = STANDARD.encode(&plain);
        let wrapped: String = encoded
            .as_bytes()
            .chunks(76)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n");

        let report = parse_document(&wrapped, &source());
        assert_eq!(report.profiles.len(), 2);
    }

    #[test]
    fn url_safe_base64_is_parsed() {
        let plain = format!("{VLESS}\n");
        let body = URL_SAFE_NO_PAD.encode(&plain);
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 1);
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let body = format!("{VLESS}\r\n{SS}\r\n");
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 2);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let body = format!("# заголовок панели\n\n{VLESS}\n\n// комментарий\n{SS}\n");
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 2);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn unsupported_links_are_skipped_not_fatal() {
        let body = format!("{VLESS}\ntrojan://pw@example.com:443#Trojan\n{SS}\n");
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 2, "поддерживаемые серверы должны остаться");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].scheme, "trojan");
    }

    #[test]
    fn skipped_entries_do_not_leak_credentials() {
        // Отчёт уходит в логи — учётных данных в нём быть не должно.
        let body = "trojan://SUPER-SECRET-PASSWORD@example.com:443#T\n";
        let report = parse_document(body, &source());
        let rendered = format!("{:?}", report.skipped);
        assert!(!rendered.contains("SUPER-SECRET-PASSWORD"), "утечка: {rendered}");
    }

    #[test]
    fn duplicate_servers_are_collapsed() {
        let body = format!("{VLESS}\n{VLESS}\n");
        let report = parse_document(&body, &source());
        assert_eq!(report.profiles.len(), 1);
    }

    #[test]
    fn empty_body_yields_empty_report() {
        let report = parse_document("", &source());
        assert!(report.is_empty());
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn garbage_body_is_not_mistaken_for_base64() {
        // «Ошибка 404» вполне может оказаться валидным base64. Проверка на
        // наличие ссылок не даёт принять такой ответ за подписку.
        let report = parse_document("errorerror", &source());
        assert!(report.is_empty());
    }

    #[test]
    fn all_supported_schemes_round_trip() {
        let vmess = format!(
            "vmess://{}",
            STANDARD.encode(
                r#"{"v":"2","ps":"Tokyo","add":"jp.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","path":"/ray","host":"jp.example.com","tls":"tls"}"#
            )
        );
        let tuic = "tuic://11111111-2222-3333-4444-555555555555:pw@sg.example.com:443?congestion_control=bbr&alpn=h3#Singapore";

        let body = format!("{VLESS}\n{vmess}\n{SS}\n{HY2}\n{tuic}\n");
        let report = parse_document(&body, &source());

        assert_eq!(report.profiles.len(), 5, "пропущено: {:?}", report.skipped);

        let kinds: Vec<TransportKind> = report.profiles.iter().map(|p| p.transport.kind()).collect();
        assert!(kinds.contains(&TransportKind::Vless));
        assert!(kinds.contains(&TransportKind::Vmess));
        assert!(kinds.contains(&TransportKind::Shadowsocks));
        assert!(kinds.contains(&TransportKind::Hysteria2));
        assert!(kinds.contains(&TransportKind::Tuic));
    }
}

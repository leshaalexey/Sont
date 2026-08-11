//! Разбор заголовка `subscription-userinfo`.
//!
//! Панели отдают в нём расход трафика и срок действия подписки:
//!
//! ```text
//! subscription-userinfo: upload=1234; download=5678; total=107374182400; expire=1735689600
//! ```
//!
//! Формат неформальный, поэтому разбор нарочно снисходительный: незнакомые
//! ключи игнорируются, отсутствующие поля остаются пустыми. Заголовок —
//! справочная информация для UI, и его кривизна не должна мешать подключению.

use sont_core::SubscriptionInfo;

/// Разбирает значение заголовка.
///
/// Поля, которых нет или которые не разобрались, остаются `None`.
pub fn parse_user_info(header: &str) -> SubscriptionInfo {
    let mut info = SubscriptionInfo::default();

    for part in header.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let Ok(number) = value.parse::<u64>() else {
            continue;
        };

        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = Some(number),
            "download" => info.download = Some(number),
            "total" => info.total = Some(number),
            // `expire=0` у панелей означает «бессрочно», а не «истекло
            // 1 января 1970». Без этой оговорки подписка показывалась бы
            // просроченной.
            "expire" => info.expires_at_unix = (number > 0).then_some(number),
            _ => {}
        }
    }

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_header_is_parsed() {
        let info = parse_user_info("upload=1234; download=5678; total=107374182400; expire=1735689600");
        assert_eq!(info.upload, Some(1234));
        assert_eq!(info.download, Some(5678));
        assert_eq!(info.total, Some(107_374_182_400));
        assert_eq!(info.expires_at_unix, Some(1_735_689_600));
    }

    #[test]
    fn zero_expire_means_unlimited() {
        let info = parse_user_info("upload=0; download=0; total=0; expire=0");
        assert_eq!(
            info.expires_at_unix, None,
            "expire=0 означает бессрочную подписку"
        );
        assert!(!info.is_expired(u64::MAX));
    }

    #[test]
    fn partial_header_is_accepted() {
        let info = parse_user_info("download=100");
        assert_eq!(info.download, Some(100));
        assert_eq!(info.upload, None);
        assert_eq!(info.total, None);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let info = parse_user_info("upload=1; something=else; download=2");
        assert_eq!(info.upload, Some(1));
        assert_eq!(info.download, Some(2));
    }

    #[test]
    fn non_numeric_values_are_skipped_not_fatal() {
        let info = parse_user_info("upload=много; download=5");
        assert_eq!(info.upload, None);
        assert_eq!(info.download, Some(5));
    }

    #[test]
    fn whitespace_variations_are_tolerated() {
        let a = parse_user_info("upload=1;download=2;total=3");
        let b = parse_user_info("  upload = 1 ;  download = 2 ; total = 3  ");
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_keys() {
        let info = parse_user_info("Upload=1; DOWNLOAD=2; Total=3");
        assert_eq!(info.upload, Some(1));
        assert_eq!(info.download, Some(2));
        assert_eq!(info.total, Some(3));
    }

    #[test]
    fn empty_header_yields_defaults() {
        assert_eq!(parse_user_info(""), SubscriptionInfo::default());
    }

    #[test]
    fn computed_fields_work_on_parsed_header() {
        let info = parse_user_info("upload=1073741824; download=3221225472; total=10737418240");
        assert_eq!(info.used_percent(), Some(40));
        assert_eq!(info.remaining_bytes(), Some(6_442_450_944));
    }
}

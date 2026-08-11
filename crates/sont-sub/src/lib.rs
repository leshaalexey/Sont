//! Разбор подписок VPN-панелей.
//!
//! # Что здесь происходит
//!
//! Панель (Marzban, 3x-ui, Remnawave и прочие) отдаёт по ссылке подписки
//! документ, в котором построчно перечислены ссылки на серверы. Документ может
//! быть в base64 или в открытом виде, ссылки — пяти разных схем, и каждая
//! панель расходится с соседней в мелочах: регистр параметров, наличие
//! padding в base64, кодирование имени в `#fragment`.
//!
//! # Принцип
//!
//! Крейт ничего не скачивает — на входе строка, на выходе типизированные
//! [`sont_core::ServerProfile`]. Это делает разбор полностью
//! детерминированным и тестируемым на корпусе фикстур, без сети.
//!
//! Всё, что не разобралось, отбрасывается с диагностикой и **не** прокидывается
//! дальше в виде сырых данных: конфиг для ядра собирается только из
//! типизированных структур (см. [`sont_core::Transport`]).

pub mod document;
pub mod links;
pub mod userinfo;

pub use document::{parse_document, ParseReport};
pub use links::parse_link;
pub use userinfo::parse_user_info;

/// Ошибка разбора одной ссылки.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("неизвестная схема ссылки: {0}")]
    UnknownScheme(String),

    #[error("ссылка не разбирается как URI: {0}")]
    Malformed(String),

    #[error("отсутствует обязательное поле: {0}")]
    MissingField(&'static str),

    #[error("недопустимое значение поля {field}: {value}")]
    BadValue { field: &'static str, value: String },

    #[error("не удалось декодировать base64: {0}")]
    Base64(String),
}

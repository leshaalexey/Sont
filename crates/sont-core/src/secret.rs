//! Обёртка над секретными строками.
//!
//! Инвариант архитектуры: ключ подписки, UUID, пароли и приватные ключи не
//! попадают в логи и в диагностический архив. Полагаться на дисциплину
//! разработчика здесь нельзя — одна `tracing::debug!("{profile:?}")` сливает
//! платный доступ пользователя в текстовый файл.
//!
//! Поэтому секрет — отдельный тип, у которого `Debug` и `Display` печатают
//! маску. Достать настоящее значение можно только явным `expose()`, и такой
//! вызов видно на code review.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Строка, которую нельзя случайно напечатать.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Единственный способ получить настоящее значение.
    ///
    /// Вызывать только там, где значение уходит в конфиг ядра, в защищённое
    /// хранилище или в исходящий HTTP-запрос.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Маска для показа в UI: `abcd…wxyz`.
    ///
    /// Для коротких значений возвращает только звёздочки, чтобы не раскрывать
    /// значимую долю секрета.
    pub fn masked(&self) -> String {
        let chars: Vec<char> = self.0.chars().collect();
        if chars.len() <= 12 {
            return "•".repeat(8);
        }
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}…{tail}")
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Сериализация — это путь в конфиг ядра и в хранилище, здесь нужно
        // настоящее значение. Защиту самого хранилища обеспечивает слой secrets.
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak() {
        let s = Secret::new("super-secret-subscription-token");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
        assert!(!format!("{s:?} {s}").contains("subscription"));
    }

    #[test]
    fn short_secrets_are_fully_masked() {
        assert_eq!(Secret::new("short").masked(), "••••••••");
        assert_eq!(Secret::new("123456789012").masked(), "••••••••");
    }

    #[test]
    fn long_secrets_show_edges_only() {
        assert_eq!(Secret::new("abcdefghijklmnop").masked(), "abcd…mnop");
    }

    #[test]
    fn roundtrips_through_serde() {
        let s = Secret::new("value");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"value\"");
        assert_eq!(serde_json::from_str::<Secret>(&json).unwrap(), s);
    }
}

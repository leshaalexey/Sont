//! Детерминированное хэширование для стабильных идентификаторов.
//!
//! `std::collections::hash_map::DefaultHasher` для этого не годится: стандартная
//! библиотека явно не гарантирует стабильность его результата между версиями и
//! запусками. А `ProfileId` обязан быть стабильным — иначе избранные серверы и
//! закреплённый выбор пользователя слетают при каждом обновлении подписки.
//!
//! FNV-1a 64-бит: детерминированный, без зависимостей, для идентификаторов
//! достаточный. Это не криптографический хэш и не используется как таковой.

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Инкрементальный FNV-1a.
#[derive(Debug, Clone)]
pub struct Fnv1a(u64);

impl Default for Fnv1a {
    fn default() -> Self {
        Self(FNV_OFFSET_BASIS)
    }
}

impl Fnv1a {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    /// Добавляет поле с разделителем, чтобы `("ab", "c")` и `("a", "bc")`
    /// давали разные хэши.
    pub fn field(&mut self, value: &str) -> &mut Self {
        self.write(value.as_bytes());
        self.write(&[0x1f]);
        self
    }

    pub fn finish(&self) -> u64 {
        self.0
    }

    pub fn finish_hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // Классический контрольный вектор FNV-1a 64.
        let mut h = Fnv1a::new();
        h.write(b"hello");
        assert_eq!(h.finish(), 0xa430_d846_80aa_bd0b);
    }

    #[test]
    fn field_separator_prevents_collision() {
        let mut a = Fnv1a::new();
        a.field("ab").field("c");
        let mut b = Fnv1a::new();
        b.field("a").field("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn is_deterministic() {
        let mut a = Fnv1a::new();
        a.field("example.com").field("443");
        let mut b = Fnv1a::new();
        b.field("example.com").field("443");
        assert_eq!(a.finish_hex(), b.finish_hex());
    }
}

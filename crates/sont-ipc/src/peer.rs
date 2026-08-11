//! Личность процесса на другом конце канала и решение, пускать ли его.
//!
//! Права на сам pipe/сокет — первая линия обороны, но её мало. На Windows к
//! каналу допущены все интерактивные пользователи (иначе tray пришлось бы
//! запускать от администратора), а на Unix — вся группа `sont`. Поэтому демон
//! дополнительно смотрит, *кто* именно подключился.

use std::path::PathBuf;

/// Что удалось узнать о подключившемся процессе.
///
/// Все поля опциональны: набор доступных сведений отличается между Windows и
/// Unix, и политика должна явно решать, что делать при их отсутствии, а не
/// получать правдоподобные нули.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pid: Option<u32>,
    /// Владелец процесса (Unix).
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Путь к исполняемому файлу.
    pub exe_path: Option<PathBuf>,
}

impl PeerIdentity {
    /// Короткое описание для логов.
    pub fn describe(&self) -> String {
        let pid = self
            .pid
            .map_or_else(|| "?".to_owned(), |p| p.to_string());
        let exe = self
            .exe_path
            .as_deref()
            .and_then(|p| p.to_str())
            .unwrap_or("<неизвестно>");
        match self.uid {
            Some(uid) => format!("pid={pid} uid={uid} exe={exe}"),
            None => format!("pid={pid} exe={exe}"),
        }
    }
}

/// Решение о допуске.
pub trait AuthPolicy: Send + Sync + 'static {
    /// `Ok(())` — пускаем. `Err(причина)` — отказ, причина уходит в лог и
    /// клиенту.
    fn authorize(&self, peer: &PeerIdentity) -> Result<(), String>;
}

/// Политика по умолчанию.
///
/// # Что проверяется сейчас
///
/// * Личность пира вообще удалось установить. Если нет — отказ: неизвестный
///   процесс не должен управлять службой, работающей от SYSTEM/root.
/// * Если задан [`DefaultPolicy::require_exe_under`], исполняемый файл клиента
///   обязан лежать внутри этого каталога. Это отсекает произвольную программу
///   пользователя, которая нашла канал и решила им воспользоваться.
///
/// # Что осознанно не проверяется на этом этапе
///
/// Подпись Authenticode на Windows. Проверка требует WinTrust и аккуратной
/// работы с политикой отзыва; она запланирована вместе с подписыванием сборок
/// и до тех пор не имитируется — лучше честное «проверяется путь», чем
/// видимость криптографической проверки. См. [`AuthPolicy`] — политику можно
/// заменить, не трогая транспорт.
pub struct DefaultPolicy {
    require_exe_under: Option<PathBuf>,
}

impl DefaultPolicy {
    pub fn new() -> Self {
        Self {
            require_exe_under: None,
        }
    }

    /// Требовать, чтобы клиент запускался из указанного каталога установки.
    pub fn require_exe_under(mut self, dir: impl Into<PathBuf>) -> Self {
        self.require_exe_under = Some(dir.into());
        self
    }
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthPolicy for DefaultPolicy {
    fn authorize(&self, peer: &PeerIdentity) -> Result<(), String> {
        // Набор доступных сведений зависит от платформы: Windows даёт pid,
        // macOS через getpeereid — uid без pid. Достаточно любого из них;
        // полное отсутствие идентификации — отказ.
        if peer.pid.is_none() && peer.uid.is_none() {
            return Err("не удалось определить процесс клиента".to_owned());
        }

        if let Some(dir) = &self.require_exe_under {
            let Some(exe) = &peer.exe_path else {
                return Err("не удалось определить путь к исполняемому файлу клиента".to_owned());
            };
            // Сравниваем канонизированные пути: иначе `C:\Program Files\Sont`
            // и `C:\PROGRA~1\Sont` считаются разными, а `..\..\evil.exe`
            // проходит проверку префикса.
            let exe = exe.canonicalize().map_err(|e| {
                format!("не удалось канонизировать путь клиента {}: {e}", exe.display())
            })?;
            let dir = dir
                .canonicalize()
                .map_err(|e| format!("не удалось канонизировать каталог установки: {e}"))?;
            if !exe.starts_with(&dir) {
                return Err(format!(
                    "клиент запущен вне каталога установки: {}",
                    exe.display()
                ));
            }
        }

        Ok(())
    }
}

/// Политика, пускающая кого угодно.
///
/// Только для тестов и для `sontd run --foreground` при отладке. В рабочей
/// сборке службы не используется.
pub struct AllowAll;

impl AuthPolicy for AllowAll {
    fn authorize(&self, _peer: &PeerIdentity) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unidentified_peer_is_rejected() {
        let policy = DefaultPolicy::new();
        assert!(policy.authorize(&PeerIdentity::default()).is_err());
    }

    #[test]
    fn identified_peer_is_accepted_without_path_requirement() {
        let policy = DefaultPolicy::new();
        let peer = PeerIdentity {
            pid: Some(1234),
            ..Default::default()
        };
        assert!(policy.authorize(&peer).is_ok());
    }

    #[test]
    fn peer_outside_install_dir_is_rejected() {
        let tmp = std::env::temp_dir();
        let policy = DefaultPolicy::new().require_exe_under(tmp.join("sont-install-dir-that-differs"));
        let peer = PeerIdentity {
            pid: Some(1234),
            exe_path: Some(tmp.clone()),
            ..Default::default()
        };
        assert!(policy.authorize(&peer).is_err());
    }

    #[test]
    fn missing_exe_path_is_rejected_when_required() {
        let policy = DefaultPolicy::new().require_exe_under(std::env::temp_dir());
        let peer = PeerIdentity {
            pid: Some(1234),
            exe_path: None,
            ..Default::default()
        };
        assert!(policy.authorize(&peer).is_err());
    }

    #[test]
    fn describe_is_useful_in_logs() {
        let peer = PeerIdentity {
            pid: Some(42),
            uid: Some(1000),
            gid: Some(1000),
            exe_path: Some(PathBuf::from("/usr/bin/sont-tray")),
        };
        let s = peer.describe();
        assert!(s.contains("pid=42"));
        assert!(s.contains("uid=1000"));
        assert!(s.contains("sont-tray"));
    }

    #[test]
    fn allow_all_accepts_anonymous_peer() {
        assert!(AllowAll.authorize(&PeerIdentity::default()).is_ok());
    }
}

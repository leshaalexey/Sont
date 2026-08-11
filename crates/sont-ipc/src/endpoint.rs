//! Где живёт точка подключения.

/// Имя named pipe на Windows / путь к unix-сокету на macOS и Linux.
///
/// Слушатель только локальный. Сетевого варианта нет и не предусмотрено:
/// демон работает от SYSTEM/root, и открытый на интерфейс порт превратил бы
/// его в средство удалённого управления системой.
#[cfg(windows)]
pub fn endpoint_name() -> String {
    r"\\.\pipe\sont-daemon".to_owned()
}

#[cfg(target_os = "macos")]
pub fn endpoint_name() -> String {
    "/var/run/sont/daemon.sock".to_owned()
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn endpoint_name() -> String {
    "/run/sont/daemon.sock".to_owned()
}

/// Дескриптор безопасности слушателя в формате SDDL (только Windows).
///
/// * `SY` — LocalSystem, под которым работает служба: полный доступ.
/// * `BA` — администраторы: полный доступ, чтобы работал CLI `sontd`.
/// * `IU` — интерактивно вошедшие пользователи: чтение и запись. Именно под
///   ними работает tray-приложение, которому права администратора не нужны.
///
/// `P` отключает наследование, чтобы к каналу не приклеились ACE откуда-то ещё.
/// Everyone и Anonymous доступа не получают.
#[cfg(windows)]
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Каталог, в котором создаётся сокет (Unix). Демон обязан создать его с
/// правами `0755 root:root` до того, как открывать слушатель.
#[cfg(unix)]
pub fn socket_dir() -> &'static str {
    if cfg!(target_os = "macos") {
        "/var/run/sont"
    } else {
        "/run/sont"
    }
}

/// Права на сам файл сокета: чтение и запись владельцу и группе `sont`,
/// остальным ничего.
#[cfg(unix)]
pub const SOCKET_MODE: u32 = 0o660;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_local_only() {
        let name = endpoint_name();
        assert!(!name.is_empty());
        // Ни при каких условиях это не должно превратиться в сетевой адрес.
        assert!(
            !name.contains("0.0.0.0") && !name.contains("://"),
            "точка подключения обязана быть локальной: {name}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_endpoint_is_a_named_pipe() {
        assert!(endpoint_name().starts_with(r"\\.\pipe\"));
    }

    #[cfg(windows)]
    #[test]
    fn sddl_denies_everyone_and_disables_inheritance() {
        assert!(PIPE_SDDL.starts_with("D:P"), "наследование ACE должно быть отключено");
        assert!(!PIPE_SDDL.contains(";;;WD)"), "Everyone не должен иметь доступа");
        assert!(!PIPE_SDDL.contains(";;;AN)"), "Anonymous не должен иметь доступа");
    }
}

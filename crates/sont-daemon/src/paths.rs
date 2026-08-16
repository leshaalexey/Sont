//! Где демон хранит своё состояние.
//!
//! Каталоги системные, а не пользовательские: демон работает от SYSTEM/root и
//! обслуживает машину целиком, а не конкретную сессию. Права на них выставляет
//! установщик — здесь мы только вычисляем пути.

use std::path::PathBuf;

/// Корневой каталог состояния демона.
pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // ProgramData, а не AppData: состояние принадлежит машине.
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Sont")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Sont")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/sont")
    }
}

/// Файл настроек.
pub fn settings_file() -> PathBuf {
    data_dir().join("settings.json")
}

/// Файл со списком избранных серверов.
pub fn favorites_file() -> PathBuf {
    data_dir().join("favorites.json")
}

/// Все подписки одним зашифрованным файлом.
///
/// Ключи, разобранные серверы и показатели панели лежат вместе: разнеси их по
/// файлам — и рано или поздно получишь ключ без серверов или серверы от
/// удалённой подписки, потому что одна из записей не сохранилась.
pub fn subscriptions_file() -> PathBuf {
    data_dir().join("subscriptions.bin")
}

/// Зашифрованный ключ единственной подписки — раскладка до появления списка.
///
/// Читается один раз, ради переноса, и после него удаляется.
pub fn legacy_subscription_file() -> PathBuf {
    data_dir().join("subscription.bin")
}

/// Каталог журналов.
pub fn log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Logs/Sont")
    }
    #[cfg(not(target_os = "macos"))]
    {
        data_dir().join("logs")
    }
}

/// Каталог с ядром Xray и его файлами geoip/geosite.
pub fn core_dir() -> PathBuf {
    data_dir().join("core")
}

/// Бинарь ядра.
pub fn core_binary() -> PathBuf {
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    core_dir().join(name)
}

/// Сгенерированная конфигурация ядра.
///
/// Лежит рядом с остальным состоянием демона, а не во временном каталоге:
/// в ней учётные данные сервера, а системный temp доступен всем пользователям.
pub fn core_config() -> PathBuf {
    data_dir().join("xray-config.json")
}

/// Зашифрованный кэш разобранной подписки — раскладка до появления списка.
///
/// Шифруется наравне с самим ключом: в разобранных профилях лежат UUID и
/// пароли от серверов, то есть ровно тот же платный доступ. Читается один раз,
/// ради переноса.
pub fn legacy_servers_cache_file() -> PathBuf {
    data_dir().join("servers.bin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_absolute_and_nested_under_data_dir() {
        let root = data_dir();
        assert!(root.is_absolute(), "путь должен быть абсолютным: {}", root.display());
        assert!(settings_file().starts_with(&root));
        assert!(favorites_file().starts_with(&root));
        assert!(subscriptions_file().starts_with(&root));
        assert!(legacy_servers_cache_file().starts_with(&root));
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_lives_in_programdata_not_appdata() {
        // AppData привязан к пользователю, а служба обслуживает всю машину.
        let dir = data_dir().to_string_lossy().to_lowercase();
        assert!(dir.contains("programdata"), "неожиданный каталог: {dir}");
    }
}

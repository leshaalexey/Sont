//! Атомарное хранение JSON-состояния на диске.
//!
//! Запись «в тот же файл» здесь не годится: питание может пропасть посреди
//! записи, и демон при следующем старте получит обрезанный JSON вместо
//! настроек. Пишем во временный файл рядом и переименовываем — на всех трёх
//! целевых ОС rename в пределах одного тома атомарен.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Читает значение или возвращает значение по умолчанию, если файла нет.
///
/// Битый файл — не повод не запускаться: испорченные настройки не должны
/// оставлять пользователя без VPN. Такой файл откладывается в сторону с
/// суффиксом `.corrupt`, чтобы его можно было изучить, и работа продолжается с
/// умолчаниями.
pub fn load_or_default<T: DeserializeOwned + Default>(path: &Path) -> T {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "не удалось прочитать файл состояния");
            return T::default();
        }
    };

    match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "файл состояния повреждён, используются значения по умолчанию"
            );
            let backup = path.with_extension("corrupt");
            if let Err(e) = std::fs::rename(path, &backup) {
                tracing::warn!(error = %e, "не удалось отложить повреждённый файл");
            }
            T::default()
        }
    }
}

/// Атомарно сохраняет значение.
pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("не удалось создать каталог {}", dir.display()))?;
    }

    let json = serde_json::to_vec_pretty(value).context("не удалось сериализовать состояние")?;

    // Временный файл кладём рядом с целевым: rename атомарен только в
    // пределах одной файловой системы, а системный каталог для временных
    // файлов вполне может оказаться на другом томе.
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)
            .with_context(|| format!("не удалось создать {}", tmp.display()))?;
        file.write_all(&json)?;
        // Без fsync переименование может опередить попадание данных на диск,
        // и после внезапной перезагрузки на месте настроек окажутся нули.
        file.sync_all()?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("не удалось переименовать {} в {}", tmp.display(), path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Sample {
        value: u32,
        name: String,
    }

    #[test]
    fn missing_file_yields_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");
        assert_eq!(load_or_default::<Sample>(&path), Sample::default());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");

        let value = Sample {
            value: 7,
            name: "тест".into(),
        };
        save(&path, &value).unwrap();
        assert_eq!(load_or_default::<Sample>(&path), value);
    }

    #[test]
    fn corrupt_file_is_set_aside_and_defaults_are_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, b"{ this is not json").unwrap();

        assert_eq!(load_or_default::<Sample>(&path), Sample::default());
        assert!(
            path.with_extension("corrupt").exists(),
            "повреждённый файл должен сохраняться для разбора"
        );
        assert!(!path.exists(), "повреждённый файл не должен остаться на месте");
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        save(&path, &Sample::default()).unwrap();
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn overwrite_replaces_previous_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        save(&path, &Sample { value: 1, name: "первый".into() }).unwrap();
        save(&path, &Sample { value: 2, name: "второй".into() }).unwrap();

        let loaded: Sample = load_or_default(&path);
        assert_eq!(loaded.value, 2);
        assert_eq!(loaded.name, "второй");
    }
}

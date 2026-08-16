//! Хранение ключа подписки.
//!
//! Ключ подписки — это и есть платный доступ пользователя: кто им владеет, тот
//! пользуется оплаченным трафиком. В открытом виде на диске ему не место.
//!
//! # Что это защищает, а что нет
//!
//! На Windows используется DPAPI с областью машины: расшифровать файл можно
//! только на той же машине, и утёкшая копия (в бэкапе, в чужом облаке, в
//! отправленном в поддержку архиве) бесполезна.
//!
//! От локального администратора это не защищает и защитить не может — он
//! запускается в том же контексте, что и служба. Цель скромнее и достижима:
//! ключ не лежит открытым текстом там, где его подхватит синхронизация,
//! антивирусный отчёт или невнимательный `type settings.json`.

use std::path::Path;

use anyhow::{Context, Result};
use sont_core::Secret;

/// Читает ключ, сохранённый в раскладке до появления списка подписок.
///
/// Писать в этом формате больше нечему: подписки хранятся списком через
/// [`store_json`]. Чтение осталось ради переноса — ключ пользователя не должен
/// пропасть из-за того, что у нас поменялась структура файлов.
///
/// `Ok(None)` — файла нет.
pub fn load(path: &Path) -> Result<Option<Secret>> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let plain = platform::unprotect(&raw).context(
        "не удалось расшифровать ключ подписки: файл повреждён или создан на другой машине",
    )?;

    let text = String::from_utf8(plain).context("ключ подписки не является текстом")?;
    Ok(Some(Secret::new(text)))
}

/// Сохраняет структуру в зашифрованном виде.
///
/// Нужно для кэша разобранной подписки: в профилях серверов лежат те же
/// учётные данные, что и в самом ключе, и хранить их открыто нет смысла.
pub fn store_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_vec(value).context("не удалось сериализовать данные")?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let protected = platform::protect(&json).context("не удалось зашифровать данные")?;

    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &protected)?;
    restrict_permissions(&tmp)?;
    std::fs::rename(&tmp, path)?;

    Ok(())
}

/// Читает зашифрованную структуру.
///
/// Непрочитавшийся файл — не ошибка уровня приложения: он мог остаться от
/// другой машины или повредиться. Возвращаем `None`, чтобы вызывающий код
/// просто перечитал подписку заново.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let raw = std::fs::read(path).ok()?;

    let plain = match platform::unprotect(&raw) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "не удалось расшифровать файл");
            return None;
        }
    };

    match serde_json::from_slice(&plain) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "не удалось разобрать файл");
            None
        }
    }
}

/// Удаляет сохранённый ключ.
pub fn clear(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_permissions(_path: &Path) -> Result<()> {
    // На Windows права наследуются от каталога ProgramData\Sont, который
    // установщик создаёт с ACL «только SYSTEM и администраторы». Плюс сам
    // файл зашифрован DPAPI, так что доступ к нему без прав на машину
    // ничего не даёт.
    Ok(())
}

#[cfg(windows)]
mod platform {
    use anyhow::{bail, Result};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    /// Дополнительная энтропия, привязывающая шифротекст к нашему приложению.
    ///
    /// Без неё расшифровать файл сможет любой процесс на той же машине,
    /// работающий под тем же контекстом, просто передав байты в DPAPI.
    const ENTROPY: &[u8] = b"sont-subscription-key-v1";

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Забирает данные из выходного блоба и освобождает выделенную DPAPI память.
    ///
    /// # Safety
    /// `out` должен быть результатом успешного вызова DPAPI.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let owned = slice.to_vec();
        LocalFree(out.pbData as *mut std::ffi::c_void);
        owned
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let input = blob(plain);
        let entropy = blob(ENTROPY);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: входные блобы ссылаются на живые буферы `plain` и ENTROPY,
        // которые переживают вызов; выходной блоб освобождается в `take`.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok == 0 {
            bail!(std::io::Error::last_os_error());
        }

        // SAFETY: вызов завершился успешно, значит output заполнен DPAPI.
        Ok(unsafe { take(output) })
    }

    pub fn unprotect(protected: &[u8]) -> Result<Vec<u8>> {
        let input = blob(protected);
        let entropy = blob(ENTROPY);
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: см. protect.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok == 0 {
            bail!(std::io::Error::last_os_error());
        }

        // SAFETY: вызов завершился успешно.
        Ok(unsafe { take(output) })
    }
}

#[cfg(not(windows))]
mod platform {
    use anyhow::Result;

    /// На macOS ключ должен уходить в системную связку ключей, на Linux —
    /// в файл, запечатанный ключом от machine-id. Пока ни того, ни другого
    /// нет, и хранение сводится к правам `0600` на файл.
    ///
    /// Это заметно слабее DPAPI, и молчать об этом нельзя: предупреждение
    /// пишется в журнал при каждом сохранении.
    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        tracing::warn!(
            "ключ подписки сохраняется без шифрования (доступен только root); \
             шифрование для этой платформы ещё не реализовано"
        );
        Ok(plain.to_vec())
    }

    pub fn unprotect(protected: &[u8]) -> Result<Vec<u8>> {
        Ok(protected.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Список подписок в том виде, в каком его пишет демон.
    fn subscriptions(url: &str) -> Vec<Secret> {
        vec![Secret::new(url)]
    }

    #[test]
    fn store_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscriptions.bin");
        let stored = subscriptions("https://panel.example/sub/VERY-SECRET-TOKEN");

        store_json(&path, &stored).unwrap();
        let loaded: Vec<Secret> = load_json(&path).expect("подписки должны прочитаться");
        assert_eq!(loaded[0].expose(), stored[0].expose());
    }

    #[test]
    fn missing_file_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.bin");
        assert!(load_json::<Vec<Secret>>(&absent).is_none());
        // Прежняя, одноподписочная раскладка читается тем же способом.
        assert!(load(&absent).unwrap().is_none());
    }

    #[test]
    fn clear_removes_the_file_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscriptions.bin");

        store_json(&path, &subscriptions("https://example/sub")).unwrap();
        clear(&path).unwrap();
        assert!(load_json::<Vec<Secret>>(&path).is_none());
        // Повторное удаление не должно быть ошибкой.
        clear(&path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn stored_key_is_not_readable_as_plain_text() {
        // Главное свойство: содержимое файла не выдаёт ключ тому, кто просто
        // откроет его текстовым редактором.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscriptions.bin");
        let token = "VERY-SECRET-TOKEN-12345";

        store_json(
            &path,
            &subscriptions(&format!("https://panel.example/sub/{token}")),
        )
        .unwrap();

        let raw = std::fs::read(&path).unwrap();
        let as_text = String::from_utf8_lossy(&raw);
        assert!(!as_text.contains(token), "ключ виден в файле открытым текстом");
        assert!(!as_text.contains("panel.example"), "URL виден в файле");
    }

    #[cfg(windows)]
    #[test]
    fn tampered_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscriptions.bin");
        store_json(&path, &subscriptions("https://example/sub")).unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();

        assert!(
            load_json::<Vec<Secret>>(&path).is_none(),
            "испорченный шифротекст должен отвергаться"
        );
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscriptions.bin");
        store_json(&path, &subscriptions("https://example/sub")).unwrap();
        assert!(!path.with_extension("tmp").exists());
    }
}

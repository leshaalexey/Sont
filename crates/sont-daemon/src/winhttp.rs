//! Прокси по умолчанию для WinHTTP.
//!
//! # Зачем отдельно от `sysproxy`
//!
//! Это третье место, где Windows хранит настройки прокси, и читает его третье
//! семейство программ.
//!
//! Ветка `Internet Settings` принадлежит пользователю, её читают WinINET и
//! Chromium. Переменные окружения — соглашение мира Unix, их читают Node,
//! Python, Go, curl. А WinHTTP хранит свой адрес **на машину целиком**, и им
//! пользуются службы и всё, что работает не в пользовательском сеансе:
//! Центр обновления, часть установщиков, служебные компоненты приложений.
//! Ни настроек пользователя, ни его переменных они не видят вовсе.
//!
//! Отсюда и разделение обязанностей. Пользовательские настройки применяет
//! агент в сеансе: демон работает от `LocalSystem` и записал бы их в профиль
//! служебной учётной записи. А машинную настройку, наоборот, может задать
//! только демон: она лежит в `HKLM`, и прав на неё у агента нет.
//!
//! Тот же адрес `netsh winhttp set proxy` показывает в выводе `netsh winhttp
//! show proxy` — если что-то пойдёт не так, посмотреть можно оттуда.
//!
//! # Чего это не даёт
//!
//! Приложение, которое не спрашивает ни одну из трёх настроек, всё равно
//! пойдёт напрямую. Это предел режима прокси, а не недоработка: заставить
//! чужую программу ходить через прокси против её воли можно только фильтром
//! на уровне сети, то есть режимом туннеля.

/// Прописывает машинный прокси.
pub fn apply(http_endpoint: &str) -> std::io::Result<()> {
    platform::apply(http_endpoint)
}

/// Убирает машинный прокси.
///
/// Вызывать обязательно при отключении: оставленный адрес, за которым больше
/// никого нет, ломает обновления системы — и связать это с VPN, выключенным
/// накануне, пользователь не сможет.
pub fn clear() -> std::io::Result<()> {
    platform::clear()
}

/// Что прописано в машинной настройке сейчас, если это наш адрес.
///
/// Нужно при старте демона. Прошлый его запуск мог закончиться падением или
/// жёсткой остановкой службы прямо в режиме прокси — тогда адрес остался
/// висеть, а новый запуск про это ничего не знает и, считая, что ничего не
/// применял, оставил бы его навсегда.
///
/// Чужой адрес не возвращаем: корпоративный прокси, заданный через `netsh
/// winhttp set proxy` до нас, нам не принадлежит, и снимать его мы не вправе.
pub fn ours_if_any() -> Option<String> {
    platform::current().filter(|value| points_at_loopback(value))
}

/// Наш ли это адрес.
///
/// Признак тот же, что и для переменных окружения: локальный адрес мог
/// поставить только локальный прокси, то есть мы.
fn points_at_loopback(value: &str) -> bool {
    let host = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .rsplit_once(':')
        .map_or(value, |(host, _)| host)
        .trim_matches(['[', ']']);

    matches!(host, "127.0.0.1" | "localhost" | "::1") || host.starts_with("127.")
}

#[cfg(all(windows, not(test)))]
mod platform {
    use std::io;

    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpGetDefaultProxyConfiguration, WinHttpSetDefaultProxyConfiguration,
        WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_PROXY_INFO,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Читает адрес из машинной настройки.
    pub fn current() -> Option<String> {
        let mut info = WINHTTP_PROXY_INFO::default();

        // SAFETY: структура на стеке, функция заполняет её целиком.
        let ok = unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) };
        if ok == 0 || info.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY {
            return None;
        }
        if info.lpszProxy.is_null() {
            return None;
        }

        // SAFETY: указатель непустой и, по документации, ведёт на строку,
        // завершённую нулём; выделила её сама WinHTTP.
        let value = unsafe {
            let mut len = 0usize;
            while *info.lpszProxy.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(info.lpszProxy, len))
        };

        // Освобождать выданные строки должен вызывающий. Пропустив это, демон
        // подтекал бы на каждом запуске — немного, но без всякой причины.
        free(info.lpszProxy);
        free(info.lpszProxyBypass);

        Some(value)
    }

    fn free(ptr: *mut u16) {
        use windows_sys::Win32::Foundation::LocalFree;

        if !ptr.is_null() {
            // SAFETY: строку выделила WinHTTP через LocalAlloc — именно этим
            // её и полагается освобождать.
            unsafe { LocalFree(ptr.cast()) };
        }
    }

    pub fn apply(http_endpoint: &str) -> io::Result<()> {
        // WinHTTP понимает и `http=…;https=…`, но здесь достаточно одного
        // адреса на все схемы: proxy-строка без префикса означает «этот прокси
        // для всего», а собственного HTTPS-входа у нас всё равно нет.
        let mut proxy = wide(http_endpoint);
        let mut bypass = wide(crate::sysproxy::BYPASS);

        let mut info = WINHTTP_PROXY_INFO {
            dwAccessType: WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            lpszProxy: proxy.as_mut_ptr(),
            lpszProxyBypass: bypass.as_mut_ptr(),
        };

        // SAFETY: обе строки завершены нулём и живут до конца вызова; функция
        // их только читает.
        let ok = unsafe { WinHttpSetDefaultProxyConfiguration(&mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn clear() -> io::Result<()> {
        let mut info = WINHTTP_PROXY_INFO {
            dwAccessType: WINHTTP_ACCESS_TYPE_NO_PROXY,
            lpszProxy: std::ptr::null_mut(),
            lpszProxyBypass: std::ptr::null_mut(),
        };

        // SAFETY: при `NO_PROXY` строки не читаются, нулевые указатели здесь
        // и предписаны документацией.
        let ok = unsafe { WinHttpSetDefaultProxyConfiguration(&mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Пустышка для остальных систем и для тестов.
///
/// Аналога машинной настройки WinHTTP вне Windows нет: там роль общесистемного
/// объявления играют те же переменные окружения.
///
/// Под тестами она пустая **намеренно**. Настройка общесистемная, и `cargo
/// test` не имеет права трогать прокси у того, кто его запустил: на машине с
/// правами администратора это сняло бы работающий корпоративный прокси прямо
/// посреди прогона. Решение о том, что объявлять, при этом проверяется — оно
/// в [`crate::supervisor`] и от этого модуля не зависит.
#[cfg(any(not(windows), test))]
mod platform {
    use std::io;

    pub fn apply(_http_endpoint: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn clear() -> io::Result<()> {
        Ok(())
    }

    pub fn current() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_address_is_recognised() {
        assert!(points_at_loopback("127.0.0.1:18966"));
        assert!(points_at_loopback("http://127.0.0.1:18966"));
        assert!(points_at_loopback("localhost:18966"));
    }

    #[test]
    fn a_foreign_proxy_is_left_alone() {
        // Корпоративный прокси, заданный через `netsh winhttp set proxy` до
        // нас, нам не принадлежит: сняв его, мы отобрали бы у пользователя
        // сеть способом, который он никак не свяжет с VPN.
        assert!(!points_at_loopback("proxy.corp.example:3128"));
        assert!(!points_at_loopback("http://10.0.0.5:8080"));
    }
}

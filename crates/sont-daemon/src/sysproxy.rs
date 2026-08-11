//! Прописывание прокси в настройки системы.
//!
//! # Почему это не в демоне
//!
//! Настройки прокси в Windows принадлежат **пользователю**, а не машине: они
//! живут в `HKCU` и читаются WinINET в контексте текущего сеанса. Демон же
//! работает от `LocalSystem`, и запись из него попала бы в профиль служебной
//! учётной записи — там её никто никогда не прочитает.
//!
//! Поэтому применяет настройки то, что работает в сеансе пользователя: сейчас
//! CLI, в дальнейшем tray-приложение. Демон только сообщает адреса.
//!
//! # Что остаётся за пределами прокси
//!
//! Приложение, не читающее эти настройки, пойдёт напрямую — молча. Отдельно
//! мимо идёт QUIC: системные настройки прокси на него не распространяются, а
//! браузеры используют его постоянно. Это ограничение режима, а не дефект
//! реализации, и пользователю о нём говорится прямо.

/// Адреса локальных прокси, поднятых ядром.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub http: String,
    pub socks: String,
}

/// Список адресов, которые должны идти напрямую, минуя прокси.
///
/// Локальные и частные сети через прокси гонять незачем: это ломает доступ к
/// принтерам, NAS и веб-интерфейсу роутера, а пользы не приносит.
const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;\
172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;\
172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;169.254.*;<local>";

/// Строка настроек прокси в формате WinINET.
///
/// HTTP и HTTPS направляются на HTTP-вход ядра, а `socks=` добавляется для
/// приложений, которые умеют SOCKS и предпочитают его.
fn proxy_server_value(endpoints: &Endpoints) -> String {
    format!(
        "http={http};https={http};socks={socks}",
        http = endpoints.http,
        socks = endpoints.socks
    )
}

#[cfg(windows)]
mod platform {
    use std::io;

    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: дескриптор получен от RegCreateKeyExW и ещё не закрыт.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open_settings() -> io::Result<Key> {
        let path = wide(SETTINGS_KEY);
        let mut handle: HKEY = std::ptr::null_mut();

        // SAFETY: путь завершён нулём, выходной параметр указывает на стек.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut handle,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Key(handle))
    }

    fn set_string(key: &Key, name: &str, value: &str) -> io::Result<()> {
        let name = wide(name);
        let data = wide(value);
        let bytes = std::mem::size_of_val(data.as_slice()) as u32;

        // SAFETY: буфер живёт до конца вызова, длина посчитана от него же.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                bytes,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn set_dword(key: &Key, name: &str, value: u32) -> io::Result<()> {
        let name = wide(name);

        // SAFETY: значение лежит на стеке и живёт до конца вызова.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_DWORD,
                (&value as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    /// Сообщает системе, что настройки изменились.
    ///
    /// Без этого уже запущенные приложения продолжают работать по старым
    /// настройкам до перезапуска, и пользователю кажется, что VPN не включился.
    fn notify() {
        // SAFETY: оба вызова без буферов, документированы как способ
        // уведомить WinINET об изменении настроек.
        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
    }

    pub fn apply(endpoints: &super::Endpoints) -> io::Result<()> {
        let key = open_settings()?;
        set_string(&key, "ProxyServer", &super::proxy_server_value(endpoints))?;
        set_string(&key, "ProxyOverride", super::BYPASS)?;
        set_dword(&key, "ProxyEnable", 1)?;
        notify();
        Ok(())
    }

    /// Что сейчас прописано в настройках системы.
    pub fn current() -> Option<(bool, String)> {
        use windows_sys::Win32::System::Registry::{RegOpenKeyExW, KEY_QUERY_VALUE};

        let path = wide(SETTINGS_KEY);
        let mut handle: HKEY = std::ptr::null_mut();

        // SAFETY: путь завершён нулём, выход указывает на стек.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut handle,
            )
        };
        if status != 0 {
            return None;
        }
        let key = Key(handle);

        let enabled = read_dword(&key, "ProxyEnable").unwrap_or(0) != 0;
        let server = read_string(&key, "ProxyServer").unwrap_or_default();
        Some((enabled, server))
    }

    fn read_dword(key: &Key, name: &str) -> Option<u32> {
        use windows_sys::Win32::System::Registry::RegQueryValueExW;

        let name = wide(name);
        let mut value: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as u32;

        // SAFETY: буфер и его длина согласованы.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut len,
            )
        };
        (status == 0).then_some(value)
    }

    fn read_string(key: &Key, name: &str) -> Option<String> {
        use windows_sys::Win32::System::Registry::RegQueryValueExW;

        let name = wide(name);
        let mut len = 0u32;

        // SAFETY: первый вызов только узнаёт размер.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if status != 0 || len == 0 {
            return None;
        }

        let mut buffer = vec![0u16; (len as usize).div_ceil(2)];
        // SAFETY: буфер выделен по размеру, полученному предыдущим вызовом.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if status != 0 {
            return None;
        }

        while matches!(buffer.last(), Some(0)) {
            buffer.pop();
        }
        String::from_utf16(&buffer).ok()
    }

    pub fn clear() -> io::Result<()> {
        let key = open_settings()?;

        // Выключаем прокси, но саму строку адреса удаляем тоже: оставленный
        // адрес неработающего прокси — это грабли, на которые пользователь
        // наступит, включив прокси вручную через месяц.
        set_dword(&key, "ProxyEnable", 0)?;

        let name = wide("ProxyServer");
        // SAFETY: имя завершено нулём; отсутствие значения не считаем ошибкой.
        unsafe { RegDeleteValueW(key.0, name.as_ptr()) };

        notify();
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use std::io;

    /// На macOS настройки прокси задаются через `networksetup`, на Linux —
    /// зависят от окружения рабочего стола и единого места не имеют.
    pub fn apply(_endpoints: &super::Endpoints) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "автоматическая настройка прокси на этой платформе не реализована",
        ))
    }

    pub fn clear() -> io::Result<()> {
        Ok(())
    }

    pub fn current() -> Option<(bool, String)> {
        None
    }
}

/// Прописывает прокси в настройки текущего пользователя.
pub fn apply(endpoints: &Endpoints) -> std::io::Result<()> {
    platform::apply(endpoints)
}

/// Убирает настройки прокси.
///
/// Вызывать обязательно при отключении: оставленный прокси, за которым больше
/// никого нет, выглядит для пользователя как полностью пропавший интернет.
pub fn clear() -> std::io::Result<()> {
    platform::clear()
}

/// Что сейчас прописано в настройках системы: включён ли прокси и его адрес.
///
/// Нужно диагностике: судить о том, куда пойдут приложения, следует по
/// настоящим настройкам, а не по тому, как их истолковала конкретная
/// библиотека. HTTP-клиенты разбирают формат `http=…;https=…;socks=…`
/// по-разному, и вывод «через систему трафик идёт мимо VPN», сделанный на
/// основании такого разбора, был бы ложным.
pub fn current() -> Option<(bool, String)> {
    platform::current()
}

/// Достаёт адрес для HTTP из строки настроек WinINET.
///
/// Строка бывает двух видов: единый адрес `127.0.0.1:8080` или список по
/// протоколам `http=…;https=…;socks=…`.
pub fn http_endpoint_of(value: &str) -> Option<String> {
    if !value.contains('=') {
        return (!value.trim().is_empty()).then(|| value.trim().to_owned());
    }

    value
        .split(';')
        .filter_map(|part| part.split_once('='))
        .find(|(scheme, _)| scheme.trim().eq_ignore_ascii_case("http"))
        .map(|(_, addr)| addr.trim().to_owned())
        .filter(|a| !a.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Endpoints {
        Endpoints {
            http: "127.0.0.1:18966".to_owned(),
            socks: "127.0.0.1:18965".to_owned(),
        }
    }

    #[test]
    fn proxy_value_covers_http_https_and_socks() {
        let value = proxy_server_value(&endpoints());
        assert!(value.contains("http=127.0.0.1:18966"));
        assert!(value.contains("https=127.0.0.1:18966"));
        assert!(value.contains("socks=127.0.0.1:18965"));
    }

    #[test]
    fn http_endpoint_is_extracted_from_per_scheme_value() {
        let value = "http=127.0.0.1:18966;https=127.0.0.1:18966;socks=127.0.0.1:18965";
        assert_eq!(
            http_endpoint_of(value),
            Some("127.0.0.1:18966".to_owned())
        );
    }

    #[test]
    fn single_address_form_is_supported() {
        // Настройки могут быть заданы и одним адресом на все протоколы.
        assert_eq!(
            http_endpoint_of("proxy.example:3128"),
            Some("proxy.example:3128".to_owned())
        );
    }

    #[test]
    fn value_without_http_scheme_yields_nothing() {
        assert_eq!(http_endpoint_of("socks=127.0.0.1:1080"), None);
        assert_eq!(http_endpoint_of(""), None);
    }

    #[test]
    fn scheme_matching_ignores_case() {
        assert_eq!(
            http_endpoint_of("HTTP=127.0.0.1:8080"),
            Some("127.0.0.1:8080".to_owned())
        );
    }

    #[test]
    fn local_and_private_networks_bypass_the_proxy() {
        // Иначе ломается доступ к роутеру, принтерам и сетевым хранилищам.
        for network in ["localhost", "127.*", "192.168.*", "10.*", "<local>"] {
            assert!(BYPASS.contains(network), "нет исключения для {network}");
        }
    }

    #[test]
    fn bypass_list_covers_the_whole_private_range() {
        // 172.16/12 — это 172.16..172.31, и пропуск любой из подсетей
        // означает отвалившийся доступ к части локальных устройств.
        for n in 16..=31 {
            assert!(BYPASS.contains(&format!("172.{n}.*")), "нет 172.{n}.*");
        }
    }

    #[cfg(windows)]
    #[test]
    fn clearing_when_nothing_was_set_is_not_an_error() {
        // Отключение может произойти без предшествующего включения — например,
        // после перезапуска клиента. Ошибкой это быть не должно.
        assert!(clear().is_ok());
    }
}

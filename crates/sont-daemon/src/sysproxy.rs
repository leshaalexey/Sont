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
//! # Три разных способа объявить прокси
//!
//! Настроек прокси в Windows не одна, а три, и читают их разные семейства
//! приложений. Этот модуль отвечает за две пользовательские; третья, машинная,
//! живёт в [`crate::winhttp`] — задать её может только демон.
//!
//! Ветка `Internet Settings` — родная для Windows. Её читают WinINET и
//! Chromium, то есть браузеры и всё на Electron.
//!
//! Переменные окружения `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` — соглашение
//! мира Unix, но именно его соблюдает всё, что принесено оттуда: Node, Python,
//! Go, curl, git. Настроек Windows эти программы не читают вовсе, и в режиме
//! прокси идут напрямую, ничего никому не сообщая.
//!
//! Пример того, как это выглядит у пользователя: Claude Desktop состоит из
//! оболочки на Electron и отдельного процесса Claude Code на Node. Первая
//! честно ходила через прокси, второй — мимо, и со стороны это выглядело как
//! «приложение работает в обход VPN».
//!
//! Поэтому объявляем все три.
//!
//! # Что остаётся за пределами прокси
//!
//! Приложение, не читающее ни одну из трёх настроек, пойдёт напрямую — молча.
//! Это предел режима, а не дефект реализации: заставить чужую программу ходить
//! через прокси против её воли можно только фильтром на уровне сети, то есть
//! режимом туннеля. Пользователю об этом говорится прямо.
//!
//! Про QUIC оговорка точнее, чем «идёт мимо». Настройки прокси действительно
//! не распространяются на UDP, но браузер, который эти настройки прочитал, сам
//! перестаёт использовать QUIC и переходит на TCP через прокси: замер показал
//! обращения вида `CONNECT узел:443` к тем самым адресам, куда браузер до
//! этого ходил по HTTP/3. Мимо QUIC идёт у приложений, которые настройку
//! проигнорировали, — но у них мимо идёт и всё остальное.
//!
//! Переменные окружения достаются процессу при запуске, поэтому уже открытые
//! приложения их не увидят: им нужен перезапуск. Об этом тоже говорится прямо —
//! молчаливое «почему-то не подействовало» хуже честного «перезапустите».

/// Адрес локального прокси, который прописывается в настройки системы.
///
/// Только HTTP. SOCKS-вход ядра существует и годится для ручной настройки, но
/// в системные настройки он не попадает — почему, объяснено у
/// [`proxy_server_value`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub http: String,
}

/// Список адресов, которые должны идти напрямую, минуя прокси.
///
/// Локальные и частные сети через прокси гонять незачем: это ломает доступ к
/// принтерам, NAS и веб-интерфейсу роутера, а пользы не приносит.
pub(crate) const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;\
172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;\
172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;169.254.*;<local>";

/// То же самое для переменных окружения.
///
/// Синтаксис другой: разделитель — запятая, шаблоны со звёздочкой не приняты,
/// частные сети записываются диапазонами. Кто их не разбирает, просто не
/// найдёт совпадения — молчаливой поломки из этого не выйдет.
const NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,\
192.168.0.0/16,169.254.0.0/16";

/// Переменные, которыми прокси объявляется миру Unix-соглашений.
///
/// Имена в Windows регистронезависимы, поэтому вариант в нижнем регистре
/// заводить не нужно: `process.env.http_proxy` в Node найдёт `HTTP_PROXY`.
const ENV_VARS: [&str; 2] = ["HTTP_PROXY", "HTTPS_PROXY"];
const ENV_NO_PROXY: &str = "NO_PROXY";

/// Значение переменной окружения для нашего прокси.
///
/// Со схемой: `http://` здесь обязателен, без него часть клиентов трактует
/// строку как имя узла и обращается не туда.
fn env_value(endpoints: &Endpoints) -> String {
    format!("http://{}", endpoints.http)
}

/// Наше ли это значение переменной.
///
/// Трогаем только то, что указывает на localhost. Иначе один `sontd connect`
/// снёс бы пользователю корпоративный прокси, прописанный до нас, и вернуть
/// его было бы уже неоткуда.
fn points_at_loopback(value: &str) -> bool {
    let host = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .rsplit_once(':')
        .map_or(value, |(host, _)| host)
        .trim_matches(['[', ']']);

    matches!(host, "127.0.0.1" | "localhost" | "::1") || host.starts_with("127.")
}

/// Строка настроек прокси в формате WinINET.
///
/// Только `http=` и `https=`, оба на HTTP-вход ядра.
///
/// # Почему здесь нет `socks=`
///
/// Раньше строка выглядела как `http=…;https=…;socks=…`, и это ломало ровно
/// тот класс приложений, ради которого режим и существует, — десктопные
/// веб-приложения на Chromium (Electron).
///
/// Chromium разбирает эту строку сам и для схем `ws://` и `wss://` **намеренно
/// предпочитает** запись `socks=` записи `https=` — так рекомендует RFC 6455
/// §4.1.3. При этом `socks=host:port` из настроек Windows он трактует как
/// **SOCKS4**, а у SOCKS4 нет поля для имени узла: клиент обязан резолвить имя
/// сам и отправить готовый IPv4.
///
/// Что из этого следует в режиме прокси, где TUN-адаптера нет:
///
/// * DNS-запрос уходит к резолверу провайдера мимо туннеля — и утечкой, и,
///   что хуже, поводом для блокировки: подменённый ответ определяет адрес,
///   к которому приложение затем честно подключится через туннель;
/// * узлы, доступные только по IPv6, недостижимы в принципе.
///
/// А WebSocket — это и есть транспорт десктопных веб-приложений. Снаружи
/// выглядит так, будто VPN включён, но приложение работает мимо него.
///
/// Проверено замером: с `socks=` Chromium шлёт на этот адрес
/// `04 01 01bb <ipv4> 00` (SOCKS4 CONNECT с уже разрешённым адресом), без него
/// — `CONNECT узел:443` на HTTP-вход, где имя разрешает уже ядро на той
/// стороне туннеля.
///
/// Сам SOCKS-вход никуда не делся: его адрес сообщают `sontd connect` и
/// `sontd status` для приложений, которые настраиваются вручную. Он просто не
/// объявляется всей системе.
fn proxy_server_value(endpoints: &Endpoints) -> String {
    format!("http={http};https={http}", http = endpoints.http)
}

#[cfg(windows)]
mod platform {
    use std::io;

    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    /// Ветка пользовательских переменных окружения.
    const ENV_KEY: &str = "Environment";

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

    fn open_key(path: &str, access: u32) -> io::Result<Key> {
        let path = wide(path);
        let mut handle: HKEY = std::ptr::null_mut();

        // SAFETY: путь завершён нулём, выходной параметр указывает на стек.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                access,
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

    fn open_settings() -> io::Result<Key> {
        open_key(SETTINGS_KEY, KEY_SET_VALUE)
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

    /// Сообщает системе, что изменились пользовательские переменные окружения.
    ///
    /// Без этого их не увидит даже вновь запущенное приложение: Explorer
    /// раздаёт дочерним процессам ту копию окружения, что прочитал сам, и
    /// перечитывает её только по этому сообщению.
    fn notify_environment() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };

        let topic = wide(ENV_KEY);
        // SAFETY: строка завершена нулём и живёт до конца вызова; таймаут не
        // даёт застрять на зависшем окне.
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                topic.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                1000,
                std::ptr::null_mut(),
            );
        }
    }

    /// Прописывает `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`.
    ///
    /// Чужие значения не трогаем: если переменная уже указывает не на
    /// localhost, её поставил не мы — скорее всего это корпоративный прокси,
    /// и затирать его нельзя.
    pub(super) fn apply_env(endpoints: &super::Endpoints) -> io::Result<()> {
        let key = open_key(ENV_KEY, KEY_QUERY_VALUE | KEY_SET_VALUE)?;
        let value = super::env_value(endpoints);
        let mut changed = false;

        for name in super::ENV_VARS {
            match read_string(&key, name) {
                Some(existing)
                    if !existing.trim().is_empty() && !super::points_at_loopback(&existing) =>
                {
                    tracing::warn!(
                        variable = name,
                        "переменная уже задана и указывает не на localhost — оставляю как есть"
                    );
                }
                _ => {
                    set_string(&key, name, &value)?;
                    changed = true;
                }
            }
        }

        if changed {
            set_string(&key, super::ENV_NO_PROXY, super::NO_PROXY)?;
            notify_environment();
        }
        Ok(())
    }

    /// Убирает переменные, но только свои.
    pub(super) fn clear_env() -> io::Result<()> {
        let key = open_key(ENV_KEY, KEY_QUERY_VALUE | KEY_SET_VALUE)?;
        let mut changed = false;

        for name in super::ENV_VARS {
            let Some(existing) = read_string(&key, name) else {
                continue;
            };
            if !super::points_at_loopback(&existing) {
                continue;
            }
            let wide_name = wide(name);
            // SAFETY: имя завершено нулём; отсутствие значения не ошибка.
            unsafe { RegDeleteValueW(key.0, wide_name.as_ptr()) };
            changed = true;
        }

        if changed {
            let wide_name = wide(super::ENV_NO_PROXY);
            // SAFETY: см. выше.
            unsafe { RegDeleteValueW(key.0, wide_name.as_ptr()) };
            notify_environment();
        }
        Ok(())
    }

    /// Значение пользовательской переменной окружения — как оно лежит в
    /// реестре, а не как его видит текущий процесс.
    ///
    /// Разница существенная: свою копию окружения процесс получил при запуске
    /// и об изменениях не узнаёт, поэтому проверять запись через `std::env`
    /// бессмысленно.
    #[cfg(test)]
    pub(super) fn env_var(name: &str) -> Option<String> {
        let key = open_key(ENV_KEY, KEY_QUERY_VALUE).ok()?;
        read_string(&key, name).filter(|v| !v.is_empty())
    }

    pub fn apply(endpoints: &super::Endpoints) -> io::Result<()> {
        let key = open_settings()?;
        set_string(&key, "ProxyServer", &super::proxy_server_value(endpoints))?;
        set_string(&key, "ProxyOverride", super::BYPASS)?;
        set_dword(&key, "ProxyEnable", 1)?;
        notify();

        // Переменные окружения — вторая половина дела, и неудача здесь не
        // повод считать, что прокси не включён: настройки Windows уже стоят, и
        // браузеры через них пойдут.
        if let Err(e) = apply_env(endpoints) {
            tracing::error!(error = %e, "не удалось задать переменные окружения прокси");
        }
        Ok(())
    }

    /// Что сейчас прописано в настройках системы.
    pub fn current() -> Option<(bool, String)> {
        use windows_sys::Win32::System::Registry::RegOpenKeyExW;

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
        // Переменные снимаем первыми и независимо от исхода остального:
        // оставленный `HTTPS_PROXY`, за которым больше никого нет, ломает
        // вообще всю работу в командной строке — и никак не связывается
        // пользователем с VPN, который он выключил час назад.
        let env = clear_env();

        let key = open_settings()?;

        // Выключаем прокси, но саму строку адреса удаляем тоже: оставленный
        // адрес неработающего прокси — это грабли, на которые пользователь
        // наступит, включив прокси вручную через месяц.
        set_dword(&key, "ProxyEnable", 0)?;

        let name = wide("ProxyServer");
        // SAFETY: имя завершено нулём; отсутствие значения не считаем ошибкой.
        unsafe { RegDeleteValueW(key.0, name.as_ptr()) };

        notify();
        env
    }
}

/// Настройки прокси на macOS.
///
/// Задаются `networksetup` и требуют прав администратора и имени сетевой
/// службы — ни того, ни другого у агента сеанса нет. Пока честная заглушка.
#[cfg(all(unix, target_os = "macos"))]
mod platform {
    use std::io;

    pub fn apply(_endpoints: &super::Endpoints) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "автоматическая настройка прокси на macOS не реализована",
        ))
    }

    pub fn clear() -> io::Result<()> {
        Ok(())
    }

    pub fn current() -> Option<(bool, String)> {
        None
    }
}

/// Настройки прокси на Linux.
///
/// # Почему тут два способа, а не один
///
/// Единого места для настроек прокси в Linux нет — и это не оплошность
/// разработчиков, а следствие устройства системы: рабочий стол здесь сменный.
/// Приходится объявлять прокси там, куда смотрят разные семейства программ.
///
/// **`gsettings`** — настройки GNOME. Их читает не только сам GNOME: Chrome,
/// Chromium и всё на Electron спрашивают именно их, независимо от того, какой
/// рабочий стол запущен. Это тот же слой, что `Internet Settings` на Windows,
/// и покрывает он то же самое — браузеры.
///
/// **`~/.config/environment.d`** — переменные окружения для служб сеанса
/// systemd. Их видят программы, запущенные после записи: `curl`, `git`, Node,
/// Python — весь мир соглашения `http_proxy`. Ровно та же роль, что у
/// переменных окружения на Windows, и ровно та же оговорка: уже запущенные
/// программы своё окружение не перечитывают.
///
/// # Чего здесь нет
///
/// KDE держит настройки в `kioslaverc` и требует уведомления по D-Bus, чтобы
/// их перечитали. Это отдельная реализация, и писать её вслепую, без KDE под
/// рукой, значит выдать непроверенный код за работающий. Пока — не сделано.
#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use std::io;
    use std::process::Command;

    /// Ветка настроек GNOME, откуда прокси читают браузеры.
    const SCHEMA: &str = "org.gnome.system.proxy";

    /// Файл переменных окружения для сеанса systemd.
    ///
    /// Отдельный файл, а не правка общего: так снятие настроек — это удаление
    /// одного файла, и чужие переменные при этом заведомо не пострадают.
    const ENV_FILE: &str = "sont-proxy.conf";

    pub fn apply(endpoints: &super::Endpoints) -> io::Result<()> {
        let (host, port) = super::split_endpoint(&endpoints.http)?;

        // Порядок важен: сначала адреса, потом режим. Включённый режим с
        // ещё не записанным адресом — это несколько миллисекунд, в которые
        // браузер ходит через прокси на нулевой порт.
        for scheme in ["http", "https"] {
            gsettings(&[
                "set",
                &format!("{SCHEMA}.{scheme}"),
                "host",
                host,
            ])?;
            gsettings(&[
                "set",
                &format!("{SCHEMA}.{scheme}"),
                "port",
                &port.to_string(),
            ])?;
        }

        gsettings(&["set", SCHEMA, "ignore-hosts", &super::gnome_ignore_list()])?;
        gsettings(&["set", SCHEMA, "mode", "manual"])?;

        // Переменные окружения — отдельно и не смертельно: если каталога
        // сеанса нет, браузеры всё равно уже настроены.
        if let Err(e) = write_env(&endpoints.http) {
            tracing::warn!(error = %e, "переменные окружения прокси не записаны");
        }
        Ok(())
    }

    pub fn clear() -> io::Result<()> {
        // Режим первым: он один определяет, пойдёт ли трафик через прокси, и
        // снять его важнее, чем прибрать адреса.
        let mode = gsettings(&["set", SCHEMA, "mode", "none"]);
        let env = remove_env();

        if let Err(e) = &env {
            tracing::warn!(error = %e, "не удалось убрать переменные окружения прокси");
        }
        mode
    }

    pub fn current() -> Option<(bool, String)> {
        let mode = read(&["get", SCHEMA, "mode"])?;
        let on = mode.trim().trim_matches('\'') == "manual";

        let host = read(&["get", &format!("{SCHEMA}.http"), "host"])?;
        let port = read(&["get", &format!("{SCHEMA}.http"), "port"])?;
        let host = host.trim().trim_matches('\'').to_owned();
        let port = port.trim();
        if host.is_empty() {
            return None;
        }

        // Формат тот же, что читает диагностика на Windows: `http=адрес:порт`.
        Some((on, format!("http={host}:{port}")))
    }

    fn gsettings(args: &[&str]) -> io::Result<()> {
        let status = Command::new("gsettings").args(args).status().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "не удалось запустить gsettings ({e}); \
                     задайте прокси в настройках рабочего стола вручную"
                ),
            )
        })?;

        if status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "gsettings отказал: {}",
            args.join(" ")
        )))
    }

    fn read(args: &[&str]) -> Option<String> {
        let out = Command::new("gsettings").args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Каталог переменных окружения сеанса.
    fn env_dir() -> Option<std::path::PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))?;
        Some(base.join("environment.d"))
    }

    fn write_env(endpoint: &str) -> io::Result<()> {
        let dir = env_dir().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "не найден домашний каталог")
        })?;
        std::fs::create_dir_all(&dir)?;

        let url = format!("http://{endpoint}");
        let no_proxy = super::NO_PROXY;
        // И в верхнем, и в нижнем регистре: часть программ читает только
        // одно написание, и какое именно — зависит от программы.
        let body = format!(
            "# Создано Sont. Файл удаляется при отключении.\n\
             HTTP_PROXY={url}\nHTTPS_PROXY={url}\nNO_PROXY={no_proxy}\n\
             http_proxy={url}\nhttps_proxy={url}\nno_proxy={no_proxy}\n"
        );
        std::fs::write(dir.join(ENV_FILE), body)
    }

    fn remove_env() -> io::Result<()> {
        let Some(dir) = env_dir() else {
            return Ok(());
        };
        match std::fs::remove_file(dir.join(ENV_FILE)) {
            Ok(()) => Ok(()),
            // Файла нет — значит и убирать нечего.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Делит `адрес:порт`.
///
/// Живёт снаружи платформенного модуля, чтобы проверяться тестами на любой
/// системе: ошибка тут — это прокси на нулевом порту, то есть молча пропавший
/// интернет, а такое нельзя проверять только на той машине, где собирают.
///
/// В сборке под Windows вызывается только из тестов — оттого и разрешение.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn split_endpoint(endpoint: &str) -> std::io::Result<(&str, u16)> {
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("адрес прокси без порта: {endpoint}"),
        )
    })?;
    let port: u16 = port.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("порт прокси не число: {port}"),
        )
    })?;
    if host.is_empty() || port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("пустой адрес прокси: {endpoint}"),
        ));
    }
    Ok((host, port))
}

/// Список исключений в том виде, который понимает GNOME.
///
/// Набор тот же, что и для переменных окружения, а синтаксис свой: массив
/// строк в одинарных кавычках. Ошибка формата тут не заметна на глаз —
/// `gsettings` примет строку и просто не станет никого исключать.
///
/// В сборке под Windows вызывается только из тестов — оттого и разрешение.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn gnome_ignore_list() -> String {
    let list = NO_PROXY
        .split(',')
        .map(|entry| format!("'{}'", entry.trim()))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{list}]")
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
        }
    }

    #[test]
    fn proxy_value_covers_http_and_https() {
        let value = proxy_server_value(&endpoints());
        assert!(value.contains("http=127.0.0.1:18966"));
        assert!(value.contains("https=127.0.0.1:18966"));
    }

    #[test]
    fn proxy_value_never_announces_socks() {
        // Chromium предпочитает запись `socks=` для ws/wss и говорит с ней по
        // SOCKS4, резолвя имя узла локально. Для десктопных веб-приложений это
        // означает DNS мимо туннеля и подчинение блокировкам провайдера при
        // формально поднятом VPN. Подробности — у `proxy_server_value`.
        let value = proxy_server_value(&endpoints());
        assert!(
            !value.contains("socks"),
            "socks= в системных настройках уводит WebSocket Chromium мимо туннеля: {value}"
        );
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
    fn env_value_carries_the_scheme() {
        // Без `http://` часть клиентов принимает строку за имя узла.
        assert_eq!(env_value(&endpoints()), "http://127.0.0.1:18966");
    }

    #[test]
    fn our_own_values_are_recognised() {
        for value in [
            "http://127.0.0.1:18966",
            "127.0.0.1:18966",
            "http://localhost:18966",
            "http://127.1.2.3:18966",
        ] {
            assert!(points_at_loopback(value), "не опознано своим: {value}");
        }
    }

    #[test]
    fn foreign_proxy_is_left_alone() {
        // Затереть корпоративный прокси — значит отобрать у пользователя сеть
        // способом, который он никак не свяжет с VPN.
        for value in [
            "http://proxy.corp.example:3128",
            "http://10.0.0.5:8080",
            "proxy.example:3128",
        ] {
            assert!(!points_at_loopback(value), "чужое принято за своё: {value}");
        }
    }

    #[test]
    fn no_proxy_keeps_local_traffic_local() {
        // Иначе через прокси уйдёт обращение к самому себе и к локальной сети.
        for entry in ["localhost", "127.0.0.1", "192.168.0.0/16"] {
            assert!(NO_PROXY.contains(entry), "нет исключения для {entry}");
        }
        assert!(
            !NO_PROXY.contains(';'),
            "здесь разделитель — запятая, точка с запятой из формата WinINET"
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

    /// Замок для проверок, которые ходят в настоящий реестр.
    ///
    /// Реестр один на процесс, а тесты идут параллельно: без замка `clear()`
    /// одного теста стирает переменные, которые только что записал другой, и
    /// падение зависит от того, кто успел первым. Такой тест хуже
    /// отсутствующего — он подрывает доверие ко всему прогону.
    #[cfg(windows)]
    static REGISTRY: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(windows)]
    #[test]
    fn environment_variables_are_written_and_taken_back() {
        let _guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        // Проверка ходит в настоящий реестр: ломается здесь именно запись, а
        // подстановка строк проверена выше и без неё.
        //
        // Чужой прокси не трогаем — тогда и восстанавливать нечего. Если он на
        // машине есть, проверять тут нечего: этот случай отдельно проверен
        // в `foreign_proxy_is_left_alone`.
        let occupied = ENV_VARS
            .iter()
            .filter_map(|name| platform::env_var(name))
            .any(|value| !points_at_loopback(&value));
        if occupied {
            return;
        }

        platform::apply_env(&endpoints()).expect("переменные должны записаться");
        for name in ENV_VARS {
            assert_eq!(
                platform::env_var(name).as_deref(),
                Some("http://127.0.0.1:18966"),
                "{name} не записана"
            );
        }
        assert_eq!(platform::env_var(ENV_NO_PROXY).as_deref(), Some(NO_PROXY));

        platform::clear_env().expect("переменные должны сняться");
        for name in ENV_VARS {
            assert_eq!(platform::env_var(name), None, "{name} осталась висеть");
        }
        assert_eq!(
            platform::env_var(ENV_NO_PROXY),
            None,
            "NO_PROXY без прокси бессмысленна и должна уйти вместе с ним"
        );
    }

    #[cfg(windows)]
    #[test]
    fn clearing_when_nothing_was_set_is_not_an_error() {
        let _guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        // Отключение может произойти без предшествующего включения — например,
        // после перезапуска клиента. Ошибкой это быть не должно.
        assert!(clear().is_ok());
    }
}

#[cfg(test)]
mod unix_helpers_tests {
    use super::{gnome_ignore_list, split_endpoint};

    #[test]
    fn an_endpoint_splits_into_host_and_port() {
        let (host, port) = split_endpoint("127.0.0.1:18966").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 18966);
    }

    #[test]
    fn a_broken_endpoint_is_refused_rather_than_guessed() {
        // Прокси на нулевом порту — это молча пропавший интернет: браузер
        // честно пойдёт по указанному адресу, где никого нет. Лучше отказ.
        assert!(split_endpoint("127.0.0.1").is_err(), "без порта");
        assert!(split_endpoint("127.0.0.1:").is_err(), "порт пустой");
        assert!(split_endpoint("127.0.0.1:0").is_err(), "нулевой порт");
        assert!(split_endpoint(":18966").is_err(), "адрес пустой");
        assert!(split_endpoint("127.0.0.1:не число").is_err());
    }

    #[test]
    fn the_ignore_list_is_a_gnome_array() {
        let list = gnome_ignore_list();
        assert!(list.starts_with('[') && list.ends_with(']'), "{list}");
        assert!(list.contains("'localhost'"), "{list}");
        assert!(list.contains("'192.168.0.0/16'"), "{list}");
        // Каждый элемент — строка в кавычках без пробелов внутри: лишний
        // пробел gsettings проглотит молча, а исключать перестанет.
        for entry in list.trim_matches(['[', ']']).split(", ") {
            assert!(entry.starts_with('\x27') && entry.ends_with('\x27'), "{entry}");
            assert!(!entry.trim_matches('\x27').contains(' '), "{entry}");
        }
    }
}

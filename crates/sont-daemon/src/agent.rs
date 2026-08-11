//! Спутник в сеансе пользователя.
//!
//! # Зачем он существует
//!
//! Настройки прокси в Windows принадлежат пользователю: они живут в его ветке
//! реестра, и об их изменении нужно уведомить именно его сеанс. Служба
//! работает от `LocalSystem` и сделать это не может — запись ушла бы в профиль
//! служебной учётной записи, где её никто не прочитает.
//!
//! Поэтому за настройки отвечает отдельный процесс в сеансе пользователя. Он
//! ничего не решает: следит за состоянием демона и приводит настройки системы
//! в соответствие. Права администратора ему не нужны.
//!
//! В дальнейшем эту роль возьмёт tray-приложение, а агент останется как способ
//! работать без графического интерфейса.

use std::time::Duration;

use anyhow::{Context, Result};
use sont_core::ConnectionMode;
use sont_ipc::protocol::{Event, Request, Response};
use sont_ipc::Client;

use crate::sysproxy;

const AGENT: &str = concat!("sontd-agent/", env!("CARGO_PKG_VERSION"));

/// Пауза перед повторной попыткой связаться с демоном.
///
/// Демон может перезапускаться (обновление, сбой), и агент обязан это
/// переживать, а не завершаться при первой неудаче.
const RECONNECT_DELAY: Duration = Duration::from_secs(3);

/// Что агент считает нужным состоянием системных настроек.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Desired {
    Proxy(sysproxy::Endpoints),
    None,
}

/// Работает до остановки, поддерживая настройки системы в соответствии с
/// состоянием демона.
pub async fn run() -> Result<()> {
    tracing::info!("агент запущен");

    // При выходе настройки обязаны быть сняты. Оставленный прокси, за которым
    // никого нет, для пользователя выглядит как полностью пропавший интернет,
    // причём без всякой связи с VPN.
    let result = tokio::select! {
        r = serve() => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("получен сигнал остановки");
            Ok(())
        }
    };

    apply(&Desired::None);
    tracing::info!("агент остановлен");
    result
}

async fn serve() -> Result<()> {
    let addr = sont_ipc::endpoint_name();
    let mut applied = Desired::None;

    loop {
        let connected = Client::connect(&addr, AGENT).await;

        let (client, mut events) = match connected {
            Ok(v) => v,
            Err(e) => {
                // Демона нет — значит и прокси быть не должно.
                if applied != Desired::None {
                    tracing::info!("демон недоступен, снимаю настройки прокси");
                    applied = Desired::None;
                    apply(&applied);
                }
                tracing::debug!(error = %e, "демон недоступен, повтор");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        tracing::info!("подключён к демону");
        if client.request(Request::SubscribeEvents).await.is_err() {
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }

        // Состояние на момент подключения: демон мог подняться раньше агента
        // и уже держать соединение.
        sync(&client, &mut applied).await;

        while let Some(event) = events.recv().await {
            match event {
                Event::StateChanged(_) => sync(&client, &mut applied).await,
                // Смена сервера меняет порты ядра, а с ними и адрес прокси.
                Event::SubscriptionUpdated(_) => sync(&client, &mut applied).await,
                _ => {}
            }
        }

        tracing::info!("соединение с демоном потеряно");
    }
}

/// Приводит настройки системы в соответствие с состоянием демона.
async fn sync(client: &Client, applied: &mut Desired) {
    let desired = match desired_state(client).await {
        Some(d) => d,
        // Демон не ответил: не трогаем настройки, иначе рискуем снять рабочий
        // прокси из-за одной неудачной проверки.
        None => return,
    };

    if desired == *applied {
        return;
    }

    apply(&desired);
    *applied = desired;
}

async fn desired_state(client: &Client) -> Option<Desired> {
    let Ok(Response::Settings(settings)) = client.request(Request::GetSettings).await else {
        return None;
    };
    if !matches!(settings.mode, ConnectionMode::Proxy) {
        // В режиме туннеля системный прокси не нужен: трафик идёт через
        // адаптер, а лишняя настройка только собьёт приложения с толку.
        return Some(Desired::None);
    }

    let Ok(Response::Status(status)) = client.request(Request::GetStatus).await else {
        return None;
    };

    Some(match status.proxy {
        Some(p) => Desired::Proxy(sysproxy::Endpoints {
            http: p.http,
            socks: p.socks,
        }),
        None => Desired::None,
    })
}

fn apply(desired: &Desired) {
    let outcome = match desired {
        Desired::Proxy(endpoints) => {
            tracing::info!(http = %endpoints.http, "включаю системный прокси");
            sysproxy::apply(endpoints)
        }
        Desired::None => {
            tracing::info!("снимаю системный прокси");
            sysproxy::clear()
        }
    };

    if let Err(e) = outcome {
        tracing::error!(error = %e, "не удалось изменить настройки прокси");
    }
}

// ───────────────────────────── автозапуск ─────────────────────────────

/// Имя записи автозапуска.
const RUN_VALUE: &str = "SontAgent";

#[cfg(windows)]
mod autostart {
    use std::io;

    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: дескриптор получен от RegCreateKeyExW.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(access: u32) -> io::Result<Key> {
        let path = wide(RUN_KEY);
        let mut handle: HKEY = std::ptr::null_mut();

        // SAFETY: путь завершён нулём, выход указывает на стек.
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

    pub fn enable(command: &str) -> io::Result<()> {
        let key = open(KEY_SET_VALUE)?;
        let name = wide(super::RUN_VALUE);
        let data = wide(command);
        let bytes = std::mem::size_of_val(data.as_slice()) as u32;

        // SAFETY: буфер живёт до конца вызова, длина посчитана от него же.
        let status = unsafe {
            RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, data.as_ptr().cast(), bytes)
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub fn disable() -> io::Result<()> {
        let key = open(KEY_SET_VALUE)?;
        let name = wide(super::RUN_VALUE);
        // SAFETY: имя завершено нулём; отсутствие значения ошибкой не считаем.
        unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        Ok(())
    }

    pub fn is_enabled() -> bool {
        let Ok(key) = open(KEY_QUERY_VALUE) else {
            return false;
        };
        let name = wide(super::RUN_VALUE);
        let mut len = 0u32;

        // SAFETY: запрашиваем только размер значения, буфер не передаём.
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
        status == 0
    }
}

#[cfg(not(windows))]
mod autostart {
    use std::io;

    pub fn enable(_command: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "автозапуск на этой платформе не реализован",
        ))
    }
    pub fn disable() -> io::Result<()> {
        Ok(())
    }
    pub fn is_enabled() -> bool {
        false
    }
}

/// Включает автозапуск агента при входе пользователя в систему.
pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("не удалось определить путь к собственному файлу")?;
    let command = format!("\"{}\" agent run", exe.display());
    autostart::enable(&command).context("не удалось прописать автозапуск")?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    autostart::disable().context("не удалось убрать автозапуск")?;
    // Настройки снимаем сразу: агента больше не будет, и снять их станет некому.
    let _ = sysproxy::clear();
    Ok(())
}

pub fn is_installed() -> bool {
    autostart::is_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> sysproxy::Endpoints {
        sysproxy::Endpoints {
            http: "127.0.0.1:18966".to_owned(),
            socks: "127.0.0.1:18965".to_owned(),
        }
    }

    #[test]
    fn same_state_is_not_reapplied() {
        // Настройки прокси уведомляют все приложения сеанса; переписывать их
        // на каждое событие значит дёргать систему без причины.
        let a = Desired::Proxy(endpoints());
        let b = Desired::Proxy(endpoints());
        assert_eq!(a, b);
    }

    #[test]
    fn changed_endpoints_are_a_different_state() {
        let a = Desired::Proxy(endpoints());
        let b = Desired::Proxy(sysproxy::Endpoints {
            http: "127.0.0.1:19000".to_owned(),
            socks: "127.0.0.1:18965".to_owned(),
        });
        assert_ne!(a, b);
    }

    #[test]
    fn disconnected_state_differs_from_proxy() {
        assert_ne!(Desired::Proxy(endpoints()), Desired::None);
    }

    #[test]
    fn autostart_command_quotes_the_path() {
        // В пути к файлу бывают пробелы; без кавычек Windows запустит не то.
        let exe = std::path::PathBuf::from(r"C:\Program Files\Sont\sontd.exe");
        let command = format!("\"{}\" agent run", exe.display());
        assert!(command.starts_with('"'));
        assert!(command.ends_with("\" agent run"));
    }
}

//! Сброс установленных соединений при включении прокси.
//!
//! # Зачем это нужно
//!
//! Настройка прокси действует только на **новые** соединения. Уже открытые
//! сокеты никто никуда не переносит, а HTTP/2 и WebSocket живут часами. Отсюда
//! наблюдение, ради которого модуль и появился: пользователь включает режим
//! прокси, `netsh` и реестр показывают правильный адрес, замер подтверждает,
//! что путь через ядро исправен, — а приложение продолжает ходить напрямую,
//! потому что оно вообще не открывало новых соединений.
//!
//! В режиме туннеля этого не происходит: подъём адаптера меняет маршрут по
//! умолчанию, и прежние соединения обрываются сами. Прокси-режим таким рычагом
//! не обладает, и разница между режимами получается не в охвате, а в том,
//! замечает ли пользователь охват вообще.
//!
//! Поэтому обрываем их сами — один раз, в момент, когда адрес прокси уже
//! объявлен. Приложение увидит обрыв, переподключится и на этот раз прочитает
//! настройку. Ровно то же самое делает переключение в режим туннеля, только
//! там это побочный эффект смены маршрута, а здесь — явное действие.
//!
//! # Чего мы не трогаем
//!
//! Собственные соединения — ядра и демона: оборвать связь ядра с сервером
//! значило бы обрушить тот самый туннель, ради которого всё затевалось.
//!
//! Локальные и частные адреса: они и так идут мимо прокси, обрывать их не за
//! чем, а среди них бывают соединения с базами и службами, которым внезапный
//! разрыв обходится дороже.
//!
//! Только IPv4 и только TCP: `SetTcpEntry` умеет ровно это. Соединения по
//! IPv6 останутся жить, и это честное ограничение приёма, а не недосмотр.

use std::net::Ipv4Addr;

/// Обрывает установленные соединения, чтобы приложения переподключились.
///
/// Возвращает, сколько удалось оборвать. Права нужны административные; без них
/// система откажет, и это не повод считать подключение неудавшимся — просто
/// приложения переедут на прокси не сразу, а когда откроют новое соединение
/// сами.
pub fn reset_established(protect: &Protected) -> usize {
    platform::reset_established(protect)
}

/// Что обрывать нельзя.
#[derive(Debug, Default, Clone)]
pub struct Protected {
    /// Процессы, чьи соединения трогать нельзя, — прежде всего ядро.
    pub pids: Vec<u32>,
    /// Адреса, до которых соединения трогать нельзя, — прежде всего сервер.
    pub addresses: Vec<Ipv4Addr>,
}

impl Protected {
    fn covers(&self, pid: u32, remote: Ipv4Addr) -> bool {
        self.pids.contains(&pid) || self.addresses.contains(&remote)
    }
}

/// Стоит ли вообще трогать это соединение.
///
/// Вынесено из платформенного кода, чтобы правило проверялось обычным тестом:
/// ошибиться здесь значит либо оборвать связь ядра с сервером, либо не
/// оборвать ничего.
fn worth_resetting(protect: &Protected, pid: u32, remote: Ipv4Addr) -> bool {
    if protect.covers(pid, remote) {
        return false;
    }
    // Локальное и частное идёт мимо прокси и без нас.
    !(remote.is_loopback()
        || remote.is_private()
        || remote.is_link_local()
        || remote.is_multicast()
        || remote.is_broadcast()
        || remote.is_unspecified())
}

#[cfg(all(windows, not(test)))]
mod platform {
    use std::net::Ipv4Addr;

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    pub fn reset_established(protect: &super::Protected) -> usize {
        let Some(rows) = table() else {
            return 0;
        };

        let mut reset = 0;
        for row in rows {
            if row.dwState != MIB_TCP_STATE_ESTAB as u32 {
                continue;
            }
            // Адреса в таблице лежат в сетевом порядке байт.
            let remote = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
            if !super::worth_resetting(protect, row.dwOwningPid, remote) {
                continue;
            }

            let mut entry = MIB_TCPROW_LH {
                Anonymous: unsafe { std::mem::zeroed() },
                dwLocalAddr: row.dwLocalAddr,
                dwLocalPort: row.dwLocalPort,
                dwRemoteAddr: row.dwRemoteAddr,
                dwRemotePort: row.dwRemotePort,
            };
            entry.Anonymous.dwState = MIB_TCP_STATE_DELETE_TCB as u32;

            // SAFETY: структура заполнена целиком и живёт до конца вызова.
            if unsafe { SetTcpEntry(&entry) } == 0 {
                reset += 1;
            }
            // Отказ — обычное дело: соединение могло закрыться само, а часть
            // системных нам не отдадут. Шуметь об этом в журнал незачем.
        }

        reset
    }

    /// Снимок таблицы TCP вместе с владельцами.
    fn table() -> Option<Vec<MIB_TCPROW_OWNER_PID>> {
        let mut size = 0u32;

        // Первый вызов только узнаёт размер.
        // SAFETY: буфер не передаём, функция обязана вернуть нужный размер.
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        // SAFETY: буфер выделен по размеру, полученному предыдущим вызовом.
        let status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status != 0 {
            return None;
        }

        // SAFETY: в начале буфера лежит счётчик, дальше — записи подряд.
        let header = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let count = header.dwNumEntries as usize;
        let first = std::ptr::addr_of!(header.table) as *const MIB_TCPROW_OWNER_PID;

        // SAFETY: длина взята из той же структуры, что и сами записи.
        Some(unsafe { std::slice::from_raw_parts(first, count) }.to_vec())
    }
}

#[cfg(any(not(windows), test))]
mod platform {
    /// Пустышка вне Windows и под тестами.
    ///
    /// Под тестами — намеренно: обрывать соединения на машине, где идёт
    /// `cargo test`, недопустимо. Правило отбора при этом проверяется, оно
    /// от системы не зависит.
    pub fn reset_established(_protect: &super::Protected) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protect() -> Protected {
        Protected {
            pids: vec![4242],
            addresses: vec![Ipv4Addr::new(132, 243, 203, 40)],
        }
    }

    #[test]
    fn ordinary_connections_are_reset() {
        assert!(worth_resetting(&protect(), 100, Ipv4Addr::new(160, 79, 104, 10)));
    }

    #[test]
    fn the_core_connection_to_the_server_is_spared() {
        // Оборвать её — обрушить туннель, ради которого всё и делается.
        assert!(!worth_resetting(&protect(), 4242, Ipv4Addr::new(160, 79, 104, 10)));
        assert!(!worth_resetting(&protect(), 100, Ipv4Addr::new(132, 243, 203, 40)));
    }

    #[test]
    fn local_and_private_traffic_is_spared() {
        // Оно идёт мимо прокси и без нас, а среди него бывают соединения,
        // которым внезапный разрыв обходится дороже, чем нам польза.
        for addr in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            assert!(!worth_resetting(&protect(), 100, addr), "не пощажён {addr}");
        }
    }
}

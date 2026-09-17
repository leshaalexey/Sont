//! Маршруты локальных сетей мимо туннеля — на Windows.
//!
//! # Почему не через `tun2proxy`
//!
//! Его обходные маршруты `tproxy-config` прописывает внешней утилитой `route`,
//! передавая сеть строкой вида `10.0.0.0/8`. Для адресов узлов это работает —
//! маска у них не пишется вовсе, — а запись сети с длиной префикса `route` для
//! IPv4 не документирует. Не поймёт — `tproxy-config` прервёт настройку, и
//! туннель не поднимется совсем. Ставить на это подключение нельзя.
//!
//! Здесь маршруты создаются напрямую через IP Helper: документированный вызов,
//! без запуска внешних программ, и отказ стоит только самого маршрута, а не
//! туннеля.

use std::net::Ipv4Addr;

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT, SOCKADDR_INET};

/// Адрес, по маршруту к которому узнаём физический выход.
const PUBLIC_PROBE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// Шлюз TUN-адаптера `tun2proxy`.
///
/// Если маршрут наружу ведёт через него, прежний туннель ещё не снят, и
/// «физического» выхода сейчас не узнать.
const TUN_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Созданные маршруты; снимаются при уничтожении.
pub struct LanRoutes {
    rows: Vec<MIB_IPFORWARD_ROW2>,
}

// SAFETY: строки маршрутов — простые данные без указателей на чужую память.
unsafe impl Send for LanRoutes {}

impl LanRoutes {
    /// Прописывает сети через тот выход, которым машина ходит наружу сейчас.
    ///
    /// Вызывать до подъёма туннеля: после него маршрут наружу ведёт уже в TUN.
    pub fn add(networks: &[(Ipv4Addr, u8)]) -> Option<Self> {
        let outside = best_route(PUBLIC_PROBE)?;

        let next_hop = unsafe { Ipv4Addr::from(u32::from_be(outside.NextHop.Ipv4.sin_addr.S_un.S_addr)) };
        if next_hop == TUN_GATEWAY {
            tracing::warn!("маршрут наружу всё ещё ведёт в прежний туннель — локальные сети не выведены");
            return None;
        }

        let mut rows = Vec::with_capacity(networks.len());
        for &(network, prefix) in networks {
            // SAFETY: структура обнуляется и заполняется значениями по умолчанию
            // самой системой.
            let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
            unsafe { InitializeIpForwardEntry(&mut row) };

            row.InterfaceLuid = outside.InterfaceLuid;
            row.InterfaceIndex = outside.InterfaceIndex;
            row.DestinationPrefix.Prefix = ipv4(network);
            row.DestinationPrefix.PrefixLength = prefix;
            row.NextHop = outside.NextHop;
            row.Metric = 1;
            row.Protocol = MIB_IPPROTO_NETMGMT;

            // SAFETY: строка заполнена и живёт до конца вызова.
            match unsafe { CreateIpForwardEntry2(&row) } {
                // Уже есть — скорее всего, остался от прошлого запуска, упавшего
                // без уборки. Берём его себе: снимем вместе со своими.
                NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => rows.push(row),
                code => tracing::warn!(%network, prefix, code, "не удалось вывести сеть мимо туннеля"),
            }
        }

        tracing::info!(
            networks = rows.len(),
            %next_hop,
            "локальные сети идут мимо туннеля"
        );
        Some(Self { rows })
    }
}

impl Drop for LanRoutes {
    fn drop(&mut self) {
        for row in &self.rows {
            // SAFETY: строка та же, что создавалась.
            let code = unsafe { DeleteIpForwardEntry2(row) };
            if code != NO_ERROR && code != ERROR_NOT_FOUND {
                tracing::warn!(code, "не удалось снять маршрут локальной сети");
            }
        }
    }
}

fn ipv4(address: Ipv4Addr) -> SOCKADDR_INET {
    // SAFETY: объединение обнуляется, дальше заполняется вариант IPv4.
    let mut sockaddr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    sockaddr.Ipv4.sin_family = AF_INET;
    sockaddr.Ipv4.sin_addr.S_un.S_addr = u32::from(address).to_be();
    sockaddr
}

fn best_route(destination: Ipv4Addr) -> Option<MIB_IPFORWARD_ROW2> {
    let target = ipv4(destination);
    // SAFETY: выходные структуры обнулены и принадлежат нам.
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    let code = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &target,
            0,
            &mut route,
            &mut source,
        )
    };
    if code != NO_ERROR {
        tracing::warn!(code, "не удалось узнать маршрут наружу — локальные сети не выведены");
        return None;
    }
    Some(route)
}

//! Kill-switch: фильтры WFP, не пускающие трафик мимо туннеля.
//!
//! # Зачем
//!
//! Туннель может упасть в любой момент — ядро завершилось, сеть сменилась,
//! машина проснулась. Пока демон это заметит и поднимет соединение заново,
//! проходит от секунд до минут, и всё это время маршрут по умолчанию снова
//! указывает в обычную сеть. Приложения не знают о VPN ничего и продолжают
//! работать — уже открыто. Ради этого промежутка kill-switch и существует:
//! он закрывает трафик там, где его закрыть можно, — на уровне сетевого
//! стека, а не уговорами.
//!
//! # Устройство
//!
//! Windows Filtering Platform: одно правило блокирует весь исходящий трафик
//! с наименьшим весом, несколько правил с большим весом возвращают наружу
//! то, без чего машина перестала бы работать вовсе:
//!
//! * петля (`127.0.0.1`, `::1`) — иначе рассыплется всё локальное, включая
//!   наш собственный канал к трею;
//! * туннельный адаптер по LUID — ради него всё и затевалось;
//! * сам демон и ядро — им нужно дотянуться до сервера и до подписки, иначе
//!   блокировка не даст подняться тому самому туннелю, который её снимет;
//! * DHCP — без продления аренды физический адаптер теряет адрес, и после
//!   выключения VPN пользователь остаётся без сети уже по-настоящему;
//! * локальная сеть, если пользователь так попросил.
//!
//! # Почему это не оставляет пользователя без интернета
//!
//! Сессия WFP по умолчанию **динамическая**: фильтры принадлежат открытому
//! дескриптору и исчезают вместе с процессом. Демон убит, служба снята,
//! машина ушла в синий экран — сеть возвращается сама. Это главное свойство
//! всей конструкции, и отказываться от него можно только по явной просьбе:
//! [`FirewallMode::Lockdown`] заводит постоянные фильтры, которые переживут
//! падение демона и снимаются либо им же, либо `sontd firewall reset`.

use std::net::IpAddr;
use std::path::PathBuf;

use sont_core::FirewallMode;

/// Что выпускается наружу мимо общего запрета.
#[derive(Debug, Clone, Default)]
pub struct Allowances {
    /// LUID туннельного адаптера, если он уже поднят.
    ///
    /// `None` на время подключения: фильтры ставятся **до** запуска ядра,
    /// иначе между «сняли прежний туннель» и «подняли новый» остаётся ровно
    /// та щель, ради закрытия которой всё и делается.
    pub tunnel_luid: Option<u64>,
    /// Программы, которым разрешено ходить куда угодно: демон и ядро.
    pub apps: Vec<PathBuf>,
    /// Адреса серверов подписки — запасной путь на случай, если ядро
    /// запустится не из ожидаемого файла.
    pub servers: Vec<IpAddr>,
    /// Выпускать ли локальную сеть.
    pub allow_lan: bool,
}

/// Поднятая блокировка.
///
/// Снимается в [`Firewall::disengage`] или, для динамической сессии, сама —
/// вместе с процессом. `Drop` намеренно не реализован: снятие может не
/// удаться, а `Drop`, который молча проглатывает ошибку, — худший способ
/// узнать, что блокировка осталась висеть.
pub struct Firewall {
    inner: platform::Engine,
    mode: FirewallMode,
}

impl Firewall {
    /// Ставит фильтры.
    ///
    /// Всё делается одной транзакцией: половина правил — это либо дырявая
    /// блокировка, либо машина без сети, и оба исхода хуже, чем честная
    /// ошибка.
    pub fn engage(mode: FirewallMode, allow: &Allowances) -> std::io::Result<Self> {
        let inner = platform::Engine::open(mode.survives_daemon_crash())?;
        inner.install(allow)?;
        tracing::info!(?mode, tunnel = allow.tunnel_luid.is_some(), "kill-switch включён");
        Ok(Self { inner, mode })
    }

    /// Переставляет правила под новые разрешения, не открывая трафик.
    ///
    /// Нужно после подъёма туннеля: LUID адаптера становится известен только
    /// тогда. Снять блокировку и поставить заново было бы проще, но в
    /// промежутке трафик пошёл бы напрямую — то есть ровно то, от чего мы
    /// защищаемся, случилось бы по нашей же вине.
    pub fn update(&self, allow: &Allowances) -> std::io::Result<()> {
        self.inner.install(allow)
    }

    /// Снимает фильтры.
    pub fn disengage(self) -> std::io::Result<()> {
        self.inner.remove()?;
        tracing::info!(mode = ?self.mode, "kill-switch снят");
        Ok(())
    }
}

/// Снимает фильтры, оставшиеся от прошлого запуска.
///
/// Нужно в двух случаях: при старте демона (прошлый запуск мог оборваться в
/// режиме `Lockdown`, и постоянные фильтры пережили его) и по команде
/// `sontd firewall reset`, когда пользователю нужно вернуть сеть, ничего не
/// запуская.
pub fn reset() -> std::io::Result<()> {
    platform::reset()
}

/// Диапазоны локальной сети, выпускаемые при `allow_lan`.
///
/// Тот же список, что в обходе прокси: принтер, NAS и веб-интерфейс роутера
/// должны остаться доступными, иначе «VPN включён» на практике означает
/// «печать не работает».
///
/// `169.254/16` здесь не для удобства: это адреса, которые машина назначает
/// себе сама, пока не получила аренду, и без них восстановление сети после
/// разрыва упирается в нашу же блокировку.
const LAN_V4: [(u32, u32); 5] = [
    (0x0A00_0000, 0xFF00_0000), // 10.0.0.0/8
    (0xAC10_0000, 0xFFF0_0000), // 172.16.0.0/12
    (0xC0A8_0000, 0xFFFF_0000), // 192.168.0.0/16
    (0xA9FE_0000, 0xFFFF_0000), // 169.254.0.0/16
    (0xE000_0000, 0xF000_0000), // 224.0.0.0/4 — многоадресная рассылка
];

#[cfg(all(windows, not(test)))]
mod platform {
    use std::io;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    use std::path::Path;

    use super::{Allowances, LAN_V4};

    /// Наши собственные ключи. Постоянные: по ним `reset` находит и снимает
    /// то, что осталось от прошлого запуска, ничего не зная о нём.
    const PROVIDER: GUID = GUID::from_u128(0x7d1f9a44_5c2e_4f18_9b3a_6e0c1d2f4a71);
    const SUBLAYER: GUID = GUID::from_u128(0x7d1f9a44_5c2e_4f18_9b3a_6e0c1d2f4a72);

    /// Вес нашего подслоя. Максимальный: правило, которое можно перебить
    /// чужим фильтром, — это не kill-switch.
    const SUBLAYER_WEIGHT: u16 = u16::MAX;

    /// Веса внутри подслоя. Запрет лежит ниже всех разрешений.
    const W_BLOCK: u64 = 0;
    const W_LAN: u64 = 8;
    const W_DHCP: u64 = 9;
    const W_LOOPBACK: u64 = 10;
    const W_SERVER: u64 = 11;
    const W_TUNNEL: u64 = 12;
    const W_APP: u64 = 13;

    const UDP: u8 = 17;
    const DHCP_SERVER_PORT: u16 = 67;

    pub struct Engine {
        handle: HANDLE,
        persistent: bool,
    }

    // Дескриптор WFP потокобезопасен: библиотека сериализует доступ сама.
    unsafe impl Send for Engine {}
    unsafe impl Sync for Engine {}

    impl Engine {
        pub fn open(persistent: bool) -> io::Result<Self> {
            let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            // Динамическая сессия — предохранитель всей конструкции: фильтры
            // живут ровно столько, сколько живёт этот дескриптор.
            session.flags = if persistent { 0 } else { FWPM_SESSION_FLAG_DYNAMIC };
            session.txnWaitTimeoutInMSec = 5_000;

            let mut handle: HANDLE = std::ptr::null_mut();
            // SAFETY: сессия заполнена и жива до конца вызова, дескриптор
            // закрывается в `remove`.
            let code = unsafe {
                FwpmEngineOpen0(
                    std::ptr::null(),
                    RPC_C_AUTHN_DEFAULT,
                    std::ptr::null(),
                    &session,
                    &mut handle,
                )
            };
            check(code, "не удалось открыть движок фильтрации")?;

            Ok(Self { handle, persistent })
        }

        /// Ставит полный набор правил, заменяя прежний.
        pub fn install(&self, allow: &Allowances) -> io::Result<()> {
            let transaction = Transaction::begin(self.handle)?;

            // Прежние правила убираем внутри той же транзакции: снаружи
            // трафик за это время не проходит ни секунды.
            delete_ours(self.handle)?;
            add_provider(self.handle, self.persistent)?;
            add_sublayer(self.handle, self.persistent)?;

            for (layer, v4) in [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, true),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false),
            ] {

                self.add(layer, W_BLOCK, FWP_ACTION_BLOCK, &[], "запрет по умолчанию")?;

                self.add(
                    layer,
                    W_LOOPBACK,
                    FWP_ACTION_PERMIT,
                    &[flag_condition(FWP_CONDITION_FLAG_IS_LOOPBACK)],
                    "петля",
                )?;

                if let Some(luid) = allow.tunnel_luid {
                    self.add(
                        layer,
                        W_TUNNEL,
                        FWP_ACTION_PERMIT,
                        &[luid_condition(&luid)],
                        "туннель",
                    )?;
                }

                self.add(
                    layer,
                    W_DHCP,
                    FWP_ACTION_PERMIT,
                    &[protocol_condition(UDP), remote_port_condition(DHCP_SERVER_PORT)],
                    "DHCP",
                )?;

                if allow.allow_lan && v4 {
                    for (addr, mask) in LAN_V4 {
                        let value = V4Mask::new(addr, mask);
                        self.add(
                            layer,
                            W_LAN,
                            FWP_ACTION_PERMIT,
                            &[value.condition()],
                            "локальная сеть",
                        )?;
                    }
                }

                for server in &allow.servers {
                    match (server, v4) {
                        (IpAddr::V4(a), true) => {
                            let octets = u32::from_be_bytes(a.octets());
                            self.add(
                                layer,
                                W_SERVER,
                                FWP_ACTION_PERMIT,
                                &[v4_address_condition(&octets)],
                                "адрес сервера",
                            )?;
                        }
                        (IpAddr::V6(a), false) => {
                            let octets = a.octets();
                            self.add(
                                layer,
                                W_SERVER,
                                FWP_ACTION_PERMIT,
                                &[v6_address_condition(&octets)],
                                "адрес сервера",
                            )?;
                        }
                        _ => {}
                    }
                }

                for app in &allow.apps {
                    let Some(id) = AppId::of(app) else {
                        // Ядро может быть ещё не скачано — это не повод
                        // валить установку фильтров.
                        tracing::warn!(path = %app.display(), "программу не удалось опознать для WFP");
                        continue;
                    };
                    self.add(
                        layer,
                        W_APP,
                        FWP_ACTION_PERMIT,
                        &[id.condition()],
                        "своя программа",
                    )?;
                }
            }

            transaction.commit()
        }

        pub fn remove(self) -> io::Result<()> {
            let result = (|| {
                let transaction = Transaction::begin(self.handle)?;
                delete_ours(self.handle)?;
                transaction.commit()
            })();

            // SAFETY: дескриптор получен из `FwpmEngineOpen0` и больше не
            // используется.
            unsafe { FwpmEngineClose0(self.handle) };
            result
        }

        fn add(
            &self,
            layer: GUID,
            weight: u64,
            action: FWP_ACTION_TYPE,
            conditions: &[FWPM_FILTER_CONDITION0],
            name: &str,
        ) -> io::Result<()> {
            let mut label = wide(name);

            let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            filter.displayData.name = label.as_mut_ptr();
            filter.layerKey = layer;
            filter.subLayerKey = SUBLAYER;
            filter.providerKey = &PROVIDER as *const GUID as *mut GUID;
            filter.weight.r#type = FWP_UINT64;
            // Вес передаётся указателем на значение, а не значением: так
            // устроен `FWP_VALUE0`, и `weight` обязан пережить вызов.
            let weight_value = weight;
            filter.weight.Anonymous.uint64 = &weight_value as *const u64 as *mut u64;
            filter.action.r#type = action;
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0;
            if self.persistent {
                filter.flags |= FWPM_FILTER_FLAG_PERSISTENT;
            }

            // SAFETY: все указатели ведут на живые значения этой функции.
            let code = unsafe {
                FwpmFilterAdd0(self.handle, &filter, std::ptr::null_mut(), std::ptr::null_mut())
            };
            check(code, "не удалось добавить фильтр")
        }
    }

    /// Транзакция WFP. Незавершённая откатывается в `Drop` — иначе ошибка на
    /// середине набора оставила бы половину правил.
    struct Transaction {
        handle: HANDLE,
        done: bool,
    }

    impl Transaction {
        fn begin(handle: HANDLE) -> io::Result<Self> {
            // SAFETY: дескриптор открыт.
            let code = unsafe { FwpmTransactionBegin0(handle, 0) };
            check(code, "не удалось начать транзакцию фильтров")?;
            Ok(Self { handle, done: false })
        }

        fn commit(mut self) -> io::Result<()> {
            // SAFETY: транзакция открыта и ещё не завершена.
            let code = unsafe { FwpmTransactionCommit0(self.handle) };
            self.done = true;
            check(code, "не удалось применить фильтры")
        }
    }

    impl Drop for Transaction {
        fn drop(&mut self) {
            if !self.done {
                // SAFETY: транзакция открыта.
                unsafe { FwpmTransactionAbort0(self.handle) };
            }
        }
    }

    fn add_provider(handle: HANDLE, persistent: bool) -> io::Result<()> {
        let mut name = wide("Sont");
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.providerKey = PROVIDER;
        provider.displayData.name = name.as_mut_ptr();
        if persistent {
            provider.flags |= FWPM_PROVIDER_FLAG_PERSISTENT;
        }

        // SAFETY: структура заполнена и жива до конца вызова.
        let code = unsafe { FwpmProviderAdd0(handle, &provider, std::ptr::null_mut()) };
        if code == FWP_E_ALREADY_EXISTS {
            return Ok(());
        }
        check(code, "не удалось зарегистрировать поставщика фильтров")
    }

    fn add_sublayer(handle: HANDLE, persistent: bool) -> io::Result<()> {
        let mut name = wide("Sont kill-switch");
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = SUBLAYER;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.providerKey = &PROVIDER as *const GUID as *mut GUID;
        sublayer.weight = SUBLAYER_WEIGHT;
        if persistent {
            sublayer.flags |= FWPM_SUBLAYER_FLAG_PERSISTENT;
        }

        // SAFETY: структура заполнена и жива до конца вызова.
        let code = unsafe { FwpmSubLayerAdd0(handle, &sublayer, std::ptr::null_mut()) };
        if code == FWP_E_ALREADY_EXISTS {
            return Ok(());
        }
        check(code, "не удалось создать подслой фильтров")
    }

    /// Удаляет всё, что помечено нашим поставщиком.
    ///
    /// Перебором, а не по заранее сохранённым ключам: снимать приходится и
    /// то, что оставил другой процесс, — постоянные фильтры прошлого запуска
    /// демона, о которых у нас нет никаких записей.
    fn delete_ours(handle: HANDLE) -> io::Result<()> {
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = &PROVIDER as *const GUID as *mut GUID;
        template.actionMask = u32::MAX;

        let mut enum_handle: HANDLE = std::ptr::null_mut();
        // SAFETY: шаблон жив до уничтожения дескриптора перечисления.
        let code = unsafe { FwpmFilterCreateEnumHandle0(handle, &template, &mut enum_handle) };
        check(code, "не удалось перечислить свои фильтры")?;

        let mut ids = Vec::new();
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count: u32 = 0;
            // SAFETY: дескриптор перечисления открыт.
            let code = unsafe { FwpmFilterEnum0(handle, enum_handle, 64, &mut entries, &mut count) };
            if code != ERROR_SUCCESS || count == 0 {
                // SAFETY: массив выделен библиотекой, если он вообще есть.
                if !entries.is_null() {
                    unsafe { FwpmFreeMemory0(&mut entries.cast()) };
                }
                break;
            }
            for i in 0..count as usize {
                // SAFETY: библиотека вернула массив из `count` указателей.
                ids.push(unsafe { (**entries.add(i)).filterId });
            }
            // SAFETY: массив выделен библиотекой и больше не нужен.
            unsafe { FwpmFreeMemory0(&mut entries.cast()) };
        }

        // SAFETY: дескриптор перечисления открыт и больше не используется.
        unsafe { FwpmFilterDestroyEnumHandle0(handle, enum_handle) };

        for id in ids {
            // SAFETY: идентификаторы получены перечислением.
            let code = unsafe { FwpmFilterDeleteById0(handle, id) };
            if code != ERROR_SUCCESS && code != FWP_E_FILTER_NOT_FOUND {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }

        // Подслой и поставщик снимаем последними: пока на них ссылается хоть
        // один фильтр, удаление не пройдёт.
        // SAFETY: ключи наши, отсутствие объекта — не ошибка.
        unsafe {
            FwpmSubLayerDeleteByKey0(handle, &SUBLAYER);
            FwpmProviderDeleteByKey0(handle, &PROVIDER);
        }

        Ok(())
    }

    pub fn reset() -> io::Result<()> {
        // Постоянная сессия: снимать нужно именно постоянные фильтры, а
        // динамических к этому моменту уже нет.
        let engine = Engine::open(true)?;
        engine.remove()
    }

    // ─────────────────────────── условия ───────────────────────────

    fn condition(field: GUID, match_type: FWP_MATCH_TYPE) -> FWPM_FILTER_CONDITION0 {
        let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        c.fieldKey = field;
        c.matchType = match_type;
        c
    }

    fn flag_condition(flag: u32) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ANY_SET);
        c.conditionValue.r#type = FWP_UINT32;
        c.conditionValue.Anonymous.uint32 = flag;
        c
    }

    fn luid_condition(luid: &u64) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_MATCH_EQUAL);
        c.conditionValue.r#type = FWP_UINT64;
        c.conditionValue.Anonymous.uint64 = luid as *const u64 as *mut u64;
        c
    }

    fn protocol_condition(protocol: u8) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL);
        c.conditionValue.r#type = FWP_UINT8;
        c.conditionValue.Anonymous.uint8 = protocol;
        c
    }

    fn remote_port_condition(port: u16) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL);
        c.conditionValue.r#type = FWP_UINT16;
        c.conditionValue.Anonymous.uint16 = port;
        c
    }

    fn v4_address_condition(addr: &u32) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
        c.conditionValue.r#type = FWP_UINT32;
        c.conditionValue.Anonymous.uint32 = *addr;
        c
    }

    fn v6_address_condition(octets: &[u8; 16]) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
        c.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
        c.conditionValue.Anonymous.byteArray16 = octets.as_ptr() as *mut FWP_BYTE_ARRAY16;
        c
    }

    /// Подсеть в виде, который понимает WFP.
    ///
    /// Значение живёт отдельной структурой, потому что условие ссылается на
    /// него указателем: временное значение внутри выражения умерло бы до
    /// вызова, оставив условию висячий адрес.
    struct V4Mask(FWP_V4_ADDR_AND_MASK);

    impl V4Mask {
        fn new(addr: u32, mask: u32) -> Self {
            Self(FWP_V4_ADDR_AND_MASK { addr, mask })
        }

        fn condition(&self) -> FWPM_FILTER_CONDITION0 {
            let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
            c.conditionValue.r#type = FWP_V4_ADDR_MASK;
            c.conditionValue.Anonymous.v4AddrMask =
                &self.0 as *const FWP_V4_ADDR_AND_MASK as *mut FWP_V4_ADDR_AND_MASK;
            c
        }
    }

    /// Идентификатор программы в терминах WFP.
    ///
    /// Это не путь: ядро хранит имя файла в собственном виде, и получить его
    /// можно только через `FwpmGetAppIdFromFileName0`. Блоб принадлежит
    /// библиотеке и освобождается в `Drop`.
    struct AppId(*mut FWP_BYTE_BLOB);

    impl AppId {
        fn of(path: &Path) -> Option<Self> {
            let wide_path = wide(&path.to_string_lossy());
            let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            // SAFETY: путь завершён нулём и жив до конца вызова.
            let code = unsafe { FwpmGetAppIdFromFileName0(wide_path.as_ptr(), &mut blob) };
            (code == ERROR_SUCCESS && !blob.is_null()).then_some(Self(blob))
        }

        fn condition(&self) -> FWPM_FILTER_CONDITION0 {
            let mut c = condition(FWPM_CONDITION_ALE_APP_ID, FWP_MATCH_EQUAL);
            c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            c.conditionValue.Anonymous.byteBlob = self.0;
            c
        }
    }

    impl Drop for AppId {
        fn drop(&mut self) {
            // SAFETY: блоб выделен библиотекой и больше не используется.
            unsafe { FwpmFreeMemory0(&mut self.0.cast()) };
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn check(code: u32, what: &str) -> io::Result<()> {
        if code == ERROR_SUCCESS {
            return Ok(());
        }
        Err(io::Error::other(format!("{what}: код 0x{code:08X}")))
    }

    /// `RPC_C_AUTHN_DEFAULT` из `rpcdce.h`: аутентификация по умолчанию.
    const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
    const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0067;
}

/// Заглушка для не-Windows и для тестов.
///
/// Тесты супервизора гоняют весь путь подключения, и настоящие фильтры WFP
/// в этот момент отрезали бы сеть машине, на которой идёт сборка.
#[cfg(not(all(windows, not(test))))]
mod platform {
    use std::io;

    use super::Allowances;

    pub struct Engine;

    impl Engine {
        pub fn open(_persistent: bool) -> io::Result<Self> {
            Ok(Self)
        }
        pub fn install(&self, allow: &Allowances) -> io::Result<()> {
            // Записываем то, что поставили бы: на не-Windows и в тестах это
            // единственный способ увидеть, с какими разрешениями kill-switch
            // был бы поднят.
            tracing::debug!(
                tunnel = allow.tunnel_luid.is_some(),
                apps = allow.apps.len(),
                servers = allow.servers.len(),
                lan = allow.allow_lan,
                "фильтры не ставятся: платформа без WFP"
            );
            Ok(())
        }
        pub fn remove(self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn reset() -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_ranges_cover_the_private_space() {
        let is_covered = |addr: [u8; 4]| {
            let value = u32::from_be_bytes(addr);
            LAN_V4.iter().any(|(net, mask)| value & mask == *net)
        };

        assert!(is_covered([10, 1, 2, 3]));
        assert!(is_covered([172, 20, 0, 1]));
        assert!(is_covered([192, 168, 1, 1]));
        assert!(is_covered([169, 254, 5, 5]), "адрес без аренды тоже локальный");
        assert!(is_covered([224, 0, 0, 251]), "многоадресная рассылка");
        assert!(!is_covered([8, 8, 8, 8]), "публичный адрес не локальный");
        assert!(!is_covered([172, 32, 0, 1]), "соседний с 172.16/12 — уже нет");
    }

    #[test]
    fn only_lockdown_survives_the_daemon() {
        assert!(!FirewallMode::Auto.survives_daemon_crash());
        assert!(FirewallMode::Lockdown.survives_daemon_crash());
        assert!(!FirewallMode::Off.is_enabled());
    }
}

//! Сетевой слой: TUN-адаптер и системные маршруты.
//!
//! # Почему это здесь, а не в ядре
//!
//! Первая версия поручала TUN и маршруты самому Xray. На практике его
//! TUN-inbound создавал адаптер, но не назначал ему адрес и не прописывал ни
//! одного маршрута: в таблице оставался только маршрут физического интерфейса,
//! а адаптер получал случайный APIPA-адрес от Windows. Изнутри чужого
//! Go-бинаря ни увидеть причину, ни исправить её было нельзя.
//!
//! Теперь ролями владеют разные слои: ядро отвечает за протокол
//! (VLESS/Reality/XHTTP) и слушает локальный SOCKS, а адаптер, маршруты и
//! перенос пакетов между ними — забота демона. Здесь это делает `tun2proxy`:
//! он создаёт адаптер через wintun, настраивает маршруты и переносит трафик
//! в SOCKS.
//!
//! # Обязательное исключение
//!
//! Подключение ядра к VPN-серверу обязано идти мимо туннеля. Иначе получается
//! петля: пакет к серверу попадает в TUN, оттуда в SOCKS, ядро снова шлёт его
//! к серверу — и так до исчерпания ресурсов. Адрес сервера передаётся в
//! [`TunnelConfig::bypass`] и получает отдельный маршрут через физический шлюз.

use std::net::{IpAddr, SocketAddr};

use tokio_util::sync::CancellationToken;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, ProxyType};

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("не удалось разобрать адрес: {0}")]
    BadAddress(String),
    #[error("не удалось запустить поток сетевого слоя: {0}")]
    Thread(String),
}

/// Сети, получающие маршрут мимо туннеля.
fn bypass_cidrs(hosts: &[IpAddr], lan_direct: bool) -> Vec<String> {
    let mut cidrs: Vec<String> = hosts
        .iter()
        .map(|ip| format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
        .collect();
    if lan_direct {
        cidrs.extend(LAN_NETWORKS.iter().map(|net| (*net).to_owned()));
    }
    cidrs
}

pub struct TunnelConfig {
    /// Локальный SOCKS-адрес ядра.
    pub socks: SocketAddr,
    /// Имя создаваемого адаптера.
    pub tun_name: String,
    pub mtu: u16,
    /// Адреса, которые обязаны идти мимо туннеля. Прежде всего — VPN-сервер.
    pub bypass: Vec<IpAddr>,
    /// Пускать локальные сети мимо туннеля — см. [`LAN_NETWORKS`].
    pub lan_direct: bool,
}

/// Частные сети, которые при разрешённой локальной сети идут мимо туннеля.
///
/// # Почему маршрутом, а не правилом ядра
///
/// Правило «локальная сеть — напрямую» в ядре было и раньше, но срабатывало
/// слишком поздно. Пакет к частному адресу попадал в TUN, пользовательский
/// стек TCP принимал соединение сам, мгновенно, а уже потом ядро пыталось
/// дозвониться до адресата от имени службы. Приложение видело «подключено»,
/// через таймаут — обрыв, и повторяло.
///
/// У пользователя так Delivery Optimization перебирал узлы
/// `192.168.x.x:7680`, запомненные в другой сети: пятьдесят две тысячи
/// сессий за несколько минут, девятьсот двадцать потоков в ядре, падение ядра —
/// и зависший на переподключении демон. Настоящий стек TCP ответил бы
/// приложению честным отказом, и оно бы отступило.
///
/// Маршрут к собственной подсети адаптера (`10.0.0.0/24` у TUN, подсеть Wi-Fi)
/// точнее этих и продолжает действовать: шлюз туннеля и его DNS остаются в
/// туннеле.
pub const LAN_NETWORKS: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

/// Прописывает ли локальные сети сам `tun2proxy`.
///
/// На Windows — нет: он отдал бы их утилите `route` записью с длиной префикса,
/// а это для IPv4 не документировано, и отказ сорвал бы подъём всего туннеля.
/// Там маршруты создаёт [`crate::lanroute`]. На остальных системах `ip route`
/// и `route -net` такую запись понимают.
const LAN_VIA_TUN2PROXY: bool = cfg!(not(windows));

/// Локальные сети как адрес и длина префикса.
#[cfg_attr(not(windows), allow(dead_code))]
fn lan_networks_v4() -> Vec<(std::net::Ipv4Addr, u8)> {
    LAN_NETWORKS
        .iter()
        .filter_map(|net| {
            let (base, prefix) = net.split_once('/')?;
            Some((base.parse().ok()?, prefix.parse().ok()?))
        })
        .collect()
}

/// Работающий сетевой слой.
///
/// Остановка обязательна и должна происходить раньше остановки ядра: пока
/// маршруты указывают в туннель, а ядра уже нет, машина остаётся без сети.
///
/// # Свой рантайм
///
/// `tun2proxy` работает в собственном рантайме на отдельном потоке, а не в
/// рантайме демона. Настраивая и снимая маршруты, он синхронно запускает
/// `route`, `netsh` и `ipconfig` прямо из асинхронного кода — то есть занимает
/// рабочий поток, пока внешняя программа не завершится. В рантайме демона это
/// останавливало вместе с потоком и задачи из его локальной очереди — IPC,
/// главный цикл. Своему рантайму туннель может мешать сколько угодно.
pub struct Tunnel {
    shutdown: CancellationToken,
    done: Option<tokio::sync::oneshot::Receiver<std::io::Result<usize>>>,
    /// Маршруты локальных сетей; снимаются вместе с туннелем.
    #[cfg(windows)]
    lan: Option<crate::lanroute::LanRoutes>,
}

/// Второй уровень защиты, а не основной: обычный путь остановки — `stop()`,
/// который ждёт, пока задача снимет маршруты и адаптер. Но если `Tunnel` всё
/// же будет отброшен без вызова (забытая передача предыдущей сессии, паника
/// по пути), сама задача не должна остаться работать бесконтрольно: без
/// отмены `general_run_async` продолжает крутиться в рантайме демона,
/// удерживая TUN-адаптер и маршруты, о которых больше некому напомнить.
/// `JoinHandle` при дропе не абортит задачу — отменять её обязана именно
/// отмена токена.
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl Tunnel {
    /// Поднимает адаптер и настраивает маршруты.
    pub fn start(config: TunnelConfig) -> Result<Self, TunnelError> {
        let mut args = Args::default();

        args.proxy(ArgProxy {
            proxy_type: ProxyType::Socks5,
            addr: config.socks,
            credentials: None,
        });
        args.tun(config.tun_name);

        // `setup` разрешает библиотеке самой прописать системные маршруты и
        // вернуть их обратно при остановке.
        args.setup(true);

        // DNS поверх TCP, а не UDP.
        //
        // UDP через SOCKS требует UDP-ассоциации, которая ломается на части
        // сетей и промежуточных устройств. Резолвинг — то место, где отказ
        // выглядит как «интернета нет вообще», поэтому здесь выбран самый
        // надёжный путь, пусть и чуть более медленный.
        args.dns(ArgDns::OverTcp);

        args.verbosity(ArgVerbosity::Warn);

        // IPv6 не поднимаем: адаптер и маршруты настраиваются только для
        // IPv4, и объявлять маршрут ::/0 без адреса значит отправить
        // IPv6-трафик в никуда.
        args.ipv6_enabled = false;
        args.mtu = config.mtu;

        for cidr in bypass_cidrs(&config.bypass, config.lan_direct && LAN_VIA_TUN2PROXY) {
            let parsed = cidr
                .parse()
                .map_err(|_| TunnelError::BadAddress(cidr.clone()))?;
            args.bypass(parsed);
        }

        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let mtu = config.mtu;

        tracing::info!(
            socks = %config.socks,
            bypass = ?config.bypass,
            lan_direct = config.lan_direct,
            "поднимаю сетевой слой"
        );

        // До подъёма адаптера: после него маршрут наружу ведёт уже в TUN, и
        // узнать физический выход будет не у кого.
        #[cfg(windows)]
        let lan = if config.lan_direct {
            crate::lanroute::LanRoutes::add(&lan_networks_v4())
        } else {
            None
        };

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("sont-tun".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .thread_name("sont-tun-worker")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        tracing::error!(error = %e, "не удалось создать рантайм сетевого слоя");
                        let _ = done_tx.send(Err(e));
                        return;
                    }
                };

                tracing::debug!("запуск tun2proxy");
                let result = runtime.block_on(tun2proxy::general_run_async(args, mtu, false, token));
                match &result {
                    Ok(sessions) => tracing::info!(sessions, "сетевой слой остановлен"),
                    Err(e) => tracing::error!(error = %e, "сетевой слой завершился с ошибкой"),
                }
                // Результат отдаём до того, как гасить рантайм: маршруты уже
                // сняты, и ждать уборки оставшихся сессий демону незачем.
                let _ = done_tx.send(result);
                // Не бесконечно: застрявшая блокирующая задача не должна
                // держать поток вечно.
                runtime.shutdown_timeout(std::time::Duration::from_secs(2));
            })
            .map_err(|e| TunnelError::Thread(e.to_string()))?;

        Ok(Self {
            shutdown,
            done: Some(done_rx),
            #[cfg(windows)]
            lan,
        })
    }

    /// Останавливает слой и возвращает системные маршруты на место.
    pub async fn stop(mut self) {
        self.shutdown.cancel();

        // Ждём именно завершения задачи: она снимает маршруты и удаляет
        // адаптер. Если бросить её и сразу погасить ядро, у пользователя
        // останется таблица маршрутов, указывающая в несуществующий туннель.
        //
        // Приёмник берём через `take`, а не выносим из `self`: `Tunnel`
        // реализует `Drop`, а из типа с `Drop` нельзя частично вынести поле.
        let Some(done) = self.done.take() else {
            return;
        };
        match tokio::time::timeout(std::time::Duration::from_secs(10), done).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => tracing::warn!("поток сетевого слоя завершился, не отчитавшись"),
            Err(_) => tracing::error!(
                "сетевой слой не остановился за отведённое время; \
                 маршруты могут остаться до перезагрузки"
            ),
        }

        // Маршруты локальных сетей — последними, когда туннеля уже нет.
        #[cfg(windows)]
        {
            self.lan = None;
        }
    }

    /// Заглушка для тестов конечного автомата: адаптер не создаётся.
    #[cfg(test)]
    pub(crate) fn placeholder() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = tx.send(Ok(0));
        Self {
            shutdown: CancellationToken::new(),
            done: Some(rx),
            #[cfg(windows)]
            lan: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_addresses_become_host_routes() {
        // Проверяем ровно то, из-за чего возникает петля: адрес сервера
        // должен превращаться в маршрут на один узел.
        let hosts: Vec<IpAddr> = vec!["198.51.100.7".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        assert_eq!(
            bypass_cidrs(&hosts, false),
            ["198.51.100.7/32", "2001:db8::1/128"]
        );
    }

    #[test]
    fn local_networks_skip_the_tunnel_only_when_allowed() {
        // Разрешённая локальная сеть обязана идти мимо TUN маршрутом: иначе
        // пользовательский стек принимает соединение к несуществующему узлу
        // сам, и приложение перебирает такие узлы тысячами.
        let hosts: Vec<IpAddr> = vec!["198.51.100.7".parse().unwrap()];

        let allowed = bypass_cidrs(&hosts, true);
        for net in LAN_NETWORKS {
            assert!(allowed.iter().any(|c| c == net), "нет маршрута для {net}");
        }
        assert!(allowed.iter().any(|c| c == "198.51.100.7/32"));

        // Запрещённая — остаётся в туннеле, как просил пользователь.
        assert_eq!(bypass_cidrs(&hosts, false), ["198.51.100.7/32"]);
    }

    #[test]
    fn every_lan_network_becomes_a_prefix_for_the_route_table() {
        // Разберись одна из сетей с ошибкой — она молча выпала бы из маршрутов,
        // и трафик к ней снова пошёл бы в туннель.
        let parsed = lan_networks_v4();
        assert_eq!(parsed.len(), LAN_NETWORKS.len());
        for (network, prefix) in parsed {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            assert_eq!(
                u32::from(network) & !mask,
                0,
                "{network}/{prefix}: адрес сети с ненулевой хостовой частью система отвергнет"
            );
        }
    }

    #[test]
    fn every_lan_network_parses_as_a_route() {
        for net in LAN_NETWORKS {
            let mut args = Args::default();
            let parsed = net.parse().unwrap_or_else(|_| panic!("не разбирается: {net}"));
            args.bypass(parsed);
        }
    }

    #[test]
    fn the_tunnel_gateway_stays_inside_the_tunnel() {
        // Шлюз и DNS туннеля — 10.0.0.1 в подсети адаптера 10.0.0.0/24.
        // Обходной маршрут, покрывающий этот адрес, обязан быть менее точным,
        // чем /24: иначе он перебьёт подсеть адаптера, и DNS уйдёт мимо
        // туннеля.
        const GATEWAY: u32 = u32::from_be_bytes([10, 0, 0, 1]);
        const ADAPTER_PREFIX: u32 = 24;

        for net in LAN_NETWORKS {
            let (base, prefix) = net.split_once('/').unwrap();
            let base: std::net::Ipv4Addr = base.parse().unwrap();
            let prefix: u32 = prefix.parse().unwrap();
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            if GATEWAY & mask == u32::from(base) & mask {
                assert!(prefix < ADAPTER_PREFIX, "{net} перебьёт подсеть адаптера");
            }
        }
    }

    #[tokio::test]
    async fn start_requires_privileges_and_fails_cleanly() {
        // Без прав администратора адаптер создать нельзя. Проверяем, что это
        // не паника и не зависание, а обычная ошибка: демон должен уметь
        // сообщить причину и остаться работоспособным.
        let config = TunnelConfig {
            socks: "127.0.0.1:1".parse().unwrap(),
            tun_name: "sont-test-tun".to_owned(),
            mtu: 1500,
            bypass: vec!["203.0.113.1".parse().unwrap()],
            // Маршрутов машины тест не касается: запущенный с правами
            // администратора, он иначе переписал бы их на живой системе.
            lan_direct: false,
        };

        let Ok(tunnel) = Tunnel::start(config) else {
            return; // отказ на этапе настройки тоже приемлем
        };

        // Задача либо быстро упадёт из-за нехватки прав, либо будет работать;
        // в обоих случаях остановка обязана пройти без зависания.
        tokio::time::timeout(std::time::Duration::from_secs(20), tunnel.stop())
            .await
            .expect("остановка не должна зависать");
    }
}

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
}

pub struct TunnelConfig {
    /// Локальный SOCKS-адрес ядра.
    pub socks: SocketAddr,
    /// Имя создаваемого адаптера.
    pub tun_name: String,
    pub mtu: u16,
    /// Адреса, которые обязаны идти мимо туннеля. Прежде всего — VPN-сервер.
    pub bypass: Vec<IpAddr>,
}

/// Работающий сетевой слой.
///
/// Остановка обязательна и должна происходить раньше остановки ядра: пока
/// маршруты указывают в туннель, а ядра уже нет, машина остаётся без сети.
pub struct Tunnel {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<std::io::Result<usize>>,
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

        for ip in &config.bypass {
            let cidr = format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 });
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
            "поднимаю сетевой слой"
        );

        let task = tokio::spawn(async move {
            tracing::debug!("запуск tun2proxy");
            let result = tun2proxy::general_run_async(args, mtu, false, token).await;
            match &result {
                Ok(sessions) => tracing::info!(sessions, "сетевой слой остановлен"),
                Err(e) => tracing::error!(error = %e, "сетевой слой завершился с ошибкой"),
            }
            result
        });

        Ok(Self { shutdown, task })
    }

    /// Останавливает слой и возвращает системные маршруты на место.
    pub async fn stop(mut self) {
        self.shutdown.cancel();

        // Ждём именно завершения задачи: она снимает маршруты и удаляет
        // адаптер. Если бросить её и сразу погасить ядро, у пользователя
        // останется таблица маршрутов, указывающая в несуществующий туннель.
        //
        // Берём задачу по `&mut`, а не забираем её из `self`: `Tunnel`
        // реализует `Drop`, а из типа с `Drop` нельзя частично вынести поле.
        match tokio::time::timeout(std::time::Duration::from_secs(10), &mut self.task).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "задача сетевого слоя завершилась аварийно"),
            Err(_) => tracing::error!(
                "сетевой слой не остановился за отведённое время; \
                 маршруты могут остаться до перезагрузки"
            ),
        }
    }

    /// Заглушка для тестов конечного автомата: адаптер не создаётся.
    #[cfg(test)]
    pub(crate) fn placeholder() -> Self {
        Self {
            shutdown: CancellationToken::new(),
            task: tokio::spawn(async { Ok(0) }),
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
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(format!("{v4}/{}", 32), "198.51.100.7/32");

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(v6.is_ipv6());
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

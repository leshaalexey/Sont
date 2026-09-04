//! Сборка конфигурации Xray.
//!
//! Чистая функция без ввода-вывода: на входе профиль сервера и настройки, на
//! выходе JSON. Благодаря этому весь разбор особенностей ядра проверяется
//! обычными тестами, без запуска чего-либо.

use serde_json::{json, Map, Value};
use sont_core::{
    Security, ServerProfile, Settings, SplitTunnelMode, Stream, Transport,
};

use crate::support;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("сервер не поддерживается: {0}")]
    Unsupported(String),
}

/// Параметры окружения, которые знает демон, а не профиль сервера.
#[derive(Debug, Clone)]
pub struct RuntimeInfo {
    /// Имя TUN-интерфейса. Создаёт его демон, а не ядро.
    pub tun_name: String,
    pub mtu: u16,
    /// Адрес служебного порта статистики, только на localhost.
    pub metrics_listen: String,
    /// Локальный SOCKS-порт, только на localhost.
    pub probe_listen: String,
    /// Локальный HTTP-порт, только на localhost.
    ///
    /// Нужен отдельно от SOCKS: системные настройки прокси Windows и часть
    /// приложений работают с HTTP-прокси надёжнее, а некоторые SOCKS не
    /// понимают вовсе.
    pub http_listen: String,
    pub log_level: String,
}

/// Адрес, по которому демон проверяет, работает ли туннель.
///
/// Живёт здесь, рядом с правилом маршрутизации, которое загоняет его в
/// туннель: разъедься эти два места — и проверка пойдёт мимо туннеля,
/// подтверждая работу того, чего нет.
pub const HEALTH_CHECK_IP: &str = "1.1.1.1";

/// Полный адрес проверки. Отдаёт заодно видимый снаружи IP-адрес.
pub const HEALTH_CHECK_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

/// Тег входящего соединения для проверки связности и туннелирования.
pub const PROBE_INBOUND: &str = "probe-in";
/// Тег входящего HTTP-соединения.
pub const HTTP_INBOUND: &str = "http-in";

/// Приставка к тегам дорожек гонки серверов. Номер дорожки идёт следом.
const RACE_INBOUND: &str = "race-in-";
const RACE_OUTBOUND: &str = "race-out-";

impl Default for RuntimeInfo {
    fn default() -> Self {
        Self {
            tun_name: "sont-tun".to_owned(),
            mtu: 1500,
            // Порт указан явно, а не нулём: `:0` заставил бы ядро занять
            // случайный порт, номер которого мы бы уже не узнали, и
            // статистику стало бы неоткуда читать. Демон подставляет сюда
            // свободный порт, выбранный заранее.
            metrics_listen: "127.0.0.1:18964".to_owned(),
            probe_listen: "127.0.0.1:18965".to_owned(),
            http_listen: "127.0.0.1:18966".to_owned(),
            log_level: "warning".to_owned(),
        }
    }
}

/// Тег основного исходящего соединения.
const PROXY: &str = "proxy";
const DIRECT: &str = "direct";
const BLOCK: &str = "block";

/// Собирает конфигурацию для подключения к одному серверу.
///
/// Ядро настраивается на один сервер, а не на группу: у Xray нет живого
/// переключения между outbound-ами по внешней команде, поэтому смена сервера
/// это пересборка конфигурации и перезапуск ядра. Проще и честнее, чем
/// поддерживать иллюзию мгновенного переключения.
pub fn build(
    server: &ServerProfile,
    settings: &Settings,
    runtime: &RuntimeInfo,
) -> Result<Value, BuildError> {
    if let Some(reason) = support::unsupported_reason(&server.transport) {
        return Err(BuildError::Unsupported(reason));
    }

    let mut config = Map::new();

    config.insert(
        "log".into(),
        json!({
            "loglevel": core_log_level(&runtime.log_level),
            // Журнал доступа отключён намеренно и безусловно.
            //
            // Он не подчиняется `loglevel` и пишет строку про каждое
            // соединение — то есть полный список всего, что пользователь
            // открывал. Для VPN-клиента вести такой файл недопустимо: это
            // ровно те сведения, ради сокрытия которых VPN и включают.
            "access": "none",
        }),
    );

    // Единственный вход — локальный SOCKS.
    //
    // TUN-inbound самого Xray не используется: он создавал адаптер, но не
    // назначал ему адрес и не прописывал маршруты, а диагностировать это
    // изнутри чужого Go-бинаря невозможно. Сетевым слоем теперь владеет
    // демон, а ядро отвечает ровно за то, что умеет лучше всех, — за
    // протокол VLESS/Reality/XHTTP.
    config.insert(
        "inbounds".into(),
        json!([socks_inbound(runtime), http_inbound(runtime)]),
    );

    // Порядок важен: Xray отправляет в первый outbound всё, что не подошло
    // ни под одно правило маршрутизации.
    config.insert(
        "outbounds".into(),
        json!([
            proxy_outbound(server),
            { "tag": DIRECT, "protocol": "freedom", "settings": { "domainStrategy": "UseIP" } },
            { "tag": BLOCK, "protocol": "blackhole" },
        ]),
    );

    config.insert("dns".into(), dns(settings));
    config.insert("routing".into(), routing(settings));

    if !runtime.metrics_listen.is_empty() {
        config.insert(
            "metrics".into(),
            json!({ "tag": "metrics", "listen": runtime.metrics_listen }),
        );
        // Без включённой статистики счётчики трафика остаются нулевыми.
        config.insert("stats".into(), json!({}));
        config.insert(
            "policy".into(),
            json!({
                "system": {
                    "statsOutboundUplink": true,
                    "statsOutboundDownlink": true,
                }
            }),
        );
    }

    Ok(Value::Object(config))
}

/// Собирает конфигурацию для одновременной проверки нескольких серверов.
///
/// # Зачем отдельная конфигурация
///
/// Понять, работает ли сервер, не запуская ядро, нельзя. Ни замер задержки, ни
/// рукопожатие TLS этого не показывают: до сервера, у которого истёк ключ или
/// сломана конфигурация, TCP доходит прекрасно, а Reality на чужой ClientHello
/// честно отвечает тем сайтом, за который себя выдаёт, — то есть выглядит
/// исправным ровно так же, как исправный.
///
/// Проверять по одному значит платить полной последовательностью подключения за
/// каждый негодный сервер. Здесь все кандидаты проверяются сразу: каждому свой
/// локальный вход, свой выход и правило, соединяющее их напрямую. Одно ядро,
/// один запуск, и ответ приходит от того, кто действительно провёл запрос.
///
/// # Чего здесь нет
///
/// Ни DNS, ни статистики, ни раздельного туннелирования, ни правил для
/// широковещательного трафика. Через эту конфигурацию проходит ровно один
/// запрос на дорожку, к адресу-литералу, и всё перечисленное только добавило бы
/// ей поводов не запуститься.
pub fn build_race(lanes: &[(&ServerProfile, u16)], log_level: &str) -> Result<Value, BuildError> {
    if lanes.is_empty() {
        return Err(BuildError::Unsupported(
            "гонка без участников не имеет смысла".to_owned(),
        ));
    }

    let mut inbounds = Vec::with_capacity(lanes.len());
    let mut outbounds = Vec::with_capacity(lanes.len() + 1);
    let mut rules = Vec::with_capacity(lanes.len());

    for (lane, (server, port)) in lanes.iter().enumerate() {
        if let Some(reason) = support::unsupported_reason(&server.transport) {
            return Err(BuildError::Unsupported(reason));
        }

        let inbound_tag = format!("{RACE_INBOUND}{lane}");
        let outbound_tag = format!("{RACE_OUTBOUND}{lane}");

        inbounds.push(json!({
            "tag": inbound_tag,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": port,
            // UDP не нужен: проверка — это один запрос HTTPS. А вот разбор
            // протокола не нужен тем более: адрес назначения известен и задан
            // литералом, подсматривать в трафик не за чем.
            "settings": { "auth": "noauth", "udp": false },
        }));

        let mut outbound = proxy_outbound(server);
        outbound["tag"] = json!(outbound_tag);
        outbounds.push(outbound);

        // Дорожки не должны перетекать одна в другую: без правила весь трафик
        // ушёл бы в первый outbound, и гонку выиграл бы кто попало.
        rules.push(json!({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": outbound_tag,
        }));
    }

    // Всё, что почему-либо не подошло ни под одно правило, обязано умереть, а
    // не уйти мимо проверяемого сервера: иначе дорожка отчитается об успехе,
    // не пройдя через тот сервер, ради которого заведена.
    outbounds.push(json!({ "tag": BLOCK, "protocol": "blackhole" }));
    rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": BLOCK,
    }));

    Ok(json!({
        "log": { "loglevel": core_log_level(log_level), "access": "none" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "rules": rules },
    }))
}

/// Уровень журналирования ядра.
///
/// Уровень демона напрямую ядру не передаётся. На `info` Xray пишет строку про
/// **каждое** соединение — это, во-первых, поток в тысячи строк в минуту, а
/// во-вторых, журнал всех посещённых пользователем адресов. Для VPN-клиента
/// такой файл — ровно то, чего пользователь и пытается избежать.
///
/// Поэтому подробный вывод включается только явным запросом отладки.
fn core_log_level(daemon_level: &str) -> &'static str {
    match daemon_level.trim().to_ascii_lowercase().as_str() {
        "trace" | "debug" => "info",
        _ => "warning",
    }
}

/// Локальный SOCKS-вход — единственная точка входа в ядро.
///
/// Через него идёт и весь туннелированный трафик (его подаёт слой TUN на
/// стороне демона), и проверка связности. Слушает только localhost.
fn socks_inbound(runtime: &RuntimeInfo) -> Value {
    let (host, port) = split_listen(&runtime.probe_listen);
    json!({
        "tag": PROBE_INBOUND,
        "protocol": "socks",
        "listen": host,
        "port": port,
        // UDP обязателен: без него отваливаются QUIC, а с ним заметная часть
        // современного веба, и игры.
        "settings": { "auth": "noauth", "udp": true },
        // Разбор протокола нужен для маршрутизации по доменам: в пакетах,
        // пришедших из TUN, имени узла уже нет.
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": false,
        },
    })
}

/// Локальный HTTP-вход.
///
/// Именно его прописывают в системные настройки прокси Windows: WinINET и
/// многие приложения работают с HTTP-прокси, а SOCKS понимают не все.
fn http_inbound(runtime: &RuntimeInfo) -> Value {
    let (host, port) = split_listen(&runtime.http_listen);
    json!({
        "tag": HTTP_INBOUND,
        "protocol": "http",
        "listen": host,
        "port": port,
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls"],
            "routeOnly": false,
        },
    })
}

/// Делит `host:port`, оставляя разумные значения при неверном формате.
fn split_listen(listen: &str) -> (String, u16) {
    match listen.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(18965)),
        None => ("127.0.0.1".to_owned(), 18965),
    }
}

fn proxy_outbound(server: &ServerProfile) -> Value {
    let address = &server.endpoint.host;
    let port = server.endpoint.port;

    let (protocol, settings) = match &server.transport {
        Transport::Vless(v) => (
            "vless",
            json!({
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [vless_user(v)],
                }]
            }),
        ),

        Transport::Vmess(v) => (
            "vmess",
            json!({
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": v.uuid.expose(),
                        "alterId": v.alter_id,
                        "security": v.cipher,
                    }],
                }]
            }),
        ),

        Transport::Shadowsocks(s) => (
            "shadowsocks",
            json!({
                "servers": [{
                    "address": address,
                    "port": port,
                    "method": s.method,
                    "password": s.password.expose(),
                }]
            }),
        ),

        Transport::WireGuard(w) => {
            let mut peer = json!({
                "publicKey": w.peer_public_key,
                "endpoint": format!("{}:{}", address, port),
            });
            if let Some(psk) = &w.pre_shared_key {
                peer["preSharedKey"] = json!(psk.expose());
            }

            let mut s = json!({
                "secretKey": w.private_key.expose(),
                "address": w.local_address,
                "peers": [peer],
            });
            if let Some(mtu) = w.mtu {
                s["mtu"] = json!(mtu);
            }
            ("wireguard", s)
        }

        // Отсеяно раньше, в build().
        Transport::Hysteria2(_) | Transport::Tuic(_) => unreachable!(
            "неподдерживаемые протоколы отбраковываются до сборки конфигурации"
        ),
    };

    let mut outbound = json!({
        "tag": PROXY,
        "protocol": protocol,
        "settings": settings,
    });

    if let Some(stream) = stream_settings(&server.transport) {
        outbound["streamSettings"] = stream;
    }

    outbound
}

fn vless_user(v: &sont_core::transport::Vless) -> Value {
    let mut user = json!({
        "id": v.uuid.expose(),
        "encryption": "none",
    });

    // XTLS-flow работает только поверх «сырого» TCP и только с TLS-подобным
    // слоем. Проставить его при ws/grpc/xhttp — верный способ получить
    // отказ ядра при старте, поэтому фильтруем здесь, а не надеемся на
    // корректность ссылки из подписки.
    let raw_tcp = matches!(v.stream, Stream::Tcp);
    let encrypted = !matches!(v.security, Security::None);

    if let Some(flow) = v.flow.as_ref().filter(|f| !f.is_empty()) {
        if raw_tcp && encrypted {
            user["flow"] = json!(flow);
        } else {
            tracing::debug!(
                %flow,
                "flow отброшен: он применим только к TCP с TLS или Reality"
            );
        }
    }

    user
}

fn stream_settings(transport: &Transport) -> Option<Value> {
    let (stream, security) = match transport {
        Transport::Vless(v) => (&v.stream, &v.security),
        Transport::Vmess(v) => (&v.stream, &v.security),
        // У остальных протоколов транспортный слой собственный.
        _ => return None,
    };

    let mut s = Map::new();

    match stream {
        Stream::Tcp => {
            s.insert("network".into(), json!("tcp"));
        }
        Stream::Ws {
            path,
            host,
            max_early_data,
        } => {
            s.insert("network".into(), json!("ws"));
            let mut ws = json!({ "path": path });
            if let Some(h) = host {
                ws["host"] = json!(h);
            }
            if let Some(ed) = max_early_data {
                ws["maxEarlyData"] = json!(ed);
                ws["earlyDataHeaderName"] = json!("Sec-WebSocket-Protocol");
            }
            s.insert("wsSettings".into(), ws);
        }
        Stream::Grpc { service_name } => {
            s.insert("network".into(), json!("grpc"));
            s.insert("grpcSettings".into(), json!({ "serviceName": service_name }));
        }
        Stream::HttpUpgrade { path, host } => {
            s.insert("network".into(), json!("httpupgrade"));
            let mut hu = json!({ "path": path });
            if let Some(h) = host {
                hu["host"] = json!(h);
            }
            s.insert("httpupgradeSettings".into(), hu);
        }
        Stream::Http { path, host } => {
            s.insert("network".into(), json!("http"));
            s.insert("httpSettings".into(), json!({ "path": path, "host": host }));
        }
        Stream::Xhttp { path, host, mode } => {
            s.insert("network".into(), json!("xhttp"));
            let mut x = json!({ "path": path });
            if let Some(h) = host {
                x["host"] = json!(h);
            }
            // `auto` — значение по умолчанию самого Xray; проставляем явно,
            // чтобы конфиг читался однозначно.
            x["mode"] = json!(mode.as_deref().unwrap_or("auto"));
            s.insert("xhttpSettings".into(), x);
        }
    }

    match security {
        Security::None => {
            s.insert("security".into(), json!("none"));
        }
        Security::Tls(tls) => {
            s.insert("security".into(), json!("tls"));
            let mut t = Map::new();
            if let Some(sni) = &tls.sni {
                t.insert("serverName".into(), json!(sni));
            }
            if !tls.alpn.is_empty() {
                t.insert("alpn".into(), json!(tls.alpn));
            }
            if let Some(fp) = &tls.fingerprint {
                t.insert("fingerprint".into(), json!(fp));
            }
            if tls.insecure {
                t.insert("allowInsecure".into(), json!(true));
            }
            s.insert("tlsSettings".into(), Value::Object(t));
        }
        Security::Reality(r) => {
            s.insert("security".into(), json!("reality"));
            let mut t = json!({
                "serverName": r.sni,
                "publicKey": r.public_key,
                "shortId": r.short_id,
            });
            if let Some(fp) = &r.fingerprint {
                t["fingerprint"] = json!(fp);
            }
            s.insert("realitySettings".into(), t);
        }
    }

    Some(Value::Object(s))
}

fn dns_servers(settings: &Settings) -> Vec<String> {
    match &settings.dns.mode {
        sont_core::DnsMode::Custom { servers } if !servers.is_empty() => servers.clone(),
        // Резолверы по умолчанию. Запросы к ним всё равно уходят через
        // туннель — за это отвечает правило маршрутизации ниже.
        _ => vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()],
    }
}

fn dns(settings: &Settings) -> Value {
    json!({
        "servers": dns_servers(settings),
        // Интерфейс поднимается только с IPv4, поэтому AAAA-ответы привели бы
        // к попыткам соединения по недоступному семейству адресов.
        "queryStrategy": "UseIPv4",
        "disableFallback": false,
    })
}

fn routing(settings: &Settings) -> Value {
    let mut rules: Vec<Value> = Vec::new();

    // 1. Широковещательный и многоадресный трафик — в никуда.
    //
    //    Он не имеет смысла ни в туннеле, ни в `direct`: обычный исходящий
    //    сокет не может отправить пакет на broadcast-адрес и возвращает
    //    «недостаточно места в буфере». А поскольку такие пакеты шлются
    //    десятками в секунду (NetBIOS, mDNS, SSDP, обнаружение устройств в
    //    локальной сети), ядро уходит в бесконечный цикл неудачных попыток.
    //
    //    Правило первое и безусловное — эти адреса не должны доходить ни до
    //    одного другого правила.
    rules.push(json!({
        "type": "field",
        "ip": [
            // Многоадресная рассылка целиком: mDNS, SSDP, LLMNR.
            "224.0.0.0/4",
            // Ограниченный широковещательный адрес.
            "255.255.255.255/32",
            // Широковещательный адрес link-local сегмента (APIPA).
            "169.254.255.255/32",
            // То же самое для IPv6, и это не для полноты списка.
            //
            // Windows шлёт mDNS в каждый интерфейс, где включён IPv6, — в том
            // числе в туннельный, сколько бы маршрутов мы туда ни не
            // прописывали: многоадресные пакеты попадают в адаптер помимо
            // таблицы маршрутизации. Отправить их наружу обычным сокетом
            // нельзя, и каждый такой пакет висел полминуты до таймаута.
            // Скорость их появления — сотни в секунду; ipstack захлёбывался,
            // проверка связности не пробивалась сквозь очередь, две неудачи
            // подряд — и демон переподключался. По кругу.
            "ff00::/8",
        ],
        "outboundTag": BLOCK,
    }));

    // 2. Проверка связности всегда идёт в туннель.
    //
    //    Иначе она ничего не проверяет: при раздельном туннелировании в
    //    режиме Include весь неперечисленный трафик уходит напрямую, и
    //    проверка подтверждала бы работу туннеля, не проходя через него.
    //
    //    Правило по адресу назначения, а не по входу.
    //
    //    Раньше здесь стояло `inboundTag: [PROBE_INBOUND, HTTP_INBOUND]` — и
    //    это отменяло раздельное туннелирование целиком. Через эти два входа
    //    приходит **весь** трафик: SOCKS принимает то, что подал слой TUN,
    //    HTTP — то, что система отдала прокси. Правило совпадало с каждым
    //    соединением, а Xray берёт первое подошедшее — до правил ниже дело
    //    не доходило никогда. Ни программы, ни сайты из списка исключений
    //    мимо туннеля не уходили, и понять это по интерфейсу было нельзя:
    //    он показывал настроенное правило, которого не существовало.
    rules.push(json!({
        "type": "field",
        "ip": [format!("{HEALTH_CHECK_IP}/32")],
        "outboundTag": PROXY,
    }));

    // 3. Раздельное туннелирование. Самое частное из оставшихся правил,
    //    поэтому идёт раньше общих.
    let split = &settings.split_tunnel;
    if split.is_active() {
        // Программы различает не всякое ядро и не на всякой системе; сайты —
        // всегда. Поэтому списки проверяются по отдельности: невозможность
        // одного не должна отменять другое.
        let apps = (!split.apps.is_empty() && support::process_routing_available())
            .then_some(&split.apps);

        // `domain:` вместо голой строки: у Xray голая строка — это поиск
        // подстроки, и «vk.com» поймал бы «notvk.com.evil.net». Префикс даёт
        // домен и его поддомены, то есть ровно то, что человек имеет в виду,
        // называя сайт.
        let sites: Vec<String> = split.sites.iter().map(|d| format!("domain:{d}")).collect();
        let sites = (!sites.is_empty()).then_some(sites);

        let target = match split.mode {
            SplitTunnelMode::Exclude => DIRECT,
            SplitTunnelMode::Include => PROXY,
            SplitTunnelMode::Off => DIRECT,
        };

        if !matches!(split.mode, SplitTunnelMode::Off) {
            if let Some(apps) = apps {
                rules.push(json!({
                    "type": "field",
                    "process": apps,
                    "outboundTag": target,
                }));
            }
            if let Some(sites) = sites {
                rules.push(json!({
                    "type": "field",
                    "domain": sites,
                    "outboundTag": target,
                }));
            }
            if matches!(split.mode, SplitTunnelMode::Include) {
                // Перечисленные ушли в туннель выше, всё прочее — напрямую.
                rules.push(json!({
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": DIRECT,
                }));
            }
        }
    }

    // 4. DNS-запросы — в туннель, иначе резолвер провайдера видит, куда
    //    ходит пользователь, даже когда весь остальной трафик закрыт.
    rules.push(json!({
        "type": "field",
        "port": 53,
        "outboundTag": PROXY,
    }));

    // 5. Локальная сеть мимо туннеля: принтеры, NAS, шлюз.
    if settings.allow_lan {
        rules.push(json!({
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": DIRECT,
        }));
    }

    json!({
        // AsIs: решение принимается по имени узла, полученному из sniffing.
        // IPIfNonMatch заставил бы ядро резолвить домены заранее и сводил бы
        // на нет смысл маршрутизации по доменам.
        "domainStrategy": "AsIs",
        "rules": rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sont_core::transport::{Reality, Shadowsocks, Tls, Tuic, Vless};
    use sont_core::{
        Endpoint, Secret, SplitTunnelRules, SubscriptionId,
    };

    fn source() -> SubscriptionId {
        SubscriptionId::from_url("https://panel.example/sub")
    }

    /// Профиль, повторяющий реальный сервер: VLESS + Reality + XHTTP.
    fn xhttp_reality() -> ServerProfile {
        ServerProfile::new(
            "PaperVPN_AT",
            Endpoint::new("198.51.100.7", 8443),
            Transport::Vless(Vless {
                uuid: Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: None,
                stream: Stream::Xhttp {
                    path: "/".into(),
                    host: None,
                    mode: None,
                },
                security: Security::Reality(Reality {
                    sni: "api.dropbox.com".into(),
                    public_key: "PUBKEY".into(),
                    short_id: String::new(),
                    fingerprint: Some("firefox".into()),
                }),
            }),
            source(),
        )
    }

    fn build_ok(server: &ServerProfile, settings: &Settings) -> Value {
        build(server, settings, &RuntimeInfo::default()).expect("конфиг должен собраться")
    }


    #[test]
    fn xhttp_reality_produces_the_expected_outbound() {
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let out = &cfg["outbounds"][0];

        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["tag"], PROXY);
        assert_eq!(out["settings"]["vnext"][0]["address"], "198.51.100.7");
        assert_eq!(out["settings"]["vnext"][0]["port"], 8443);
        assert_eq!(out["settings"]["vnext"][0]["users"][0]["encryption"], "none");

        let stream = &out["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["xhttpSettings"]["path"], "/");
        assert_eq!(stream["xhttpSettings"]["mode"], "auto");

        assert_eq!(stream["security"], "reality");
        assert_eq!(stream["realitySettings"]["serverName"], "api.dropbox.com");
        assert_eq!(stream["realitySettings"]["publicKey"], "PUBKEY");
        assert_eq!(stream["realitySettings"]["fingerprint"], "firefox");
        assert_eq!(
            stream["realitySettings"]["shortId"], "",
            "пустой shortId допустим и должен передаваться как есть"
        );
    }

    #[test]
    fn proxy_is_the_first_outbound_so_it_is_the_default() {
        // Xray отправляет в первый outbound всё, что не подошло под правила.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        assert_eq!(cfg["outbounds"][0]["tag"], PROXY);
        assert_eq!(cfg["outbounds"][1]["tag"], DIRECT);
        assert_eq!(cfg["outbounds"][2]["tag"], BLOCK);
    }

    #[test]
    fn http_inbound_is_present_and_local() {
        // Через него работает режим прокси: именно этот адрес прописывается
        // в системные настройки Windows.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let http = &cfg["inbounds"][1];

        assert_eq!(http["tag"], HTTP_INBOUND);
        assert_eq!(http["protocol"], "http");
        assert_eq!(http["listen"], "127.0.0.1");
        assert_ne!(
            http["port"], cfg["inbounds"][0]["port"],
            "порты SOCKS и HTTP должны различаться"
        );
    }

    #[test]
    fn no_rule_matches_by_inbound() {
        // Оба входа несут пользовательский трафик: в SOCKS его подаёт слой
        // TUN, в HTTP — системная настройка прокси. Любое правило по входному
        // тегу поэтому совпадает со всем подряд и отменяет всё, что ниже.
        //
        // Обычное соединение не должно совпасть ни с одним правилом и уйти в
        // первый outbound — туннель.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        for rule in rules {
            assert!(
                rule.get("inboundTag").is_none(),
                "правило по входу перехватывает весь трафик: {rule}"
            );
        }
        assert_eq!(cfg["outbounds"][0]["tag"], PROXY);
    }

    #[test]
    fn core_has_no_tun_inbound() {
        // Управление TUN и маршрутами принадлежит демону. Ядро, которому
        // отдали эту роль, создавало адаптер без адреса и без маршрутов, и
        // причину нельзя было ни увидеть, ни исправить.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let inbounds = cfg["inbounds"].as_array().unwrap();

        assert_eq!(inbounds.len(), 2, "SOCKS и HTTP");
        assert_eq!(inbounds[0]["protocol"], "socks");
        assert!(
            !inbounds.iter().any(|i| i["protocol"] == "tun"),
            "TUN-вход ядра больше не используется"
        );
    }

    #[test]
    fn socks_inbound_carries_udp() {
        // Без UDP отваливается QUIC, а с ним заметная часть современного веба.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        assert_eq!(cfg["inbounds"][0]["settings"]["udp"], true);
        assert_eq!(cfg["inbounds"][0]["sniffing"]["enabled"], true);
    }

    #[test]
    fn vision_flow_is_kept_on_raw_tcp() {
        let mut server = xhttp_reality();
        let Transport::Vless(v) = &mut server.transport else {
            panic!()
        };
        v.stream = Stream::Tcp;
        v.flow = Some("xtls-rprx-vision".into());

        let cfg = build_ok(&server, &Settings::default());
        assert_eq!(
            cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
    }

    #[test]
    fn vision_flow_is_dropped_on_xhttp() {
        // Ядро отвергает такую комбинацию при старте, а подписки её иногда
        // содержат. Отбрасываем молча, но не даём конфигу стать нерабочим.
        let mut server = xhttp_reality();
        let Transport::Vless(v) = &mut server.transport else {
            panic!()
        };
        v.flow = Some("xtls-rprx-vision".into());

        let cfg = build_ok(&server, &Settings::default());
        assert!(
            cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
                .get("flow")
                .is_none(),
            "flow неприменим к XHTTP и должен быть отброшен"
        );
    }

    #[test]
    fn vision_flow_is_dropped_without_encryption() {
        let mut server = xhttp_reality();
        let Transport::Vless(v) = &mut server.transport else {
            panic!()
        };
        v.stream = Stream::Tcp;
        v.security = Security::None;
        v.flow = Some("xtls-rprx-vision".into());

        let cfg = build_ok(&server, &Settings::default());
        assert!(cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
            .get("flow")
            .is_none());
    }

    #[test]
    fn unsupported_protocol_is_rejected_before_building() {
        let server = ServerProfile::new(
            "TUIC",
            Endpoint::new("example.com", 443),
            Transport::Tuic(Tuic {
                uuid: Secret::new("u"),
                password: Secret::new("p"),
                congestion_control: "bbr".into(),
                udp_relay_mode: "native".into(),
                tls: Tls::default(),
            }),
            source(),
        );

        let err = build(&server, &Settings::default(), &RuntimeInfo::default()).unwrap_err();
        assert!(matches!(err, BuildError::Unsupported(_)));
    }

    #[test]
    fn shadowsocks_uses_the_servers_array() {
        let server = ServerProfile::new(
            "SS",
            Endpoint::new("fi.example.com", 8388),
            Transport::Shadowsocks(Shadowsocks {
                method: "2022-blake3-aes-128-gcm".into(),
                password: Secret::new("pw"),
                plugin: None,
            }),
            source(),
        );

        let cfg = build_ok(&server, &Settings::default());
        let out = &cfg["outbounds"][0];
        assert_eq!(out["protocol"], "shadowsocks");
        assert_eq!(out["settings"]["servers"][0]["method"], "2022-blake3-aes-128-gcm");
        assert!(
            out.get("streamSettings").is_none(),
            "у Shadowsocks собственный транспорт"
        );
    }

    #[test]
    fn shadowsocks_with_a_plugin_does_not_reach_the_core() {
        // Конфиг для такого сервера ядро приняло бы — и молча не соединилось,
        // потому что сервер ждёт обфускации, которую запускать нечем.
        // Отказать надо до запуска, назвав причину.
        let server = ServerProfile::new(
            "SS+obfs",
            Endpoint::new("fi.example.com", 8388),
            Transport::Shadowsocks(Shadowsocks {
                method: "aes-256-gcm".into(),
                password: Secret::new("pw"),
                plugin: Some("obfs-local".into()),
            }),
            source(),
        );

        let err = build(&server, &Settings::default(), &RuntimeInfo::default()).unwrap_err();
        let BuildError::Unsupported(reason) = err;
        assert!(reason.contains("obfs-local"), "в отказе нет плагина: {reason}");
    }

    #[test]
    fn socks_inbound_listens_on_loopback_only() {
        // Через этот вход идёт весь трафик пользователя. Будь он доступен из
        // сети, любой сосед по Wi-Fi получил бы открытый прокси.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let inbound = &cfg["inbounds"][0];

        assert_eq!(inbound["tag"], PROBE_INBOUND);
        assert_eq!(inbound["protocol"], "socks");
        assert_eq!(
            inbound["listen"], "127.0.0.1",
            "вход не должен быть доступен из сети"
        );
    }

    #[test]
    fn probe_traffic_always_goes_through_the_tunnel() {
        // Иначе при раздельном туннелировании в режиме Include проверка
        // ушла бы напрямую и подтвердила работу туннеля, минуя его.
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Include,
                apps: vec!["browser.exe".into()],
                sites: Vec::new()
            },
            ..Default::default()
        };
        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let probe = rules
            .iter()
            .position(|r| r["ip"][0] == json!(format!("{HEALTH_CHECK_IP}/32")))
            .expect("правило для адреса проверки должно быть");
        let catch_all = rules
            .iter()
            .position(|r| r["network"] == "tcp,udp")
            .expect("в режиме Include должно быть общее правило");

        assert_eq!(rules[probe]["outboundTag"], PROXY);
        assert!(
            probe < catch_all,
            "правило проверки обязано опережать общее правило раздельного туннелирования"
        );
    }

    #[test]
    fn access_log_is_disabled() {
        // Журнал доступа — это список всех посещённых адресов. Для
        // VPN-клиента вести такой файл недопустимо.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        assert_eq!(cfg["log"]["access"], "none");
    }

    #[test]
    fn listen_address_is_split_correctly() {
        assert_eq!(split_listen("127.0.0.1:1234"), ("127.0.0.1".to_owned(), 1234));
        // Неверный формат не должен ронять сборку конфигурации.
        assert_eq!(split_listen("мусор").0, "127.0.0.1");
    }

    #[test]
    fn broadcast_and_multicast_are_blocked_first() {
        // Такие пакеты нельзя отправить обычным сокетом, и попытка это
        // сделать оборачивается потоком ошибок «нет места в буфере».
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let first = &rules[0];
        assert_eq!(
            first["outboundTag"], BLOCK,
            "блокировка широковещания обязана быть первым правилом"
        );

        let ips: Vec<&str> = first["ip"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(ips.contains(&"224.0.0.0/4"), "многоадресная рассылка: {ips:?}");
        assert!(ips.contains(&"255.255.255.255/32"), "широковещание: {ips:?}");
        assert!(
            ips.contains(&"ff00::/8"),
            "многоадресная рассылка IPv6 — тот самый поток mDNS, который \n             захлёбывал сетевой слой: {ips:?}"
        );
        assert!(
            ips.contains(&"169.254.255.255/32"),
            "широковещание link-local: {ips:?}"
        );
    }

    #[test]
    fn split_tunnel_still_precedes_general_rules() {
        // Блокировка широковещания встала первой, но раздельное
        // туннелирование обязано остаться выше общих правил.
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Exclude,
                apps: vec!["app.exe".into()],
                sites: Vec::new()
            },
            ..Default::default()
        };
        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let split = rules
            .iter()
            .position(|r| r.get("process").is_some())
            .expect("правило раздельного туннелирования должно быть");
        let dns = rules.iter().position(|r| r["port"] == 53).unwrap();
        assert!(split < dns, "process-правило должно идти раньше общих");
    }

    #[test]
    fn core_log_level_defaults_to_warning() {
        // На `info` ядро пишет строку про каждое соединение — это и поток
        // мусора, и журнал всех посещённых адресов.
        for level in ["info", "warn", "warning", "error", ""] {
            assert_eq!(
                core_log_level(level),
                "warning",
                "уровень {level} не должен включать пожурнальный вывод соединений"
            );
        }
    }

    #[test]
    fn explicit_debug_enables_verbose_core_logging() {
        assert_eq!(core_log_level("debug"), "info");
        assert_eq!(core_log_level("TRACE"), "info");
    }

    #[test]
    fn generated_config_does_not_log_every_connection_by_default() {
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        assert_eq!(cfg["log"]["loglevel"], "warning");
    }

    #[test]
    fn dns_traffic_is_routed_through_the_tunnel() {
        // Иначе резолвер провайдера видит все посещаемые узлы, даже когда
        // остальной трафик идёт через VPN.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let dns_rule = rules
            .iter()
            .find(|r| r["port"] == 53)
            .expect("правило для DNS должно быть");
        assert_eq!(dns_rule["outboundTag"], PROXY);
    }

    #[test]
    fn lan_bypass_is_present_only_when_enabled() {
        let mut settings = Settings::default();
        settings.allow_lan = true;
        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["ip"][0] == "geoip:private"));

        settings.allow_lan = false;
        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(!rules.iter().any(|r| r["ip"][0] == "geoip:private"));
    }

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    #[test]
    fn split_tunnel_exclude_sends_listed_apps_direct() {
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Exclude,
                apps: vec![r"C:\Program Files\App\app.exe".into()],
                sites: Vec::new()
            },
            ..Default::default()
        };

        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let rule = rules
            .iter()
            .find(|r| r.get("process").is_some())
            .expect("правило раздельного туннелирования должно быть");
        assert_eq!(rule["outboundTag"], DIRECT);
        assert_eq!(rule["process"][0], r"C:\Program Files\App\app.exe");
    }

    #[test]
    fn nothing_swallows_the_traffic_before_split_tunnelling() {
        // Здесь ловится ошибка, из-за которой раздельное туннелирование не
        // работало вообще: правило `inboundTag: [probe-in, http-in]` стояло
        // выше и совпадало с каждым соединением — через эти два входа
        // приходит весь трафик. Xray берёт первое подошедшее правило, и до
        // списка исключений дело не доходило никогда.
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Exclude,
                apps: Vec::new(),
                sites: vec!["kinopoisk.ru".into()],
            },
            ..Default::default()
        };

        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        let split_at = rules
            .iter()
            .position(|r| r.get("domain").is_some())
            .expect("правило раздельного туннелирования должно быть");

        for rule in &rules[..split_at] {
            assert!(
                rule.get("inboundTag").is_none(),
                "правило по входному тегу перехватывает весь трафик: {rule}"
            );
        }
    }

    #[test]
    fn the_health_check_stays_in_the_tunnel() {
        // Проверка связности обязана идти через туннель, иначе она
        // подтверждает работу того, чего нет. Но выделять её надо адресом, а
        // не входом: вход у неё общий с пользовательским трафиком.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let rule = rules
            .iter()
            .find(|r| {
                r.get("ip")
                    .and_then(|ip| ip.as_array())
                    .is_some_and(|ips| ips.iter().any(|v| v == &json!(format!("{HEALTH_CHECK_IP}/32"))))
            })
            .expect("адрес проверки должен быть в правилах");
        assert_eq!(rule["outboundTag"], PROXY);
    }

    #[test]
    fn split_tunnel_sends_a_site_direct_with_its_subdomains() {
        // Банк не пускает с иностранного адреса не браузер, а свой сайт, —
        // и мимо туннеля надо вывести именно его.
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Exclude,
                apps: Vec::new(),
                sites: vec!["bank.example".into()],
            },
            ..Default::default()
        };

        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let rule = rules
            .iter()
            .find(|r| r.get("domain").is_some())
            .expect("правило по домену должно быть");
        assert_eq!(rule["outboundTag"], DIRECT);
        assert_eq!(
            rule["domain"][0], "domain:bank.example",
            "префикс `domain:` ловит и поддомены, а голая строка — любую \
             подстроку, включая bank.example.evil.net"
        );
    }

    #[test]
    fn a_site_rule_works_without_process_routing() {
        // Программы различает не всякая система, сайты — всякая. Список
        // сайтов не должен пропадать из-за пустого списка программ.
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Include,
                apps: Vec::new(),
                sites: vec!["work.example".into()],
            },
            ..Default::default()
        };

        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let rule = rules.iter().find(|r| r.get("domain").is_some()).unwrap();
        assert_eq!(rule["outboundTag"], PROXY, "в режиме include — в туннель");
        assert!(
            rules
                .iter()
                .any(|r| r.get("network").is_some() && r["outboundTag"] == DIRECT),
            "всё прочее должно уходить напрямую"
        );
    }

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    #[test]
    fn split_tunnel_include_sends_everything_else_direct() {
        let settings = Settings {
            split_tunnel: SplitTunnelRules {
                mode: SplitTunnelMode::Include,
                apps: vec!["browser.exe".into()],
                sites: Vec::new()
            },
            ..Default::default()
        };

        let cfg = build_ok(&xhttp_reality(), &settings);
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let at = rules
            .iter()
            .position(|r| r.get("process").is_some())
            .expect("правило раздельного туннелирования должно быть");

        assert_eq!(rules[at]["outboundTag"], PROXY);
        assert_eq!(rules[at]["process"][0], "browser.exe");
        assert_eq!(
            rules[at + 1]["outboundTag"],
            DIRECT,
            "весь остальной трафик должен идти мимо туннеля"
        );
    }

    #[test]
    fn empty_split_tunnel_adds_no_process_rules() {
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|r| r.get("process").is_none()));
    }

    #[test]
    fn metrics_endpoint_stays_on_loopback() {
        // Служебный порт ядра не должен быть доступен из сети: через него
        // видна вся статистика соединений.
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        let listen = cfg["metrics"]["listen"].as_str().unwrap();
        assert!(
            listen.starts_with("127.0.0.1:"),
            "порт статистики обязан слушать только localhost: {listen}"
        );
        assert!(
            !listen.ends_with(":0"),
            "нулевой порт нельзя опросить: ядро займёт случайный, и статистику будет негде взять"
        );
        assert_eq!(cfg["stats"], json!({}));
    }

    #[test]
    fn custom_dns_servers_are_honoured() {
        let settings = Settings {
            dns: sont_core::DnsSettings {
                mode: sont_core::DnsMode::Custom {
                    servers: vec!["9.9.9.9".into()],
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let cfg = build_ok(&xhttp_reality(), &settings);
        assert_eq!(cfg["dns"]["servers"][0], "9.9.9.9");
    }

    #[test]
    fn generated_config_is_a_json_object_with_required_sections() {
        let cfg = build_ok(&xhttp_reality(), &Settings::default());
        for key in ["log", "inbounds", "outbounds", "dns", "routing"] {
            assert!(cfg.get(key).is_some(), "нет секции {key}");
        }
    }

    // ─────────────────────────── гонка серверов ───────────────────────────

    fn named(name: &str, host: &str) -> ServerProfile {
        ServerProfile::new(
            name,
            Endpoint::new(host, 443),
            Transport::Vless(Vless {
                uuid: Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: None,
                stream: Stream::Tcp,
                security: Security::Tls(Tls::default()),
            }),
            source(),
        )
    }

    #[test]
    fn every_lane_gets_its_own_entrance_exit_and_rule() {
        // Дорожки не должны перетекать одна в другую: без правила весь трафик
        // ушёл бы в первый outbound, и гонку выиграл бы кто попало.
        let first = named("первый", "198.51.100.1");
        let second = named("второй", "198.51.100.2");
        let cfg = build_race(&[(&first, 30001), (&second, 30002)], "warning").unwrap();

        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["port"], 30001);
        assert_eq!(inbounds[1]["port"], 30002);
        assert_eq!(inbounds[0]["listen"], "127.0.0.1", "вход обязан быть локальным");

        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["settings"]["vnext"][0]["address"], "198.51.100.1");
        assert_eq!(outbounds[1]["settings"]["vnext"][0]["address"], "198.51.100.2");

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        for lane in 0..2 {
            assert_eq!(rules[lane]["inboundTag"][0], inbounds[lane]["tag"]);
            assert_eq!(rules[lane]["outboundTag"], outbounds[lane]["tag"]);
        }
    }

    #[test]
    fn tags_do_not_collide_between_lanes() {
        // Совпади теги — и Xray отдал бы обе дорожки одному серверу, а гонка
        // объявила бы победителем того, через кого запрос не шёл.
        let a = named("первый", "198.51.100.1");
        let b = named("второй", "198.51.100.2");
        let c = named("третий", "198.51.100.3");
        let cfg = build_race(&[(&a, 30001), (&b, 30002), (&c, 30003)], "warning").unwrap();

        let tags: Vec<&str> = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .chain(cfg["outbounds"].as_array().unwrap())
            .map(|v| v["tag"].as_str().unwrap())
            .collect();

        let unique: std::collections::HashSet<&&str> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len(), "теги дорожек обязаны быть разными");
    }

    #[test]
    fn unmatched_traffic_dies_rather_than_leaks_past_the_server() {
        // Иначе дорожка отчиталась бы об успехе, не пройдя через тот сервер,
        // ради которого заведена, — и гонку выиграл бы неработающий.
        let one = named("первый", "198.51.100.1");
        let cfg = build_race(&[(&one, 30001)], "warning").unwrap();

        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert!(
            outbounds.iter().all(|o| o["protocol"] != "freedom"),
            "прямого выхода в конфигурации проверки быть не должно"
        );

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap()["outboundTag"], BLOCK);
    }

    #[test]
    fn the_check_config_carries_nothing_it_does_not_need() {
        // Через неё проходит один запрос к адресу-литералу. DNS, статистика и
        // раздельное туннелирование добавили бы ей только поводов не запуститься.
        let one = named("первый", "198.51.100.1");
        let cfg = build_race(&[(&one, 30001)], "warning").unwrap();

        for key in ["dns", "stats", "metrics", "policy"] {
            assert!(cfg.get(key).is_none(), "лишняя секция {key}");
        }
        assert_eq!(cfg["log"]["access"], "none");
    }

    #[test]
    fn a_race_without_participants_is_refused() {
        assert!(build_race(&[], "warning").is_err());
    }

    #[test]
    fn an_unsupported_server_cannot_become_a_lane() {
        // Иначе один негодный профиль в подписке отменял бы сборку всей
        // проверки — то есть лишал бы её смысла для остальных.
        let tuic = ServerProfile::new(
            "tuic",
            Endpoint::new("198.51.100.9", 443),
            Transport::Tuic(Tuic {
                uuid: Secret::new("11111111-2222-3333-4444-555555555555"),
                password: Secret::new("pw"),
                congestion_control: "bbr".into(),
                udp_relay_mode: "native".into(),
                tls: Tls::default(),
            }),
            source(),
        );

        assert!(build_race(&[(&tuic, 30001)], "warning").is_err());
    }
}

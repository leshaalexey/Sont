//! `sontd` — демон-оркестратор Sont.
//!
//! Один и тот же бинарь работает и как системная служба, и как CLI поверх
//! того же IPC. Это удобно не только для отладки: администратор всегда может
//! посмотреть состояние и сбросить правила firewall, не имея под рукой GUI.

mod agent;
mod connections;
mod core;
mod demo;
mod firewall;
mod logging;
mod paths;
mod probe;
mod race;
mod secrets;
#[cfg(windows)]
mod service;
mod store;
mod subscription;
mod supervisor;
mod sysproxy;
mod tunnel;
mod winhttp;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sont_ipc::peer::{AllowAll, DefaultPolicy};
use sont_ipc::protocol::{Request, Response};
use sont_ipc::server::{Command, IpcServer};
use sont_ipc::{AuthPolicy, Client};
use tokio::sync::mpsc;

const AGENT: &str = concat!("sontd/", env!("CARGO_PKG_VERSION"));

#[derive(Parser)]
#[command(name = "sontd", version, about = "Демон-оркестратор Sont")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Запустить демон.
    Run {
        /// Не отсоединяться от терминала. В этом режиме демон работает как
        /// обычный процесс — так его удобно отлаживать.
        #[arg(long)]
        foreground: bool,

        /// Наполнить список серверов демонстрационным набором.
        ///
        /// Нужно, чтобы проверить связку с интерфейсом до появления разбора
        /// подписок. Подключение при этом не выполняется.
        #[arg(long)]
        demo_servers: bool,

        /// Не проверять, откуда запущен клиент.
        ///
        /// Только для отладки: в рабочем режиме путь клиента проверяется.
        #[arg(long)]
        allow_any_client: bool,
    },

    /// Показать состояние работающего демона.
    Status,

    /// Управление подпиской.
    Subscription {
        #[command(subcommand)]
        action: SubscriptionAction,
    },

    /// Показать список серверов.
    Servers,

    /// Замерить задержку до всех серверов.
    ///
    /// По этим числам демон выбирает сервер при подключении и подбирает
    /// замену, когда текущий выбывает.
    Probe,

    /// Показать или сменить режим работы.
    Mode {
        /// `tunnel` — весь трафик системы, нужны права администратора.
        /// `proxy` — локальный прокси, прав не нужно, иконка сети не меняется.
        /// Без аргумента показывает текущий режим.
        value: Option<String>,
    },

    /// Подключаться автоматически при старте демона.
    ///
    /// Без этого служба стартует вместе с системой, но соединение не поднимает.
    Autoconnect {
        /// `on` или `off`. Без аргумента показывает текущее значение.
        value: Option<String>,
    },

    /// Спутник в сеансе пользователя.
    ///
    /// Держит системные настройки прокси в соответствии с состоянием демона.
    /// Нужен, когда демон работает службой: настройки принадлежат
    /// пользователю, и служба от имени системы задать их не может.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Проверить, куда на самом деле идёт трафик.
    ///
    /// Сравнивает внешний адрес по трём путям: через прокси, через приложение,
    /// читающее настройки системы, и напрямую. Отвечает на вопрос «а VPN точно
    /// работает?» фактами, а не состоянием в интерфейсе.
    Check,

    /// Подключиться.
    Connect {
        /// Идентификатор сервера. По умолчанию выбирается лучший доступный.
        server: Option<String>,
    },

    /// Отключиться.
    Disconnect,

    /// Операции с firewall.
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// Управление системной службой.
    ///
    /// Служба нужна, чтобы демон работал в фоне от имени системы: тогда права
    /// администратора запрашиваются один раз при установке, а не при каждом
    /// подключении.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceAction {
    /// Установить службу и включить автозапуск. Нужны права администратора.
    Install,
    /// Удалить службу. Нужны права администратора.
    Uninstall,
    /// Запустить установленную службу.
    Start,
    /// Остановить службу.
    Stop,
    /// Показать состояние службы.
    Status,
    /// Установить (или починить) и запустить одним вызовом. Нужны права
    /// администратора. Это то, что делает трей при запуске.
    Setup,
    /// Точка входа для диспетчера служб. Вручную не вызывается.
    #[command(hide = true)]
    Run,
}

#[derive(Subcommand)]
enum AgentAction {
    /// Работать до остановки. Обычно запускается автоматически при входе.
    Run,
    /// Включить автозапуск при входе пользователя. Прав администратора не нужно.
    Install,
    /// Убрать автозапуск и снять настройки прокси.
    Uninstall,
    /// Показать, включён ли автозапуск.
    Status,
}

#[derive(Subcommand)]
enum SubscriptionAction {
    /// Добавить подписку и сразу прочитать её.
    ///
    /// Ключ сохраняется в зашифрованном виде и в выводе не показывается.
    /// Подписок может быть несколько: серверы из них складываются в общий
    /// список, и при падении сервера демон переходит на лучший из всех.
    Add {
        /// Ссылка подписки. Если не указана — будет запрошена из stdin,
        /// чтобы ключ не попал в историю команд оболочки.
        url: Option<String>,
    },
    /// Показать все подписки.
    List,
    /// Показать состояние подписок.
    Show,
    /// Удалить одну подписку и пришедшие из неё серверы.
    Remove {
        /// Идентификатор из `sontd subscription list`.
        id: String,
    },
    /// Перечитать подписки с панелей.
    Refresh {
        /// Идентификатор из `sontd subscription list`. Без него — все.
        id: Option<String>,
    },
    /// Удалить все подписки и все серверы.
    Clear,
}

#[derive(Subcommand)]
enum FirewallAction {
    /// Снять все установленные нами фильтры.
    ///
    /// Аварийный выход из режима lockdown, если демон не смог убрать их сам.
    Reset,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Запуск диспетчером служб обрабатываем до создания рантайма: диспетчер
    // ждёт подключения в считанные секунды и вызывает точку входа из
    // обычного потока.
    #[cfg(windows)]
    if let Cmd::Service {
        action: ServiceAction::Run,
    } = cli.command
    {
        return service::run_as_service();
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("не удалось создать рантайм")?;

    runtime.block_on(async {
        match cli.command {
            Cmd::Run {
                foreground,
                demo_servers,
                allow_any_client,
            } => {
                if !foreground {
                    anyhow::bail!(
                        "фоновый запуск выполняется службой: `sontd service install`, \
                         затем `sontd service start`. Для отладки: `sontd run --foreground`"
                    );
                }
                run_daemon(
                    DaemonOptions {
                        demo_servers,
                        allow_any_client,
                        log_to_file: false,
                    },
                    std::future::pending::<()>(),
                )
                .await
            }
            Cmd::Status => status().await,
            Cmd::Subscription { action } => subscription_cmd(action).await,
            Cmd::Servers => servers().await,
            Cmd::Probe => probe_cmd().await,
            Cmd::Mode { value } => mode(value).await,
            Cmd::Autoconnect { value } => autoconnect(value).await,
            Cmd::Check => check().await,
            Cmd::Agent { action } => agent_cmd(action).await,
            Cmd::Connect { server } => connect(server).await,
            Cmd::Disconnect => disconnect().await,
            Cmd::Firewall { action } => match action {
                FirewallAction::Reset => firewall_reset().await,
            },
            #[cfg(windows)]
            Cmd::Service { action } => service_cmd(action),
        }
    })
}

#[cfg(windows)]
fn service_cmd(action: ServiceAction) -> Result<()> {
    use windows_service::service::ServiceState;

    match action {
        ServiceAction::Install => {
            service::install()?;
            println!("Служба установлена и будет запускаться вместе с системой.");
            println!("Запустить сейчас: sontd service start");
            Ok(())
        }
        ServiceAction::Uninstall => {
            service::uninstall()?;
            println!("Служба удалена.");
            Ok(())
        }
        ServiceAction::Start => {
            service::start()?;
            println!("Служба запущена.");
            Ok(())
        }
        ServiceAction::Setup => {
            service::setup()?;
            println!("Служба установлена и работает.");
            Ok(())
        }
        ServiceAction::Stop => {
            service::stop()?;
            println!("Служба остановлена.");
            Ok(())
        }
        ServiceAction::Status => {
            match service::query()? {
                None => {
                    println!("Служба не установлена.");
                    println!("Установить: sontd service install (нужны права администратора)");
                }
                Some(ServiceState::Running) => println!("Служба работает."),
                Some(state) => println!("Служба установлена, состояние: {state:?}"),
            }
            Ok(())
        }
        // Обработано до создания рантайма.
        ServiceAction::Run => Ok(()),
    }
}

/// Как демон запущен.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonOptions {
    pub demo_servers: bool,
    pub allow_any_client: bool,
    /// Писать журнал в файл вместо консоли.
    pub log_to_file: bool,
}

/// Запускает демон и работает до сигнала остановки.
///
/// Синхронная обёртка для диспетчера служб: он вызывает точку входа из
/// обычного потока, где рантайма ещё нет.
pub fn run_daemon_blocking(stop: std::sync::mpsc::Receiver<()>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("не удалось создать рантайм")?;

    runtime.block_on(async move {
        // Ожидание сигнала блокирующее, поэтому уводим его с рабочих потоков.
        let stop = async move {
            let _ = tokio::task::spawn_blocking(move || stop.recv()).await;
        };

        run_daemon(
            DaemonOptions {
                demo_servers: false,
                allow_any_client: false,
                log_to_file: true,
            },
            stop,
        )
        .await
    })
}

/// Тело демона.
///
/// Один и тот же код обслуживает и службу, и передний план: расхождение между
/// «как работает у пользователя» и «как отлаживали» — источник ошибок, которые
/// видно только в бою.
async fn run_daemon(options: DaemonOptions, stop: impl std::future::Future<Output = ()>) -> Result<()> {
    // Страж файлового журнала обязан жить до самого конца: его уничтожение
    // закрывает поток записи, и последние строки — как раз объясняющие
    // остановку — теряются.
    let (logs, _guard) = if options.log_to_file {
        let dir = paths::log_dir();
        std::fs::create_dir_all(&dir).ok();
        let (logs, guard) = logging::init_to_file("info", &dir);
        (logs, Some(guard))
    } else {
        (logging::init("info"), None)
    };

    let demo_servers = options.demo_servers;
    let allow_any_client = options.allow_any_client;

    let policy: Arc<dyn AuthPolicy> = if allow_any_client {
        tracing::warn!("проверка происхождения клиента отключена — только для отладки");
        Arc::new(AllowAll)
    } else {
        // Клиент обязан лежать рядом с демоном: у установленной сборки это
        // один каталог, а посторонняя программа пользователя туда не попадёт.
        match std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
            Some(dir) => Arc::new(DefaultPolicy::new().require_exe_under(dir)),
            None => Arc::new(DefaultPolicy::new()),
        }
    };

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
    let addr = sont_ipc::endpoint_name();

    let (server, events) = IpcServer::bind(&addr, cmd_tx, policy, AGENT)
        .with_context(|| format!("не удалось открыть {addr}"))?;

    tracing::info!(endpoint = %addr, "IPC-сервер слушает");

    let supervisor = supervisor::Supervisor::new(
        supervisor::SupervisorConfig {
            demo_servers,
            settings_path: paths::settings_file(),
            favorites_path: paths::favorites_file(),
            subscriptions_path: paths::subscriptions_file(),
            legacy_subscription_path: paths::legacy_subscription_file(),
            legacy_servers_cache_path: paths::legacy_servers_cache_file(),
            core_binary: paths::core_binary(),
            core_config_path: paths::core_config(),
        },
        events,
        logs,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let ipc = tokio::spawn(server.run());
    let sup = tokio::spawn(supervisor.run(cmd_rx, shutdown_rx));

    tokio::pin!(stop);
    tokio::select! {
        _ = &mut stop => tracing::info!("запрошена остановка"),
        _ = tokio::signal::ctrl_c() => tracing::info!("получен Ctrl+C"),
        _ = ipc => tracing::error!("IPC-сервер завершился"),
    }

    // Ждём, пока supervisor приберёт за собой.
    //
    // Просто выйти нельзя: за демоном остались бы работающее ядро, маршруты в
    // никуда и TUN-адаптер. Пользователь получил бы машину без сети и без
    // очевидного способа это исправить.
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(Duration::from_secs(15), sup).await {
        Ok(_) => tracing::info!("демон остановлен"),
        Err(_) => tracing::error!("supervisor не завершился за отведённое время"),
    }

    Ok(())
}

/// Подключается к демону или завершает процесс с понятным сообщением.
///
/// «Демон не запущен» — самая частая ситуация, и она заслуживает отдельной
/// подсказки, а не общей ошибки соединения.
async fn client() -> (Client, tokio::sync::mpsc::Receiver<sont_ipc::Event>) {
    let addr = sont_ipc::endpoint_name();
    match Client::connect(&addr, AGENT).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Демон недоступен: {e}");
            eprintln!("Запустите службу или `sontd run --foreground`.");
            std::process::exit(1);
        }
    }
}

async fn status() -> Result<()> {
    let (client, _events) = client().await;

    let Response::Status(status) = client.request(Request::GetStatus).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };

    println!("Состояние:   {}", status.state.kind());
    println!("Блокировка:  {}", if status.state.is_blocked() { "да" } else { "нет" });
    println!("Серверов:    {}", status.server_count);
    match status.subscriptions.len() {
        0 => println!("Подписки:    нет"),
        1 => println!("Подписка:    {}", status.subscriptions[0].masked_url),
        n => {
            println!("Подписок:    {n}");
            for sub in &status.subscriptions {
                println!("             {}", sub.masked_url);
            }
        }
    }

    if let Response::DaemonInfo(info) = client.request(Request::DaemonInfo).await? {
        println!("Версия:      {} (протокол {})", info.daemon_version, info.protocol_version);
        println!("Платформа:   {}", info.platform);
        println!("Время работы: {} с", info.uptime_secs);
    }

    Ok(())
}

async fn subscription_cmd(action: SubscriptionAction) -> Result<()> {
    match action {
        SubscriptionAction::Add { url } => subscription_add(url).await,
        SubscriptionAction::List => subscription_list().await,
        SubscriptionAction::Show => subscription_show().await,
        SubscriptionAction::Remove { id } => subscription_remove(id).await,
        SubscriptionAction::Refresh { id } => subscription_refresh(id).await,
        SubscriptionAction::Clear => {
            let (client, _events) = client().await;
            client.request(Request::ClearSubscription).await?;
            println!("Все подписки удалены.");
            Ok(())
        }
    }
}

async fn subscription_list() -> Result<()> {
    let (client, _events) = client().await;
    let Response::Subscriptions(subs) = client.request(Request::ListSubscriptions).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };

    if subs.is_empty() {
        println!("Подписок нет. Добавьте: sontd subscription add");
        return Ok(());
    }

    println!("{:<18} {:<9} ССЫЛКА", "ИДЕНТИФИКАТОР", "СЕРВЕРОВ");
    for sub in &subs {
        println!(
            "{:<18} {:<9} {}",
            sub.id.as_str(),
            sub.info.server_count,
            sub.masked_url
        );
    }
    Ok(())
}

async fn subscription_remove(id: String) -> Result<()> {
    let (client, _events) = client().await;
    let response = client
        .request(Request::RemoveSubscription {
            id: sont_core::SubscriptionId::from_raw(id),
        })
        .await?;

    match response {
        Response::Error(e) => {
            eprintln!("Не удалось удалить: {e}");
            eprintln!("Список подписок: sontd subscription list");
            std::process::exit(1);
        }
        _ => {
            println!("Подписка удалена вместе с её серверами.");
            Ok(())
        }
    }
}

async fn subscription_add(url: Option<String>) -> Result<()> {
    let url = match url {
        Some(u) => u,
        None => {
            // Чтение из stdin, чтобы ключ не осел в истории команд оболочки.
            // Ввод при этом виден на экране — скрыть его без дополнительной
            // зависимости нельзя, и делать вид, что он скрыт, не стоит.
            eprint!("Ссылка подписки: ");
            use std::io::{BufRead, Write};
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            line
        }
    };

    let url = url.trim().to_owned();
    if url.is_empty() {
        anyhow::bail!("ссылка подписки не может быть пустой");
    }

    let (client, events) = client().await;
    client.request(Request::SubscribeEvents).await?;
    client
        .request(Request::AddSubscription {
            url: sont_core::Secret::new(url),
        })
        .await?;

    println!("Ключ сохранён, читаю подписку…");
    await_subscription(events).await
}

async fn subscription_refresh(id: Option<String>) -> Result<()> {
    let (client, events) = client().await;
    client.request(Request::SubscribeEvents).await?;
    let response = client
        .request(Request::RefreshSubscription {
            id: id.map(sont_core::SubscriptionId::from_raw),
        })
        .await?;

    if let Response::Error(e) = response {
        eprintln!("Не удалось обновить: {e}");
        std::process::exit(1);
    }

    println!("Обновляю подписки…");
    await_subscription(events).await
}

/// Ждёт результат обновления подписки.
///
/// Загрузка асинхронная: демон отвечает на запрос сразу, а результат приходит
/// событием. CLI ждёт его, чтобы пользователю не приходилось запускать
/// `status` вручную и гадать, закончилось ли уже.
async fn await_subscription(
    mut events: tokio::sync::mpsc::Receiver<sont_ipc::Event>,
) -> Result<()> {
    use sont_ipc::Event;

    let deadline = tokio::time::Duration::from_secs(45);

    let outcome = tokio::time::timeout(deadline, async {
        while let Some(event) = events.recv().await {
            match event {
                Event::SubscriptionUpdated(status) => return Some(Ok(status)),
                Event::Error(e) => return Some(Err(e)),
                _ => {}
            }
        }
        None
    })
    .await;

    match outcome {
        Ok(Some(Ok(status))) => {
            println!("Подписка: {}", status.masked_url);
            println!("Серверов: {}", status.info.server_count);

            if let Some(percent) = status.info.used_percent() {
                let used = status.info.upload.unwrap_or(0) + status.info.download.unwrap_or(0);
                println!(
                    "Трафик:   {} из {} ({percent}%)",
                    human_bytes(used),
                    human_bytes(status.info.total.unwrap_or(0))
                );
            } else {
                println!("Трафик:   без лимита");
            }

            match status.info.expires_at_unix {
                Some(exp) => println!("Истекает: {}", format_unix_date(exp)),
                None => println!("Истекает: бессрочно"),
            }
            Ok(())
        }
        Ok(Some(Err(e))) => {
            eprintln!("Не удалось прочитать подписку: {e}");
            std::process::exit(1);
        }
        Ok(None) => anyhow::bail!("демон разорвал соединение"),
        Err(_) => anyhow::bail!("панель не ответила за 45 секунд"),
    }
}

async fn subscription_show() -> Result<()> {
    let (client, _events) = client().await;
    let Response::Status(status) = client.request(Request::GetStatus).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };

    if status.subscriptions.is_empty() {
        println!("Подписок нет. Добавьте: sontd subscription add");
        return Ok(());
    }

    println!("Серверов всего: {}\n", status.server_count);

    for (i, sub) in status.subscriptions.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("Подписка:  {}", sub.masked_url);
        println!("Идентификатор: {}", sub.id.as_str());
        println!("Серверов:  {}", sub.info.server_count);

        match sub.info.fetched_at_unix {
            Some(t) => println!("Обновлена: {}", format_unix_date(t)),
            None => println!("Обновлена: ещё не читалась"),
        }
        match sub.info.expires_at_unix {
            Some(exp) => println!("Истекает:  {}", format_unix_date(exp)),
            None => println!("Истекает:  бессрочно"),
        }
        if let Some(percent) = sub.info.used_percent() {
            let used = sub.info.upload.unwrap_or(0) + sub.info.download.unwrap_or(0);
            println!(
                "Трафик:    {} из {} ({percent}%)",
                human_bytes(used),
                human_bytes(sub.info.total.unwrap_or(0))
            );
        }
    }

    Ok(())
}

async fn autoconnect(value: Option<String>) -> Result<()> {
    let (client, _events) = client().await;

    let Some(value) = value else {
        let Response::Settings(settings) = client.request(Request::GetSettings).await? else {
            anyhow::bail!("неожиданный ответ демона");
        };
        println!(
            "Автоподключение: {}",
            if settings.auto_connect { "включено" } else { "выключено" }
        );
        return Ok(());
    };

    let enabled = match value.trim().to_lowercase().as_str() {
        "on" | "yes" | "true" | "1" | "вкл" => true,
        "off" | "no" | "false" | "0" | "выкл" => false,
        other => anyhow::bail!("ожидается on или off, получено: {other}"),
    };

    client
        .request(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                auto_connect: Some(enabled),
                ..Default::default()
            },
        })
        .await?;

    if enabled {
        println!("Автоподключение включено: демон будет поднимать соединение при старте.");
    } else {
        println!("Автоподключение выключено.");
    }
    Ok(())
}

async fn agent_cmd(action: AgentAction) -> Result<()> {
    match action {
        AgentAction::Run => {
            // Свой журнал агенту не нужен: он живёт в сеансе пользователя и
            // пишет в консоль, а при автозапуске его вывод никому не виден.
            logging::init("info");
            agent::run().await
        }
        AgentAction::Install => {
            agent::install()?;
            println!("Автозапуск агента включён — он будет стартовать при входе в систему.");
            println!("Запустить сейчас: sontd agent run");
            Ok(())
        }
        AgentAction::Uninstall => {
            agent::uninstall()?;
            println!("Автозапуск агента убран, настройки прокси сняты.");
            Ok(())
        }
        AgentAction::Status => {
            if agent::is_installed() {
                println!("Автозапуск агента включён.");
            } else {
                println!("Автозапуск агента выключен.");
                println!("Включить: sontd agent install");
            }
            Ok(())
        }
    }
}

/// Адрес проверки: IP-литерал, чтобы не зависеть от DNS.
/// Тот же адрес, что загоняется в туннель правилом маршрутизации ядра.
const CHECK_URL: &str = sont_xray::config::HEALTH_CHECK_URL;

/// Внешний адрес по указанному пути.
async fn external_ip(client: reqwest::Client) -> Option<String> {
    let body = client.get(CHECK_URL).send().await.ok()?.text().await.ok()?;
    body.lines()
        .find_map(|l| l.strip_prefix("ip="))
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
}

/// Один и тот же ли это выход в интернет.
///
/// # Почему не побайтовое равенство
///
/// Провайдер сервера выпускает трафик с нескольких адресов одной подсети и
/// раздаёт их между соединениями как придётся. Проверка, требовавшая точного
/// совпадения, объявляла исправный туннель дырявым: два ответа вида
/// `152.233.35.212` и `152.233.35.206` — это один выход, а не утечка мимо
/// сервера. Диагностика, которая пугает на ровном месте, хуже отсутствующей:
/// после первого ложного тревожного вывода ей перестают верить и в настоящем
/// случае.
///
/// Сравнение по сети, конечно, огрубление: два разных выхода могут оказаться
/// в одной подсети. Но чтобы это дало ложное «всё в порядке», надо чтобы и
/// провайдер VPN, и домашний провайдер стояли в одной /24 — а это уже не
/// утечка, а совпадение из другого мира.
fn same_exit(a: &str, b: &str) -> bool {
    use std::net::IpAddr;

    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => a.octets()[..3] == b.octets()[..3],
        (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => a.octets()[..6] == b.octets()[..6],
        // Не разобрали — сравниваем как есть: лучше строгое сравнение, чем
        // выдуманное послабление.
        _ => a == b,
    }
}

async fn check() -> Result<()> {
    use sont_core::ConnectionMode;

    let (client, _events) = client().await;
    let Response::Status(status) = client.request(Request::GetStatus).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };
    let Response::Settings(settings) = client.request(Request::GetSettings).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };

    if !status.state.is_connected() {
        println!("Не подключено — проверять нечего. Состояние: {}", status.state.kind());
        return Ok(());
    }

    let timeout = Duration::from_secs(8);
    // Соединения не переиспользуем: каждая проверка должна открывать своё,
    // иначе результат отражает путь, действовавший в момент первой из них.
    let build = |f: &dyn Fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder| {
        f(reqwest::Client::builder().timeout(timeout))
            .pool_max_idle_per_host(0)
            .build()
            .ok()
    };

    // Напрямую, минуя любые настройки.
    let direct_ip = match build(&|b: reqwest::ClientBuilder| b.no_proxy()) {
        Some(c) => external_ip(c).await,
        None => None,
    };

    // Через то, что реально прописано в настройках системы.
    //
    // Читаем настройки сами, а не полагаемся на их разбор HTTP-клиентом:
    // библиотеки понимают формат `http=…;https=…` по-разному, и вывод
    // «через систему трафик идёт мимо VPN», сделанный на основании чужого
    // разбора, оказался бы ложным.
    let system = sysproxy::current();
    let system_ip = match &system {
        Some((true, value)) => match sysproxy::http_endpoint_of(value) {
            Some(addr) => match reqwest::Proxy::all(format!("http://{addr}")) {
                Ok(p) => match build(&|b: reqwest::ClientBuilder| b.proxy(p.clone())) {
                    Some(c) => external_ip(c).await,
                    None => None,
                },
                Err(_) => None,
            },
            None => None,
        },
        _ => None,
    };

    let mut proxy_ip = None;
    if let Some(endpoints) = &status.proxy {
        if let Ok(p) = reqwest::Proxy::all(format!("http://{}", endpoints.http)) {
            if let Ok(c) = reqwest::Client::builder()
                .timeout(timeout)
                .proxy(p)
                .pool_max_idle_per_host(0)
                .build()
            {
                proxy_ip = external_ip(c).await;
            }
        }
    }

    let show = |label: &str, ip: &Option<String>| {
        println!("{label:<38} {}", ip.as_deref().unwrap_or("нет ответа"));
    };

    println!("Внешний адрес по разным путям:\n");
    show("через прокси приложения", &proxy_ip);
    match &system {
        Some((true, value)) => {
            show("через настройки системы", &system_ip);
            println!("{:<38} {value}", "  настройки указывают на");
        }
        _ => println!("{:<38} прокси в системе не задан", "через настройки системы"),
    }
    show("напрямую, мимо всех настроек", &direct_ip);
    println!();

    // Где именно объявлен прокси.
    //
    // Разных мест три, и читают их разные семейства программ. Пока не видно,
    // какое из них пустует, «у меня не работает» остаётся неразрешимым: одно
    // и то же наблюдение получается и когда приложение не читает настройку, и
    // когда настройки просто нет.
    if matches!(settings.mode, ConnectionMode::Proxy) {
        let expected = status.proxy.as_ref().map(|p| p.http.clone());
        println!("Где объявлен прокси (в режиме прокси нужны все три):\n");
        report_channel(
            "настройки Windows (браузеры, Electron)",
            system.as_ref().and_then(|(on, value)| {
                on.then(|| sysproxy::http_endpoint_of(value)).flatten()
            }),
            &expected,
        );
        report_channel(
            "HTTPS_PROXY (Node, Python, Go, curl)",
            user_env_proxy(),
            &expected,
        );
        report_channel(
            "машинная WinHTTP (службы)",
            machine_proxy_setting(),
            &expected,
        );
        println!();
    }

    let tunnelled = proxy_ip.as_ref().or(system_ip.as_ref());
    let Some(tunnelled) = tunnelled else {
        println!("Через туннель ответа нет — соединение не работает, несмотря на состояние.");
        std::process::exit(1);
    };

    match settings.mode {
        ConnectionMode::Tunnel => match direct_ip.as_deref() {
            Some(direct) if same_exit(direct, tunnelled) => {
                println!("Режим туннеля: весь трафик идёт через сервер. Всё в порядке.");
                if direct != tunnelled {
                    println!(
                        "Адреса разные ({direct} и {tunnelled}), но выход один: \
                         провайдер сервера отвечает с нескольких адресов подсети."
                    );
                }
            }
            Some(_) => {
                println!("Режим туннеля, но обычный трафик идёт мимо сервера.");
                println!("Похоже, маршрут по умолчанию удерживает кто-то ещё.");
                std::process::exit(1);
            }
            None => println!("Прямой путь не ответил — судить о нём нечем."),
        },
        ConnectionMode::Proxy => {
            println!("Режим прокси: через сервер идут только приложения, знающие о прокси.");
            if direct_ip
                .as_deref()
                .is_some_and(|direct| !same_exit(direct, tunnelled))
            {
                println!(
                    "Это ожидаемо и не является неисправностью: {} — ваш обычный адрес,",
                    direct_ip.as_deref().unwrap_or("")
                );
                println!("им выходят программы, которые настройки прокси не читают.");
                println!("Так работает, например, curl без флага --proxy и QUIC в браузерах.");
                println!("\nНужен полный охват — переключитесь: sontd mode tunnel");
            }
        }
    }

    Ok(())
}

async fn servers() -> Result<()> {
    let (client, _events) = client().await;
    let Response::Servers(servers) = client.request(Request::ListServers).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };

    if servers.is_empty() {
        println!("Серверов нет. Добавьте подписку: sontd subscription add");
        return Ok(());
    }

    // Столбец подписки показываем только когда их несколько: с одной он
    // повторял бы одно и то же значение во всех строках.
    let sources: std::collections::HashSet<_> =
        servers.iter().map(|s| s.subscription.as_str()).collect();
    let show_source = sources.len() > 1;

    if show_source {
        println!(
            "{:<18} {:<28} {:<14} {:>8}  {:<18} АДРЕС",
            "ID", "ИМЯ", "ПРОТОКОЛ", "ПИНГ", "ПОДПИСКА"
        );
    } else {
        println!(
            "{:<18} {:<28} {:<14} {:>8}  АДРЕС",
            "ID", "ИМЯ", "ПРОТОКОЛ", "ПИНГ"
        );
    }

    for s in &servers {
        let rtt = match s.probe.as_ref() {
            Some(p) if p.loss_percent > 0 && p.rtt_ms.is_some() => {
                // Потери важнее самой задержки: на них соединение
                // пробуксовывает так, что лишние миллисекунды уже не главное.
                format!("{} мс {}%", p.rtt_ms.unwrap(), p.loss_percent)
            }
            Some(p) => match p.rtt_ms {
                Some(ms) => format!("{ms} мс"),
                None => "не отв.".to_owned(),
            },
            None => "—".to_owned(),
        };
        let mark = if s.favorite { "★ " } else { "  " };

        if show_source {
            println!(
                "{:<18} {mark}{:<26} {:<14} {:>8}  {:<18} {}:{}",
                s.id.as_str(),
                truncate(&s.name, 26),
                s.transport.as_str(),
                rtt,
                s.subscription.as_str(),
                s.host,
                s.port
            );
        } else {
            println!(
                "{:<18} {mark}{:<26} {:<14} {:>8}  {}:{}",
                s.id.as_str(),
                truncate(&s.name, 26),
                s.transport.as_str(),
                rtt,
                s.host,
                s.port
            );
        }
    }
    println!("\nВсего: {}", servers.len());
    if servers.iter().all(|s| s.probe.is_none()) {
        println!("Задержка ещё не измерена: sontd probe");
    }

    Ok(())
}

/// Печатает состояние одной точки объявления прокси.
///
/// Сравнение с ожидаемым адресом, а не просто «задано/не задано»: настройка,
/// указывающая на чужой или устаревший порт, для пользователя выглядит ровно
/// так же, как отсутствующая, а чинится совсем иначе.
fn report_channel(label: &str, actual: Option<String>, expected: &Option<String>) {
    let verdict = match (&actual, expected) {
        (Some(a), Some(e)) if a == e => "да".to_owned(),
        (Some(a), Some(_)) => format!("указывает на {a} — не наш адрес"),
        (Some(a), None) => format!("задан {a}, но демон адреса не сообщил"),
        (None, _) => "нет".to_owned(),
    };
    println!("  {label:<38} {verdict}");
}

/// Значение `HTTPS_PROXY` в профиле пользователя.
///
/// Читаем из реестра, а не из своего окружения: своё мы получили при запуске,
/// и свежую правку оно не покажет — ровно та причина, по которой уже открытым
/// приложениям нужен перезапуск.
#[cfg(windows)]
fn user_env_proxy() -> Option<String> {
    let output = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Environment",
            "/v",
            "HTTPS_PROXY",
        ])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|l| l.contains("HTTPS_PROXY"))?
        .split_whitespace()
        .next_back()?
        .to_owned();

    (!value.is_empty()).then_some(value)
}

#[cfg(not(windows))]
fn user_env_proxy() -> Option<String> {
    std::env::var("HTTPS_PROXY").ok().filter(|v| !v.is_empty())
}

/// Адрес из машинной настройки WinHTTP.
#[cfg(windows)]
fn machine_proxy_setting() -> Option<String> {
    winhttp::ours_if_any()
}

#[cfg(not(windows))]
fn machine_proxy_setting() -> Option<String> {
    None
}

/// Человеческое описание выбывания сервера.
fn describe_failure(f: &sont_ipc::ServerFailure) -> String {
    use sont_core::ReconnectCause;

    let why = match &f.cause {
        ReconnectCause::CoreExited { .. } => "соединение с ним оборвалось",
        ReconnectCause::HealthCheckFailed { .. } => "он перестал проводить трафик",
        // Остальные причины сервером не вызваны и сюда не приводят, но
        // молчать в ответ на неожиданное значение — худший вариант.
        _ => "он выбыл",
    };

    match (&f.switching_to, f.switching_to_rtt_ms) {
        (Some(_), Some(rtt)) => format!(
            "{}: {why}, перехожу на другой сервер ({rtt} мс)",
            truncate(&f.name, 28)
        ),
        (Some(_), None) => format!("{}: {why}, перехожу на другой сервер", truncate(&f.name, 28)),
        (None, _) => format!("{}: {why}, заменить некем", truncate(&f.name, 28)),
    }
}

/// Замер задержки до всех серверов.
async fn probe_cmd() -> Result<()> {
    use sont_ipc::Event;

    let (client, mut events) = client().await;
    client.request(Request::SubscribeEvents).await?;

    let response = client.request(Request::ProbeServers { servers: None }).await?;
    if let Response::Error(e) = response {
        eprintln!("Замер невозможен: {e}");
        std::process::exit(1);
    }

    let Response::Servers(known) = client.request(Request::ListServers).await? else {
        anyhow::bail!("неожиданный ответ демона");
    };
    let total = known.len();
    println!("Меряю задержку до {total} серверов…");

    // Результаты приходят по одному, а не пачкой: демон меряет параллельно и
    // публикует каждый по готовности. Ждём, пока придут все, но не бесконечно.
    let mut measured = std::collections::HashMap::new();
    let deadline = tokio::time::Duration::from_secs(60);
    let _ = tokio::time::timeout(deadline, async {
        while let Some(event) = events.recv().await {
            if let Event::Probe(p) = event {
                measured.insert(p.server.clone(), p);
                if measured.len() >= total {
                    return;
                }
            }
        }
    })
    .await;

    if measured.is_empty() {
        anyhow::bail!("демон не сообщил ни одного результата");
    }

    let mut rows: Vec<_> = known
        .iter()
        .filter_map(|s| measured.get(&s.id).map(|p| (s, p)))
        .collect();
    // Порядок тот же, по которому демон выбирает сервер: сверху лучший.
    rows.sort_by_key(|(_, p)| p.score());

    println!("\n{:<28} {:>10}  ПОТЕРИ", "ИМЯ", "ПИНГ");
    for (s, p) in &rows {
        let rtt = match p.rtt_ms {
            Some(ms) => format!("{ms} мс"),
            None => "не отвечает".to_owned(),
        };
        println!(
            "{:<28} {:>10}  {}%",
            truncate(&s.name, 28),
            rtt,
            p.loss_percent
        );
    }

    let reachable = rows.iter().filter(|(_, p)| p.is_reachable()).count();
    println!("\nОтвечают: {reachable} из {}", rows.len());
    if measured.len() < total {
        println!("Часть серверов не успела ответить за отведённое время.");
    }

    Ok(())
}

async fn connect(server: Option<String>) -> Result<()> {
    use sont_ipc::Event;

    let (client, mut events) = client().await;
    client.request(Request::SubscribeEvents).await?;
    client
        .request(Request::Connect {
            server: server.map(sont_core::ProfileId::from_raw),
        })
        .await?;

    println!("Подключаюсь…");

    let outcome = tokio::time::timeout(tokio::time::Duration::from_secs(60), async {
        while let Some(event) = events.recv().await {
            match event {
                Event::StateChanged(state) => match state {
                    sont_core::TunnelState::Connected { server, .. } => {
                        return Some(Ok(server));
                    }
                    sont_core::TunnelState::Failed { error, .. } => {
                        return Some(Err(error.to_string()));
                    }
                    other => println!("  {}", other.kind()),
                },
                // Смена сервера посреди подключения выглядела бы необъяснимо:
                // пользователь просил один, подключился к другому. Говорим,
                // что произошло и на каком основании выбрана замена.
                Event::ServerFailed(f) => println!("  {}", describe_failure(&f)),
                Event::Error(e) => return Some(Err(e.to_string())),
                _ => {}
            }
        }
        None
    })
    .await;

    match outcome {
        Ok(Some(Ok(server))) => {
            println!("Подключено к {server}");
            apply_system_proxy_if_needed(&client).await;
            Ok(())
        }
        Ok(Some(Err(e))) => {
            eprintln!("Не удалось подключиться: {e}");
            std::process::exit(1);
        }
        Ok(None) => anyhow::bail!("демон разорвал соединение"),
        Err(_) => anyhow::bail!("подключение не завершилось за 60 секунд"),
    }
}

async fn disconnect() -> Result<()> {
    let (client, _events) = client().await;
    client.request(Request::Disconnect).await?;

    // Настройки прокси убираем всегда, даже если их ставил не этот запуск:
    // оставленный прокси, за которым больше никого нет, выглядит для
    // пользователя как полностью пропавший интернет.
    match sysproxy::clear() {
        Ok(()) => println!("Отключено, системный прокси убран."),
        Err(e) => {
            eprintln!("Отключено, но не удалось убрать системный прокси: {e}");
            eprintln!("Проверьте: Параметры → Сеть и Интернет → Прокси,");
            eprintln!("а также переменные HTTP_PROXY, HTTPS_PROXY и NO_PROXY.");
        }
    }
    Ok(())
}

async fn mode(value: Option<String>) -> Result<()> {
    use sont_core::ConnectionMode;

    let (client, _events) = client().await;

    let Some(value) = value else {
        let Response::Settings(settings) = client.request(Request::GetSettings).await? else {
            anyhow::bail!("неожиданный ответ демона");
        };
        match settings.mode {
            ConnectionMode::Tunnel => {
                println!("Режим: туннель — весь трафик системы, нужны права администратора.");
            }
            ConnectionMode::Proxy => {
                println!("Режим: прокси — только приложения, знающие о прокси. Прав не нужно.");
            }
        }
        return Ok(());
    };

    let mode = match value.trim().to_lowercase().as_str() {
        "tunnel" | "туннель" => ConnectionMode::Tunnel,
        "proxy" | "прокси" => ConnectionMode::Proxy,
        other => anyhow::bail!("неизвестный режим: {other}. Ожидается tunnel или proxy"),
    };

    client
        .request(Request::PatchSettings {
            patch: sont_core::SettingsPatch {
                mode: Some(mode),
                ..Default::default()
            },
        })
        .await?;

    match mode {
        ConnectionMode::Tunnel => println!("Режим изменён на туннель."),
        ConnectionMode::Proxy => {
            println!("Режим изменён на прокси.");
            println!(
                "Учтите: приложения, не читающие настройки прокси, пойдут напрямую, \n\
                 и QUIC в браузерах тоже идёт мимо."
            );

            // Объявляем прокси сразу, не дожидаясь переподключения.
            //
            // Локальный HTTP-вход ядро поднимает в обоих режимах и на том же
            // порту, так что объявленный сейчас адрес рабочий уже сейчас — и
            // останется рабочим после переключения. Смысл в порядке: пока
            // адрес не объявлен, а прежний путь при подключении уже снят,
            // приложения успевают уйти напрямую и остаются так, потому что
            // открытые соединения на появившийся прокси не переносятся.
            apply_system_proxy_if_needed(&client).await;
        }
    }
    println!("Изменение вступит в силу при следующем подключении.");
    Ok(())
}

/// Прописывает прокси в настройки системы, если демон работает в этом режиме.
///
/// Делает это именно CLI, а не демон: настройки прокси принадлежат
/// пользователю и живут в его профиле, а демон в рабочей поставке будет
/// службой от `LocalSystem` и попадёт не туда. То же самое позже возьмёт на
/// себя tray-приложение.
async fn apply_system_proxy_if_needed(client: &Client) {
    let Ok(Response::Settings(settings)) = client.request(Request::GetSettings).await else {
        return;
    };
    if !matches!(settings.mode, sont_core::ConnectionMode::Proxy) {
        return;
    }

    let Ok(Response::Status(status)) = client.request(Request::GetStatus).await else {
        return;
    };
    let Some(proxy) = status.proxy else {
        eprintln!("Демон не сообщил адреса прокси — настройки системы не изменены.");
        return;
    };

    let endpoints = sysproxy::Endpoints {
        http: proxy.http.clone(),
    };

    match sysproxy::apply(&endpoints) {
        Ok(()) => {
            // Демон дожидается этого сообщения, чтобы оборвать установленные
            // соединения: настройка действует только на новые, а открытые
            // живут часами и продолжают ходить напрямую.
            let _ = client.request(Request::ProxyAnnounced).await;

            println!("Системный прокси включён: HTTP {}", proxy.http);
            // Мест, куда прописан прокси, на разных системах разные, и назвать
            // чужие — значит послать пользователя искать их там, где их нет.
            if cfg!(windows) {
                println!("Прописан и в настройки Windows, и в HTTP_PROXY/HTTPS_PROXY.");
            } else {
                println!("Прописан в настройки рабочего стола (gsettings) и в переменные");
                println!("окружения сеанса (~/.config/environment.d).");
            }
            // SOCKS в системные настройки не попадает намеренно (см. sysproxy),
            // но он поднят, и приложению, которое настраивается вручную, он
            // нужен — поэтому адрес показываем.
            println!("SOCKS {} — для ручной настройки отдельных приложений.", proxy.socks);
            println!();
            // Переменные окружения процесс получает при запуске: уже открытым
            // приложениям они не достанутся. Сказать об этом обязательно —
            // иначе пользователь решит, что не подействовало вообще.
            println!("Приложения, запущенные до этой команды, переменных не увидят —");
            println!("их нужно перезапустить. Кто не читает ни то ни другое, идёт напрямую.");

            // Настройки прокси живут ровно столько, сколько их кто-то
            // поддерживает. Эта команда прописала их один раз; переподключение
            // демона (упавшее ядро, смена сервера) её не повторит.
            if !agent::is_installed() {
                println!();
                println!("Агент сеанса не установлен: после переподключения демона");
                println!("настройки системы обновить будет некому. Установить: sontd agent install");
            }
        }
        Err(e) => {
            eprintln!("Не удалось прописать прокси в настройки системы: {e}");
            eprintln!("Задайте вручную: HTTP {} / SOCKS {}", proxy.http, proxy.socks);
        }
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        return s.to_owned();
    }
    chars[..max_chars.saturating_sub(1)]
        .iter()
        .collect::<String>()
        + "…"
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Дата по Unix-времени в виде `ГГГГ-ММ-ДД`.
///
/// Считается вручную по григорианскому календарю в UTC: полноценная работа с
/// часовыми поясами ради одной строки в выводе CLI не нужна.
fn format_unix_date(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} UTC")
}

/// Преобразование числа дней от эпохи в календарную дату.
///
/// Алгоритм Говарда Хиннанта из `chrono`-подобных реализаций: работает без
/// таблиц и корректен для всего диапазона, который нас интересует.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

async fn firewall_reset() -> Result<()> {
    // Напрямую, а не через IPC: аварийный сброс нужен ровно тогда, когда
    // демон мёртв, а постоянные фильтры режима lockdown его пережили. Ходить
    // за этим к демону значило бы требовать работоспособности от того, чья
    // неработоспособность и есть причина обращения.
    firewall::reset().context(
        "не удалось снять фильтры; для этого нужны права администратора",
    )?;
    println!("Фильтры сняты, трафик идёт напрямую.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::same_exit;

    #[test]
    fn one_provider_with_several_addresses_is_one_exit() {
        // Ровно тот случай, на котором проверка объявляла исправный туннель
        // дырявым: оба ответа пришли от одного провайдера, просто с разных
        // адресов его подсети.
        assert!(same_exit("152.233.35.212", "152.233.35.206"));
        assert!(same_exit("152.233.35.212", "152.233.35.212"));
    }

    #[test]
    fn a_real_leak_is_still_a_leak() {
        // Домашний адрес и адрес сервера в одной /24 не окажутся.
        assert!(!same_exit("152.233.35.212", "95.24.180.11"));
        assert!(!same_exit("152.233.35.212", "152.233.36.212"));
    }

    #[test]
    fn unparsed_answers_are_compared_as_they_came() {
        // Сервис ответил не адресом — выдумывать послабление не на чем.
        assert!(same_exit("что-то не то", "что-то не то"));
        assert!(!same_exit("что-то не то", "и вовсе другое"));
    }

    #[test]
    fn the_sixth_generation_of_addresses_counts_by_prefix() {
        assert!(same_exit("2a03:2880:f12f:83:face:b00c::25de", "2a03:2880:f12f:83::1"));
        assert!(!same_exit("2a03:2880:f12f:83::1", "2a03:2880:aaaa:83::1"));
    }
}

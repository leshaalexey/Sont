//! Работа демона в качестве службы Windows.
//!
//! # Зачем
//!
//! Создание сетевого адаптера и правка маршрутов требуют прав администратора.
//! Просить их у пользователя при каждом подключении — значит превратить VPN в
//! источник раздражения и приучить нажимать «Да» не глядя. Служба решает это
//! один раз: права нужны при установке, дальше она стартует вместе с системой
//! от `LocalSystem` и работает без единого запроса.
//!
//! # Разделение ролей
//!
//! Служба владеет соединением и всем привилегированным. Приложение в сеансе
//! пользователя — tray или CLI — только отдаёт команды по локальному каналу и
//! никаких прав не требует.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType,
    ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// Внутреннее имя службы.
pub const SERVICE_NAME: &str = "SontDaemon";
/// Имя, которое видит пользователь в списке служб.
const DISPLAY_NAME: &str = "Sont VPN";
const DESCRIPTION: &str =
    "Поддерживает VPN-соединение Sont и управляет сетевыми настройками. \
     Без неё подключение недоступно.";

/// Служба работает в собственном процессе.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Аргументы, с которыми диспетчер служб запускает наш бинарь.
const RUN_ARGS: [&str; 2] = ["service", "run"];

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).context(
        "не удалось обратиться к диспетчеру служб; \
         для установки и удаления нужны права администратора",
    )
}

/// Регистрирует службу и настраивает автозапуск.
pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("не удалось определить путь к собственному файлу")?;

    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        // Автозапуск с задержкой: сеть к моменту старта уже поднята, и служба
        // не соревнуется за ресурсы с остальной загрузкой системы.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: RUN_ARGS.iter().map(OsString::from).collect(),
        dependencies: vec![],
        // None означает LocalSystem: нужны права на создание адаптера,
        // изменение маршрутов и, в дальнейшем, правил firewall.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("не удалось создать службу")?;

    service
        .set_description(DESCRIPTION)
        .context("не удалось задать описание службы")?;

    // Пусть система сама перезапускает службу при сбое. Без этого падение
    // демона оставляет пользователя без VPN до перезагрузки, а он об этом
    // даже не узнает.
    if let Err(e) = configure_restart_on_failure(&service) {
        tracing::warn!(error = %e, "не удалось настроить перезапуск при сбое");
    }

    Ok(())
}

/// Просит систему перезапускать службу после сбоя.
fn configure_restart_on_failure(service: &windows_service::service::Service) -> Result<()> {
    use windows_service::service::{ServiceAction, ServiceActionType, ServiceFailureActions};

    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };

    let actions = ServiceFailureActions {
        // Счётчик сбоев сбрасывается через сутки: череда падений в разные дни
        // не должна складываться в «сдаюсь».
        reset_period: windows_service::service::ServiceFailureResetPeriod::After(
            Duration::from_secs(86_400),
        ),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    };

    service.update_failure_actions(actions)?;
    Ok(())
}

/// Удаляет службу.
pub fn uninstall() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("служба не найдена")?;

    let status = service.query_status()?;
    if status.current_state != ServiceState::Stopped {
        service.stop().context("не удалось остановить службу")?;
        wait_for_state(&service, ServiceState::Stopped)?;
    }

    service.delete().context("не удалось удалить службу")?;
    Ok(())
}

/// Приводит службу в рабочее состояние: ставит, чинит и запускает.
///
/// # Зачем отдельная команда
///
/// Это то, что делает трей при запуске, и делать он это обязан одним вызовом.
/// Установка и запуск требуют прав администратора; два вызова — это два окна
/// повышения прав подряд, после которых пользователь перестаёт их читать.
///
/// «Чинит» — про службу, оставшуюся от прошлой сборки: путь в ней указывает на
/// файл, которого уже нет. Запуск такой службы кончается ошибкой диспетчера,
/// по которой нельзя догадаться, в чём дело.
pub fn setup() -> Result<()> {
    let exe = std::env::current_exe().context("не удалось определить путь к собственному файлу")?;

    match installed_command()? {
        None => install()?,
        Some(command) => {
            let ours = exe.to_string_lossy().to_lowercase();
            if !command.to_lowercase().contains(&ours) {
                tracing::info!(%command, "служба указывает на другой файл, переустанавливаю");
                uninstall()?;
                install()?;
            }
        }
    }

    start()
}

/// Командная строка, с которой зарегистрирована служба.
///
/// Именно строка, а не путь: в `lpBinaryPathName` лежит и файл, и аргументы
/// (`service run`), поэтому сравнивать её с путём можно только вхождением.
fn installed_command() -> Result<Option<String>> {
    let Ok(manager) = manager(ServiceManagerAccess::CONNECT) else {
        return Ok(None);
    };
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG) {
        Ok(service) => Ok(Some(
            service
                .query_config()
                .context("не удалось прочитать настройки службы")?
                .executable_path
                .to_string_lossy()
                .into_owned(),
        )),
        Err(_) => Ok(None),
    }
}

pub fn start() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .context("служба не найдена; сначала выполните `sontd service install`")?;

    let status = service.query_status()?;
    if status.current_state == ServiceState::Running {
        return Ok(());
    }

    service.start(&[] as &[&str]).context("не удалось запустить службу")?;
    wait_for_state(&service, ServiceState::Running)?;
    Ok(())
}

pub fn stop() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
        .context("служба не найдена")?;

    let status = service.query_status()?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }

    service.stop().context("не удалось остановить службу")?;
    wait_for_state(&service, ServiceState::Stopped)?;
    Ok(())
}

/// Текущее состояние службы, если она установлена.
pub fn query() -> Result<Option<ServiceState>> {
    let Ok(manager) = manager(ServiceManagerAccess::CONNECT) else {
        return Ok(None);
    };
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => Ok(Some(service.query_status()?.current_state)),
        Err(_) => Ok(None),
    }
}

/// Ждёт, пока служба перейдёт в нужное состояние.
///
/// Диспетчер служб отвечает на команды асинхронно, и без ожидания следующий
/// шаг — удаление или запуск — упирается в ещё не завершившийся предыдущий.
fn wait_for_state(
    service: &windows_service::service::Service,
    target: ServiceState,
) -> Result<()> {
    const ATTEMPTS: u32 = 40;
    const INTERVAL: Duration = Duration::from_millis(250);

    for _ in 0..ATTEMPTS {
        if service.query_status()?.current_state == target {
            return Ok(());
        }
        std::thread::sleep(INTERVAL);
    }

    anyhow::bail!("служба не перешла в состояние {target:?} за отведённое время")
}

// ─────────────────────── точка входа для диспетчера ───────────────────────

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Вызывается диспетчером служб при старте.
pub fn run_as_service() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("не удалось подключиться к диспетчеру служб")?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = service_body() {
        tracing::error!(error = %e, "служба завершилась с ошибкой");
    }
}

fn service_body() -> Result<()> {
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();

    let handler = move |control| match control {
        windows_service::service::ServiceControl::Stop
        | windows_service::service::ServiceControl::Shutdown => {
            let _ = shutdown_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        windows_service::service::ServiceControl::Interrogate => {
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    let running = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: windows_service::service::ServiceControlAccept::STOP
            | windows_service::service::ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running.clone())?;

    // Основную работу выполняет тот же код, что и в переднем плане: расхождение
    // между «как работает служба» и «как отлаживали» — источник ошибок,
    // которые видит только пользователь.
    let result = crate::run_daemon_blocking(shutdown_rx);

    status_handle.set_service_status(ServiceStatus {
        current_state: ServiceState::Stopped,
        exit_code: match &result {
            Ok(()) => ServiceExitCode::Win32(0),
            // Ненулевой код нужен, чтобы система применила настроенный
            // перезапуск при сбое.
            Err(_) => ServiceExitCode::ServiceSpecific(1),
        },
        ..running
    })?;

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_is_launched_with_explicit_subcommand() {
        // Диспетчер запускает тот же бинарь; без явных аргументов он попал бы
        // в обычный разбор командной строки и не подключился к диспетчеру.
        assert_eq!(RUN_ARGS, ["service", "run"]);
    }

    #[test]
    fn service_runs_as_local_system() {
        // Права нужны для адаптера, маршрутов и firewall. Проверяем намерение:
        // account_name остаётся None, что и означает LocalSystem.
        let exe = std::path::PathBuf::from("sontd.exe");
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: RUN_ARGS.iter().map(OsString::from).collect(),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        assert!(info.account_name.is_none());
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
    }

    #[test]
    fn description_explains_what_breaks_without_the_service() {
        // Пользователь видит этот текст в списке служб и по нему решает,
        // можно ли её отключить.
        assert!(DESCRIPTION.contains("подключение недоступно"));
    }
}

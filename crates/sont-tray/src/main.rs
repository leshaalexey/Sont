//! Окно в трее.
//!
//! # Что здесь есть и чего здесь нет
//!
//! Здесь нет ни одного решения о соединении. Окно спрашивает демон и рисует
//! ответ; всё, что оно умеет само, — открыть папку журналов и положить строку
//! в буфер обмена. Это инвариант проекта: истина живёт в демоне, а клиенты
//! состояния не хранят и падением своим ничего не роняют.
//!
//! # Где должен лежать бинарь
//!
//! Рядом с `sontd`. Демон пускает только клиентов из своего каталога
//! (`DefaultPolicy::require_exe_under`), и это не формальность: канал открыт
//! всем интерактивным пользователям, а служба работает от `LocalSystem`.

// Ни одного окна консоли — ни в рабочей сборке, ни в отладочной.
//
// Обычно это ставят только для release, чтобы при отладке видеть вывод. Здесь
// иначе: приложение живёт в трее и запускается при входе в систему, а мигающее
// чёрное окно при каждом старте — это дефект, который пользователь видит
// каждый день. Журнал у демона общий, и смотреть его надо там.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::sync::Arc;
use std::time::Duration;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use serde_json::{json, Value};
use sont_core::Secret;
use sont_ipc::protocol::{Request, Response};
use sont_ipc::{Client, Event};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

const AGENT: &str = concat!("sont-tray/", env!("CARGO_PKG_VERSION"));

/// Событие, по которому окно перечитывает состояние.
const CHANGED: &str = "sont://event";

// ─────────────────────────── связь с демоном ───────────────────────────

/// Соединение с демоном, восстанавливаемое по необходимости.
///
/// Демон перезапускается — обновление, сбой, `sc restart`, — и окно обязано
/// это переживать, а не превращаться в неработающий прямоугольник до
/// перезапуска себя самого.
#[derive(Default)]
struct Link {
    client: Mutex<Option<Arc<Client>>>,
}

impl Link {
    async fn client(&self, app: &AppHandle) -> Result<Arc<Client>, String> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref() {
            return Ok(Arc::clone(client));
        }

        let (client, events) = connect_or_start().await.map_err(|e| e.to_string())?;
        let client = Arc::new(client);

        // Поток событий демона превращаем в одно событие окна: перерисовать.
        // Разбирать его содержимое здесь незачем — окно всё равно спросит
        // полное состояние, и так оно не разъедется с демоном по частям.
        let _ = client.request(Request::SubscribeEvents).await;
        spawn_event_pump(app.clone(), events);

        tracing::info!("подключён к демону");
        *slot = Some(Arc::clone(&client));
        Ok(client)
    }

    /// Забывает соединение, чтобы следующий запрос установил новое.
    async fn drop_client(&self) {
        *self.client.lock().await = None;
    }
}

/// Сколько ждём службу после запроса на запуск.
const DAEMON_WAIT: Duration = Duration::from_secs(12);

/// Сколько ждём, если запрошено повышение прав.
///
/// В этот срок укладывается не только запуск службы, но и время, пока
/// пользователь читает окно UAC и тянется к мыши. Отмерять ему на это те же
/// двенадцать секунд — значит сдаться раньше, чем он успеет нажать «Да».
const ELEVATED_WAIT: Duration = Duration::from_secs(90);

/// Подключается к демону, при необходимости подняв службу.
///
/// # Почему это здесь
///
/// Трей запускается при входе в систему и часто раньше, чем служба успевает
/// подняться, а после ручной остановки службы не поднимается вовсе. Показывать
/// в этом случае «демон недоступен» и ждать, что пользователь сам догадается
/// про `sc start`, — значит перекладывать на него нашу работу. Он открыл
/// приложение, чтобы получить соединение.
async fn connect_or_start() -> Result<(Client, tokio::sync::mpsc::Receiver<Event>), String> {
    let addr = sont_ipc::endpoint_name();

    match Client::connect(&addr, AGENT).await {
        Ok(pair) => return Ok(pair),
        Err(e) => tracing::info!(error = %e, "демон не отвечает, поднимаю службу"),
    }

    let patience = start_service();

    // Служба поднимается не мгновенно: канал появляется через секунду-другую
    // после команды. Ждём его появления, а не спим наугад фиксированный срок.
    let deadline = std::time::Instant::now() + patience;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(400)).await;
        match Client::connect(&addr, AGENT).await {
            Ok(pair) => {
                tracing::info!("демон поднялся");
                return Ok(pair);
            }
            Err(e) => last = e.to_string(),
        }
    }

    // Единственная причина сюда дойти — пользователь отказал в повышении прав
    // или сам запуск не удался. Просить его установить что-то командой уже
    // незачем: приложение умеет это само, ему нужно только разрешение.
    Err(format!(
        "не удалось поднять службу Sont ({last}). Откройте приложение ещё раз \
         и подтвердите запрос прав администратора."
    ))
}

/// Что удалось выяснить про службу.
#[derive(Debug, PartialEq, Eq)]
enum ServiceState {
    Missing,
    Running,
    Stopped,
    /// Состояние не удалось узнать — обычно не хватило прав даже на запрос.
    Unknown,
}

/// Спрашивает у диспетчера служб, что со службой демона.
///
/// Через API, а не разбором вывода `sc`: тот переводится на язык системы, и
/// любая проверка по тексту сломается на первой же нерусской машине.
#[cfg(windows)]
fn service_state() -> ServiceState {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    };

    let name: Vec<u16> = "SontDaemon\0".encode_utf16().collect();

    // SAFETY: имена завершены нулём, дескрипторы закрываются ниже.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return ServiceState::Unknown;
        }

        let service = OpenServiceW(scm, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_START);
        if service.is_null() {
            let missing =
                std::io::Error::last_os_error().raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32);
            CloseServiceHandle(scm);
            return if missing {
                ServiceState::Missing
            } else {
                ServiceState::Unknown
            };
        }

        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = QueryServiceStatus(service, &mut status);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        let _ = CloseHandle;

        if ok == 0 {
            return ServiceState::Unknown;
        }
        if status.dwCurrentState == SERVICE_RUNNING
            || status.dwCurrentState == SERVICE_START_PENDING
        {
            ServiceState::Running
        } else {
            ServiceState::Stopped
        }
    }
}

#[cfg(not(windows))]
fn service_state() -> ServiceState {
    ServiceState::Unknown
}

/// Приводит службу демона в рабочее состояние и говорит, сколько её ждать.
///
/// # Почему тут ничего не возвращается как ошибка
///
/// Раньше отсутствие службы было ошибкой с текстом «установите её от
/// администратора: sontd service install». Это перекладывание работы: команда
/// известна нам, права запрашиваются одним окном, и никакого решения от
/// пользователя тут не требуется — он открыл приложение, чтобы оно работало.
/// Поэтому недостающая служба ставится сама, а единственное, что он видит, —
/// обычный запрос прав.
///
/// Порядок такой: работающую службу трогать незачем — окно повышения прав,
/// выскакивающее при каждом открытии без причины, приучает нажимать «Да» не
/// глядя. Остановленную сначала пробуем поднять без повышения: её могли
/// настроить так, что пользователю это разрешено. И только если система
/// отказала — просим права явно, одним вызовом `service setup`, который и
/// поставит, и починит, и запустит.
#[cfg(windows)]
fn start_service() -> Duration {
    match service_state() {
        ServiceState::Running => {
            tracing::info!("служба уже работает, жду канал");
            return DAEMON_WAIT;
        }
        ServiceState::Missing => {
            tracing::info!("службы нет, устанавливаю");
            elevate_service_setup();
            return ELEVATED_WAIT;
        }
        ServiceState::Stopped | ServiceState::Unknown => {}
    }

    let started = std::process::Command::new("sc")
        .args(["start", "SontDaemon"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if started {
        return DAEMON_WAIT;
    }

    tracing::info!("запуск службы требует прав администратора, запрашиваю повышение");
    elevate_service_setup();
    ELEVATED_WAIT
}

/// Просит `sontd` установить, починить и запустить службу — с повышением прав.
///
/// Вызываем соседний `sontd.exe`, а не `sc.exe`: у `sc` нет способа поставить
/// службу правильно (описание, перезапуск при сбое, путь к нужному бинарю), а
/// каждое лишнее окно повышения прав — это ещё один шанс, что его закроют.
#[cfg(windows)]
fn elevate_service_setup() {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let Some(exe) = daemon_exe() else {
        tracing::error!("рядом нет sontd.exe, службу поднять нечем");
        return;
    };

    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args: Vec<u16> = "service setup\0".encode_utf16().collect();

    // SAFETY: все строки завершены нулём и живут до конца вызова.
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            args.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        );
    }
}

#[cfg(not(windows))]
fn start_service() -> Duration {
    let _ = std::process::Command::new("systemctl")
        .args(["start", "sont"])
        .status();
    DAEMON_WAIT
}

/// Путь к демону: он лежит рядом с треем — этого требует и проверка клиента в
/// самом демоне, и здравый смысл при установке.
fn daemon_exe() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?.with_file_name(if cfg!(windows) {
        "sontd.exe"
    } else {
        "sontd"
    });
    exe.exists().then_some(exe)
}

fn spawn_event_pump(app: AppHandle, mut events: tokio::sync::mpsc::Receiver<Event>) {
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            if let Event::StateChanged(state) = &event {
                update_tray(&app, state.kind());
            }
            let _ = app.emit(CHANGED, ());
        }

        // Канал закрылся — демон ушёл. Сообщаем окну и роняем соединение,
        // чтобы следующий запрос попробовал подключиться заново.
        let link = app.state::<Link>();
        link.drop_client().await;
        let _ = app.emit(CHANGED, ());
    });
}

/// Один запрос к демону с восстановлением соединения при обрыве.
async fn ask(app: &AppHandle, link: &Link, request: Request) -> Result<Response, String> {
    let client = link.client(app).await?;
    match client.request(request).await {
        Ok(response) => Ok(response),
        Err(e) => {
            link.drop_client().await;
            Err(e.to_string())
        }
    }
}

/// Разворачивает ответ демона, превращая его отказ в ошибку команды.
fn expect_ok(response: Response) -> Result<Response, String> {
    match response {
        Response::Error(e) => Err(e.to_string()),
        other => Ok(other),
    }
}

// ─────────────────────────── команды окна ───────────────────────────

/// Состояние вместе с именем сервера и его задержкой.
///
/// Демон отдаёт в снимке идентификатор сервера, а не имя: имена меняются, а
/// идентификатор нет. Шапке окна нужно имя, поэтому склейка делается здесь, а
/// не расширением протокола ради одного заголовка.
#[tauri::command]
async fn status(app: AppHandle, link: State<'_, Link>) -> Result<Value, String> {
    let Response::Status(snapshot) = expect_ok(ask(&app, &link, Request::GetStatus).await?)? else {
        return Err("неожиданный ответ демона".into());
    };

    let mut view = serde_json::to_value(&snapshot).map_err(|e| e.to_string())?;

    // Плоский дискриминант состояния.
    //
    // `TunnelState` сериализуется с тегом `state`, поэтому в JSON он лежит
    // как `state.state`, а рядом — поля конкретного варианта. Окно читало
    // несуществующее `state.kind` и потому всегда рисовало «отключено»:
    // строка в шапке и маскот не менялись ни при подключении, ни при
    // обрыве. Имя дискриминанта — знание Rust-типа, и выводить его здесь
    // честнее, чем повторять в JS раскладку serde.
    view["kind"] = json!(snapshot.state.kind());

    if let Some(current) = snapshot.state.server() {
        if let Ok(Response::Servers(servers)) = ask(&app, &link, Request::ListServers).await {
            if let Some(server) = servers.iter().find(|s| &s.id == current) {
                view["server_name"] = json!(server.name);
                view["rtt_ms"] = json!(server.probe.as_ref().and_then(|p| p.rtt_ms));
            }
        }
    }

    Ok(view)
}

#[tauri::command]
async fn settings(app: AppHandle, link: State<'_, Link>) -> Result<Value, String> {
    match expect_ok(ask(&app, &link, Request::GetSettings).await?)? {
        Response::Settings(s) => serde_json::to_value(s).map_err(|e| e.to_string()),
        _ => Err("неожиданный ответ демона".into()),
    }
}

#[tauri::command]
async fn patch(
    app: AppHandle,
    link: State<'_, Link>,
    patch: sont_core::SettingsPatch,
) -> Result<Value, String> {
    match expect_ok(ask(&app, &link, Request::PatchSettings { patch }).await?)? {
        Response::Settings(s) => serde_json::to_value(s).map_err(|e| e.to_string()),
        _ => Err("неожиданный ответ демона".into()),
    }
}

/// Акцентный цвет системы в виде `#RRGGBB`.
///
/// `None`, если узнать не удалось: на не-Windows такого понятия нет, а на
/// Windows значение может отсутствовать в свежем профиле. Окно тогда остаётся
/// при своём цвете — это честнее, чем подставлять «примерно такой же синий».
#[tauri::command]
async fn system_accent() -> Option<String> {
    accent::current()
}

/// Чтение акцентного цвета системы.
#[cfg(windows)]
mod accent {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD,
    };

    /// Ключ, куда Windows кладёт выбранный пользователем акцент.
    ///
    /// Значение — `AABBGGRR`, задом наперёд относительно привычного
    /// `#RRGGBB`: старший байт прозрачность, дальше синий, зелёный, красный.
    /// Соседний `ColorizationColor` из той же ветки хранит цвет рамок окон, а
    /// он у Windows заметно светлее акцента и для заливки не годится.
    const PATH: &str = r"Software\Microsoft\Windows\DWM";
    const NAME: &str = "AccentColor";

    pub fn current() -> Option<String> {
        let path = wide(PATH);
        let name = wide(NAME);
        let mut value: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;

        // SAFETY: строки завершены нулём, буфер и его размер согласованы.
        let code = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        };
        if code != 0 {
            return None;
        }

        let [r, g, b] = [value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF];
        Some(format!("#{r:02X}{g:02X}{b:02X}"))
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod accent {
    pub fn current() -> Option<String> {
        None
    }
}

#[tauri::command]
async fn daemon_info(app: AppHandle, link: State<'_, Link>) -> Result<Value, String> {
    match expect_ok(ask(&app, &link, Request::DaemonInfo).await?)? {
        Response::DaemonInfo(info) => serde_json::to_value(info).map_err(|e| e.to_string()),
        _ => Err("неожиданный ответ демона".into()),
    }
}

#[tauri::command]
async fn connect(app: AppHandle, link: State<'_, Link>) -> Result<(), String> {
    expect_ok(ask(&app, &link, Request::Connect { server: None }).await?).map(|_| ())
}

#[tauri::command]
async fn disconnect(app: AppHandle, link: State<'_, Link>) -> Result<(), String> {
    expect_ok(ask(&app, &link, Request::Disconnect).await?).map(|_| ())
}

#[tauri::command]
async fn probe(app: AppHandle, link: State<'_, Link>) -> Result<(), String> {
    expect_ok(ask(&app, &link, Request::ProbeServers { servers: None }).await?).map(|_| ())
}

#[tauri::command]
async fn add_subscription(app: AppHandle, link: State<'_, Link>, url: String) -> Result<(), String> {
    let request = Request::AddSubscription {
        url: Secret::new(url),
    };
    expect_ok(ask(&app, &link, request).await?).map(|_| ())
}

#[tauri::command]
async fn remove_subscription(
    app: AppHandle,
    link: State<'_, Link>,
    id: String,
) -> Result<(), String> {
    let request = Request::RemoveSubscription {
        id: sont_core::SubscriptionId::from_raw(id),
    };
    expect_ok(ask(&app, &link, request).await?).map(|_| ())
}

#[tauri::command]
async fn refresh_subscription(
    app: AppHandle,
    link: State<'_, Link>,
    id: Option<String>,
) -> Result<(), String> {
    let request = Request::RefreshSubscription {
        id: id.map(sont_core::SubscriptionId::from_raw),
    };
    expect_ok(ask(&app, &link, request).await?).map(|_| ())
}

/// Отдаёт ключ подписки для копирования.
///
/// Дальше строка живёт в буфере обмена, то есть вне нашего контроля, — поэтому
/// запрашивается она только по нажатию и нигде здесь не сохраняется.
#[tauri::command]
async fn reveal_subscription(
    app: AppHandle,
    link: State<'_, Link>,
    id: String,
) -> Result<String, String> {
    let request = Request::RevealSubscription {
        id: sont_core::SubscriptionId::from_raw(id),
    };
    match expect_ok(ask(&app, &link, request).await?)? {
        Response::SubscriptionSecret(secret) => Ok(secret.expose().to_owned()),
        _ => Err("неожиданный ответ демона".into()),
    }
}

/// Матрица QR для ключа подписки.
///
/// Считается здесь, а не в окне: кодировщик QR на JavaScript ради одной кнопки
/// — лишние двести строк, которые придётся сопровождать.
#[tauri::command]
async fn subscription_qr(
    app: AppHandle,
    link: State<'_, Link>,
    id: String,
) -> Result<Vec<Vec<bool>>, String> {
    let key = reveal_subscription(app, link, id).await?;
    let code = qrcode::QrCode::new(key.as_bytes()).map_err(|e| e.to_string())?;

    let width = code.width();
    let colors = code.to_colors();
    Ok((0..width)
        .map(|y| {
            (0..width)
                .map(|x| colors[y * width + x] == qrcode::Color::Dark)
                .collect()
        })
        .collect())
}

#[tauri::command]
fn open_logs(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    // Тот же каталог, что и у демона. Дублируется намеренно: тянуть сюда весь
    // `sont-daemon` ради одной строки пути дороже, чем повторить её.
    let dir = if cfg!(windows) {
        std::path::PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| {
            r"C:\ProgramData".to_owned()
        }))
        .join("Sont")
        .join("logs")
    } else {
        std::path::PathBuf::from("/var/lib/sont/logs")
    };

    app.opener()
        .open_path(dir.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn quit(app: AppHandle) {
    app.exit(0);
}

// ─────────────────────────── трей ───────────────────────────

/// Агент сеанса, запущенный этим окном.
struct Agent(std::sync::Mutex<Option<std::process::Child>>);

/// Поднимает агента сеанса скрытым и отдаёт его дескриптор.
///
/// # Почему это здесь
///
/// Агент — часть `sontd`, а `sontd` консольное приложение: запущенный из
/// автозапуска, он показывает пользователю чёрное окно при каждом входе в
/// систему. Окно трея консоли не имеет, поэтому агента запускает оно и с
/// флагом, который окна не создаёт.
///
/// Заодно это правильно по смыслу: агент нужен ровно тогда, когда в сеансе
/// есть кому следить за настройками прокси, — то есть пока открыт трей.
fn spawn_agent() -> Option<std::process::Child> {
    let Some(exe) = daemon_exe() else {
        tracing::warn!("рядом нет демона, агент не запущен");
        return None;
    };

    let mut command = std::process::Command::new(&exe);
    command.arg("agent").arg("run");

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: то самое, ради чего запуск и перенесён сюда.
        command.creation_flags(0x0800_0000);
    }

    match command.spawn() {
        Ok(child) => {
            tracing::info!(pid = child.id(), "агент сеанса запущен");
            Some(child)
        }
        Err(e) => {
            tracing::error!(error = %e, "не удалось запустить агента сеанса");
            None
        }
    }
}

/// Пиксельный рисунок иконки, собранный `build.rs` из SVG.
struct TrayArt {
    width: u32,
    height: u32,
    lit: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/icons.rs"));

impl TrayArt {
    /// Растр под трей: увеличение целым множителем, без сглаживания.
    ///
    /// Холст обнимает рисунок, а не берётся фиксированным. Разница видна
    /// сразу: маскот 15 точек шириной и «оффлайн» 21 точку в общем квадрате
    /// 32×32 занимали бы разную долю площади, и вторая иконка выглядела бы
    /// заметно мельче первой. Обнимающий холст даёт обеим одинаковый вес
    /// рядом с чужими значками в трее.
    fn image(&self) -> tauri::image::Image<'static> {
        let long = self.width.max(self.height).max(1);
        // Целый множитель — обязательное условие чёткости: дробное
        // растяжение пиксельной графики и есть то самое мыло.
        let k = (TRAY_TARGET / long).max(1);
        let size = long * k;

        let ox = (size - self.width * k) / 2;
        let oy = (size - self.height * k) / 2;

        let mut rgba = vec![0u8; (size * size * 4) as usize];
        for y in 0..self.height {
            for x in 0..self.width {
                if self.lit[(y * self.width + x) as usize] == 0 {
                    continue;
                }
                for dy in 0..k {
                    for dx in 0..k {
                        let px = ox + x * k + dx;
                        let py = oy + y * k + dy;
                        if px >= size || py >= size {
                            continue;
                        }
                        let o = ((py * size + px) * 4) as usize;
                        rgba[o..o + 4].copy_from_slice(&[244, 237, 229, 255]);
                    }
                }
            }
        }

        tauri::image::Image::new_owned(rgba, size, size)
    }
}

/// К какому размеру стремится растр иконки трея.
///
/// 32, а не 16: при крупном масштабе экрана оболочка просит именно столько, а
/// уменьшать она умеет без потерь, в отличие от увеличения. Точное значение
/// получается округлением вниз до целого множителя.
const TRAY_TARGET: u32 = 32;

/// Спрашивает состояние у демона и приводит иконку в соответствие.
///
/// Нужно при запуске: события приходят только на изменения, а первое
/// состояние надо узнать самим — иначе значок до первой смены показывает
/// «оффлайн» при исправном соединении.
async fn refresh_tray(app: &AppHandle) {
    let link = app.state::<Link>();
    let kind = match ask(app, &link, Request::GetStatus).await {
        Ok(Response::Status(snapshot)) => snapshot.state.kind().to_owned(),
        _ => "failed".to_owned(),
    };
    update_tray(app, &kind);
}

/// Пункт меню «Подключить/Отключить»: его подпись зависит от состояния.
struct ToggleItem(MenuItem<tauri::Wry>);

/// Приводит иконку, подсказку и меню трея в соответствие с состоянием.
fn update_tray(app: &AppHandle, state: &str) {
    let Some(tray) = app.tray_by_id("sont") else {
        return;
    };

    // Рабочее соединение — маскот, всё остальное — «оффлайн». Промежуточные
    // состояния показываем как нерабочие намеренно: пока соединение не
    // поднято, трафик через него не идёт, и обещать обратное иконкой нельзя.
    let art = if state == "connected" { &IDLE } else { &OFFLINE };

    let _ = tray.set_icon(Some(art.image()));
    let _ = tray.set_tooltip(Some(format!("Sont — {state}")));

    // Пока идёт подключение или отключение, пункт называется по тому, чем
    // дело кончится: мигающая туда-сюда подпись читается хуже, чем чуть
    // забегающая вперёд.
    if let Some(item) = app.try_state::<ToggleItem>() {
        let busy_up = matches!(state, "connecting" | "reconnecting");
        let label = if state == "connected" || busy_up {
            "Отключить"
        } else {
            "Подключить"
        };
        let _ = item.0.set_text(label);
    }
}

/// Поднимает или роняет соединение по команде из меню трея.
fn toggle_connection(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let link = app.state::<Link>();

        let Ok(Response::Status(snapshot)) = ask(&app, &link, Request::GetStatus).await else {
            return;
        };

        // «Подключаюсь» и «восстанавливаю» считаем включённым состоянием:
        // человек, выбравший «Отключить» в этот момент, хочет прекратить
        // происходящее, а не дождаться его конца и нажать ещё раз.
        let request = if snapshot.state.holds_a_route() {
            Request::Disconnect
        } else {
            Request::Connect { server: None }
        };

        if let Err(e) = ask(&app, &link, request).await {
            tracing::warn!(error = %e, "команда из меню трея не прошла");
        }
        refresh_tray(&app).await;
        let _ = app.emit(CHANGED, ());
    });
}

/// Рабочая область экрана — без панели задач.
///
/// Берётся у системы, а не вычитается из размера экрана на глаз: панель задач
/// бывает сверху и сбоку, бывает автоскрываемой, и любое предположение о ней
/// рано или поздно поставит окно не туда.
#[cfg(windows)]
fn work_area() -> Option<(i32, i32, i32, i32)> {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_GETWORKAREA,
    };

    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };

    // SAFETY: структура на стеке, размер передан честно.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            (&mut rect as *mut RECT).cast(),
            0,
        )
    };

    (ok != 0).then_some((rect.left, rect.top, rect.right, rect.bottom))
}

#[cfg(not(windows))]
fn work_area() -> Option<(i32, i32, i32, i32)> {
    None
}

/// Отступ от края рабочей области.
///
/// Двенадцать точек — столько же, сколько у системных всплывающих панелей
/// Windows 11. Меньше — и тень окна обрезается краем экрана, а панель
/// выглядит приклеенной к углу.
const EDGE_GAP: i32 = 12;

/// Ставит окно в правый нижний угол, над панелью задач.
fn place_window(window: &tauri::WebviewWindow) {
    let Some((_, _, right, bottom)) = work_area() else {
        return;
    };
    let Ok(size) = window.outer_size() else {
        return;
    };

    let scale = window.scale_factor().unwrap_or(1.0);
    let gap = (EDGE_GAP as f64 * scale).round() as i32;

    let x = right - size.width as i32 - gap;
    let y = bottom - size.height as i32 - gap;

    let _ = window.set_position(tauri::PhysicalPosition::new(x.max(0), y.max(0)));
}

/// Когда панель в последний раз начала уходить вниз.
///
/// Нужно, чтобы отличить «окно закрыто давно» от «окно закрылось только что,
/// потому что по нему и щёлкнули». Подробности — в [`toggle_window`].
struct LastHidden(std::sync::Mutex<Option<std::time::Instant>>);

/// Сколько после ухода панели щелчок по значку считается тем же самым.
///
/// Больше времени между нажатием кнопки и приходом события щелчка (там
/// десятки миллисекунд) и меньше промежутка, за который пользователь успеет
/// осмысленно ткнуть в значок второй раз.
const CLICK_GRACE: Duration = Duration::from_millis(500);

/// Отмечает, что панель поехала вниз, и просит разметку её увезти.
fn start_hiding(app: &AppHandle) {
    if let Some(state) = app.try_state::<LastHidden>() {
        *state.0.lock().unwrap() = Some(std::time::Instant::now());
    }
    // Не прячем сразу: сначала пусть панель уедет вниз. Само окно уберёт
    // разметка, когда анимация закончится.
    let _ = app.emit("sont://hide", ());
}

/// Показывает или прячет панель по щелчку на значке.
///
/// # Почему одной проверки видимости мало
///
/// Щелчок по значку сначала отнимает у окна фокус, а потеря фокуса — это уже
/// команда уйти вниз. К моменту, когда приходит само событие щелчка, панель
/// закрыта, и простая проверка «видно? — прячем, не видно? — показываем»
/// показывала её заново. Со стороны это выглядело так, будто окно на второе
/// нажатие моргает и остаётся открытым, а закрыть его щелчком по значку
/// вообще нельзя.
///
/// Поэтому окно, закрывшееся только что, считается закрытым этим же щелчком,
/// и он не делает ничего.
fn toggle_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };

    if window.is_visible().unwrap_or(false) {
        start_hiding(app);
        return;
    }

    if let Some(state) = app.try_state::<LastHidden>() {
        let recently = state
            .0
            .lock()
            .unwrap()
            .is_some_and(|at| at.elapsed() < CLICK_GRACE);
        if recently {
            return;
        }
    }

    place_window(&window);
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit("sont://show", ());
}

/// Заводит журнал в файл рядом с журналом демона.
///
/// У окна нет консоли — иначе оно мигало бы чёрным прямоугольником при каждом
/// входе в систему. Без файла это означает приложение, о котором при отказе
/// нельзя узнать ровно ничего: «демон недоступен» и всё. Файл превращает
/// такую жалобу в строку с причиной.
fn setup_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let dir = if cfg!(windows) {
        std::path::PathBuf::from(
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned()),
        )
        .join("Sont")
        .join("logs")
    } else {
        std::path::PathBuf::from("/var/lib/sont/logs")
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());

    // Каталог может быть недоступен на запись: демон работает от системы, а
    // окно — от пользователя. Тогда остаёмся без журнала, но не без окна.
    match std::fs::create_dir_all(&dir) {
        Ok(()) => {
            let file = tracing_appender::rolling::daily(&dir, "sont-tray.log");
            let (writer, guard) = tracing_appender::non_blocking(file);
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(writer)
                .init();
            Some(guard)
        }
        Err(_) => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
            None
        }
    }
}

/// Не давать движку засыпать, пока окно без фокуса.
///
/// # Зачем
///
/// Chromium экономит на окнах, которые считает фоновыми или перекрытыми:
/// притормаживает таймеры и вовсе останавливает анимации композитора. Для
/// вкладки браузера это разумно, а здесь ломает главное движение всего
/// приложения — уход панели вниз. Он начинается ровно в тот момент, когда
/// окно теряет фокус, то есть когда движок уже решил, что рисовать больше
/// незачем: панель замирала на месте и через мгновение просто исчезала
/// вместе с окном.
///
/// Переменную читает WebView2 при создании, поэтому ставится она до сборки
/// приложения.
#[cfg(windows)]
fn keep_rendering_in_background() {
    const FLAGS: &str = "--disable-backgrounding-occluded-windows \
                         --disable-renderer-backgrounding \
                         --disable-background-timer-throttling";

    // SAFETY: единственный поток приложения, до запуска рантайма и WebView2.
    unsafe { std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", FLAGS) };
}

#[cfg(not(windows))]
fn keep_rendering_in_background() {}

fn main() {
    // Держим до конца работы: без этого записи не успевают лечь на диск.
    let _log = setup_logging();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "окно трея запускается");

    keep_rendering_in_background();

    tauri::Builder::default()
        // Второй экземпляр не нужен и вреден: каждый поднимает своего агента
        // сеанса, и два агента начинают наперегонки править одни и те же
        // настройки прокси. Повторный запуск просто показывает уже открытое
        // окно — обычно так и происходит, когда пользователь второй раз
        // нажимает на ярлык, не заметив иконку в трее.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            toggle_window(app);
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(Link::default())
        .invoke_handler(tauri::generate_handler![
            status,
            settings,
            patch,
            daemon_info,
            system_accent,
            connect,
            disconnect,
            probe,
            add_subscription,
            remove_subscription,
            refresh_subscription,
            reveal_subscription,
            subscription_qr,
            open_logs,
            quit,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            let show = MenuItem::with_id(app, "show", "Показать окно", true, None::<&str>)?;
            // Соединением управляет демон: поднимает при запуске, пересобирает
            // при смене настроек, переключает сервер при отказе. В окне поэтому
            // нет кнопки «подключить» — верхняя строка там только сообщает,
            // что происходит.
            //
            // Ручной выключатель всё же нужен: бывает гостиничный портал,
            // который не пускает через туннель, и бывает желание проверить,
            // работает ли что-то без VPN. Меню трея — обычное для Windows
            // место для такого, и оно не спорит с окном за роль главного.
            let toggle = MenuItem::with_id(app, "toggle", "Отключить", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &toggle, &quit_item])?;
            app.manage(ToggleItem(toggle.clone()));

            TrayIconBuilder::with_id("sont")
                .icon(OFFLINE.image())
                .tooltip("Sont")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => toggle_window(app),
                    "toggle" => toggle_connection(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_window(tray.app_handle());
                    }
                })
                .build(app)?;

            // Окно трея исчезает, когда на него перестают смотреть. Иначе оно
            // остаётся поверх всех окон — «alwaysOnTop» здесь ради показа у
            // иконки, а не ради того, чтобы мешать.
            app.manage(LastHidden(std::sync::Mutex::new(None)));

            if let Some(window) = handle.get_webview_window("main") {
                let owner = handle.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::Focused(false) = event {
                        start_hiding(&owner);
                    }
                });
            }

            // Агент живёт ровно столько, сколько открыт трей: он и есть то
            // «что-то в сеансе пользователя», ради чего агент существует.
            app.manage(Agent(std::sync::Mutex::new(spawn_agent())));

            // Связь с демоном поднимаем сразу, не дожидаясь, пока пользователь
            // откроет окно.
            //
            // Раньше соединение устанавливалось при первом запросе из окна —
            // то есть трей мог висеть в углу часами, не подняв службу и не
            // зная о её состоянии. Пользователь запускает приложение, чтобы
            // получить соединение, а не чтобы получить значок.
            let starter = handle.clone();
            tauri::async_runtime::spawn(async move {
                let link = starter.state::<Link>();
                match link.client(&starter).await {
                    Ok(_) => refresh_tray(&starter).await,
                    Err(e) => {
                        tracing::error!(error = %e, "не удалось поднять демон при запуске");
                        update_tray(&starter, "failed");
                    }
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("не удалось собрать окно трея")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // Оставленный агент продолжит держать настройки прокси, за
                // которыми уже никто не следит. Снимаем его вместе с собой.
                if let Some(mut child) = app.state::<Agent>().0.lock().ok().and_then(|mut a| a.take())
                {
                    let _ = child.kill();
                }
            }
        });
}

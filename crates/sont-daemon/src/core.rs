//! Управление процессом ядра Xray.
//!
//! Ядро запускается отдельным процессом, а не встраивается в демон. Так падение
//! ядра не уносит с собой службу, правила firewall и состояние соединения — а
//! именно они нужны, чтобы корректно отработать это падение.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Сколько последних строк вывода ядра держим для диагностики.
const RECENT_LINES: usize = 20;

type RecentOutput = Arc<Mutex<VecDeque<String>>>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("ядро не найдено: {0}")]
    NotFound(PathBuf),

    #[error("контрольная сумма ядра не совпала: ожидалась {expected}, получена {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("не удалось запустить ядро: {0}")]
    Spawn(String),

    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
}

/// Запускатель ядра.
pub struct CoreLauncher {
    binary: PathBuf,
    /// Каталог с geoip.dat и geosite.dat.
    ///
    /// Без них правила вида `geoip:private` не работают, а ядро отказывается
    /// стартовать. Файлы лежат в том же архиве, что и бинарь.
    assets: PathBuf,
    /// Ожидаемая SHA-256 бинаря, если она зафиксирована при поставке.
    expected_sha256: Option<String>,
}

impl CoreLauncher {
    /// Создаёт запускатель.
    ///
    /// Если рядом с бинарём лежит файл `<имя>.sha256`, его содержимое
    /// становится обязательной контрольной суммой. Ядро выполняется с правами
    /// службы, поэтому подменённый бинарь означает исполнение произвольного
    /// кода от SYSTEM; закрепление суммы — то, что отделяет нас от этого,
    /// если каталог установки окажется доступен на запись.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        let binary = binary.into();
        let assets = binary
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let expected_sha256 = read_pinned_checksum(&binary);

        Self {
            binary,
            assets,
            expected_sha256,
        }
    }

    /// Проверяет наличие и целостность бинаря.
    pub fn verify(&self) -> Result<(), CoreError> {
        if !self.binary.is_file() {
            return Err(CoreError::NotFound(self.binary.clone()));
        }

        let Some(expected) = &self.expected_sha256 else {
            return Ok(());
        };

        let actual = sha256_file(&self.binary)?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(CoreError::ChecksumMismatch {
                expected: expected.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Возвращает строку версии ядра.
    pub async fn version(&self) -> Result<String, CoreError> {
        let output = self
            .command()
            .arg("version")
            .output()
            .await
            .map_err(|e| CoreError::Spawn(e.to_string()))?;

        let text = String::from_utf8_lossy(&output.stdout);
        Ok(text
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned())
    }

    // Предварительной проверки конфигурации здесь намеренно нет.
    //
    // Напрашивающийся `xray run -test -c config.json` для этого не годится:
    // он не разбирает конфигурацию всухую, а поднимает inbound-ы — то есть
    // реально создаёт TUN-адаптер. Следующий за ним настоящий запуск получал
    // `ERROR_ALREADY_INITIALIZED`, потому что устройство уже занято проверкой.
    // Ошибки конфигурации всё равно видны: вывод ядра пишется в журнал и
    // попадает в текст ошибки при неудачном старте.

    /// Запускает ядро.
    pub async fn spawn(&self, config: &Path) -> Result<CoreProcess, CoreError> {
        self.verify()?;

        let mut child = self
            .command()
            .arg("run")
            .arg("-c")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CoreError::Spawn(e.to_string()))?;

        // Привязываем ядро к жизни демона.
        //
        // Без этого убитый или закрытый демон оставляет ядро работать, а оно
        // держит маршрут по умолчанию и TUN-адаптер. Пользователь при этом
        // теряет управление: клиент говорит «отключено», а весь трафик
        // по-прежнему уходит в туннель, и следующая попытка подключения
        // упирается в уже занятое устройство.
        job::assign_current(&child);

        // Вывод ядра уходит и в журнал, и в кольцевой буфер: журнал нужен
        // человеку, буфер — чтобы вложить причину в текст ошибки, если ядро
        // умрёт сразу после старта.
        let recent = Arc::new(Mutex::new(VecDeque::with_capacity(RECENT_LINES)));
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pipe_to_log(stdout, "stdout", Arc::clone(&recent)));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pipe_to_log(stderr, "stderr", Arc::clone(&recent)));
        }

        Ok(CoreProcess {
            child: Some(child),
            recent,
        })
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        // Ядро ищет geoip.dat и geosite.dat по этому пути.
        cmd.env("XRAY_LOCATION_ASSET", &self.assets);
        cmd.stdin(Stdio::null());

        // Второй уровень защиты, а не основной: `shutdown()` останавливает
        // ядро явно, но если `CoreProcess` всё же будет отброшен без вызова
        // (забытая передача предыдущей сессии, паника где-то по пути), сам
        // процесс не должен пережить свой Rust-хендл. Без этого один
        // забытый `Started` — это второй `xray.exe`, который держит порт и
        // TUN-адаптер, а из демона на него больше нет ни одной ссылки.
        cmd.kill_on_drop(true);

        #[cfg(windows)]
        {
            // Не показывать окно консоли: демон работает в фоне, и мигающее
            // окно при каждом запуске ядра выглядит как сбой.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        cmd
    }
}

/// Состояние процесса ядра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    Running,
    /// Завершился. Код выхода, если система его сообщила.
    Exited(Option<i32>),
}

/// Запущенное ядро.
pub struct CoreProcess {
    /// `None` — только в тестах конечного автомата, где реальное ядро не
    /// нужно, а нужен сам факт «соединение установлено».
    child: Option<Child>,
    recent: RecentOutput,
}

impl CoreProcess {
    /// Ждёт завершения ядра.
    ///
    /// Используется, чтобы не ждать впустую истечения таймаута готовности:
    /// если ядро умерло через секунду после старта, сообщить об этом надо
    /// сразу, а не через двадцать секунд.
    pub async fn wait_exit(&mut self) -> Option<i32> {
        let child = self.child.as_mut()?;
        child.wait().await.ok().and_then(|s| s.code())
    }

    /// Жив ли процесс ядра.
    ///
    /// Проверка неблокирующая и вызывается из основного цикла supervisor:
    /// иначе упавшее ядро остаётся незамеченным, состояние навсегда
    /// показывает «подключено», а трафик при этом никуда не идёт. Врать о
    /// состоянии соединения — худшее, что может делать VPN-клиент.
    pub fn liveness(&mut self) -> Liveness {
        let Some(child) = self.child.as_mut() else {
            // Заглушка из тестов конечного автомата: считаем её живой.
            return Liveness::Running;
        };

        match child.try_wait() {
            Ok(None) => Liveness::Running,
            Ok(Some(status)) => Liveness::Exited(status.code()),
            Err(e) => {
                // Узнать состояние процесса не удалось. Считать его живым
                // опаснее: тогда мы продолжим утверждать, что соединение есть.
                tracing::warn!(error = %e, "не удалось проверить состояние ядра");
                Liveness::Exited(None)
            }
        }
    }

    /// Последние строки вывода ядра — причина, которую можно показать.
    pub fn recent_output(&self) -> String {
        let Ok(buf) = self.recent.lock() else {
            return String::new();
        };
        buf.iter()
            .rev()
            // Строки старта не несут причины отказа, а место занимают.
            .filter(|l| !l.contains("Xray ") && !l.contains("A unified platform"))
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Останавливает ядро.
    ///
    /// Xray не обрабатывает мягкую остановку на Windows, поэтому завершаем
    /// принудительно. Состояние, которое нужно прибрать (маршруты, firewall),
    /// принадлежит демону, а не ядру, так что терять нечего.
    pub async fn shutdown(self) {
        let Some(mut child) = self.child else {
            return;
        };
        if let Err(e) = child.start_kill() {
            tracing::warn!(error = %e, "не удалось послать сигнал остановки ядру");
        }
        let _ = child.wait().await;
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }

    /// Заглушка для тестов конечного автомата.
    #[cfg(test)]
    pub(crate) fn placeholder() -> Self {
        Self {
            child: None,
            recent: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

async fn pipe_to_log<R>(reader: R, stream: &'static str, recent: RecentOutput)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }
        tracing::info!(target: "xray", %stream, "{line}");

        if let Ok(mut buf) = recent.lock() {
            if buf.len() == RECENT_LINES {
                buf.pop_front();
            }
            buf.push_back(line);
        }
    }
}

/// Привязка дочерних процессов к времени жизни демона.
#[cfg(windows)]
mod job {
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Дескриптор задания живёт столько же, сколько процесс демона.
    ///
    /// Когда демон завершается любым способом — включая аварийное снятие, —
    /// система закрывает дескриптор и убивает все процессы задания.
    struct Job(HANDLE);

    // HANDLE — просто число; система сама следит за его временем жизни.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    static JOB: OnceLock<Option<Job>> = OnceLock::new();

    fn job() -> Option<&'static Job> {
        JOB.get_or_init(|| {
            // SAFETY: создаём безымянное задание с атрибутами по умолчанию.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    "не удалось создать job object; ядро может пережить демон"
                );
                return None;
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
                unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            // SAFETY: структура заполнена и её размер передан корректно.
            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    "не удалось настроить job object"
                );
                return None;
            }

            Some(Job(handle))
        })
        .as_ref()
    }

    /// Включает процесс в задание демона.
    pub fn assign_current(child: &tokio::process::Child) {
        let Some(job) = job() else { return };
        let Some(handle) = child.raw_handle() else {
            return;
        };

        // SAFETY: оба дескриптора получены от системы и валидны на момент вызова.
        let ok = unsafe { AssignProcessToJobObject(job.0, handle as HANDLE) };
        if ok == 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "не удалось привязать ядро к демону; при аварийном завершении оно останется работать"
            );
        }
    }
}

#[cfg(not(windows))]
mod job {
    /// На Unix ядро завершается вместе с группой процессов демона, а systemd
    /// и launchd дополнительно убирают за службой всё дерево.
    pub fn assign_current(_child: &tokio::process::Child) {}
}

/// Похоже ли сообщение ядра на отказ по правам доступа.
///
/// Ядро — сторонний процесс, и текст ошибки локализован системой, поэтому
/// опираемся сразу на несколько признаков: числовой код Windows, английский
/// и русский варианты сообщения, а также характерную для создания адаптера
/// фразу про мьютекс установки устройства.
pub fn looks_like_permission_error(message: &str) -> bool {
    const MARKERS: [&str; 5] = [
        "0x00000005",
        "access is denied",
        "отказано в доступе",
        "device installation mutex",
        "operation not permitted",
    ];

    let lower = message.to_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Читает закреплённую контрольную сумму из файла `<бинарь>.sha256`.
///
/// Файл необязателен: без него проверка целостности не выполняется, и об этом
/// честно сообщается в журнал.
fn read_pinned_checksum(binary: &Path) -> Option<String> {
    let mut path = binary.as_os_str().to_owned();
    path.push(".sha256");
    let path = PathBuf::from(path);

    let raw = std::fs::read_to_string(&path).ok()?;

    // Формат `sha256sum`: «<хэш>  <имя файла>». Берём первое слово.
    let hex = raw.split_whitespace().next()?.to_owned();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        tracing::warn!(path = %path.display(), "закреплённая сумма не похожа на SHA-256, игнорируется");
        return None;
    }

    tracing::info!(path = %path.display(), "контрольная сумма ядра закреплена");
    Some(hex)
}

fn sha256_file(path: &Path) -> Result<String, CoreError> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_reported_clearly() {
        let launcher = CoreLauncher::new("/несуществующий/путь/xray");
        assert!(matches!(launcher.verify(), Err(CoreError::NotFound(_))));
    }

    /// Кладёт бинарь-пустышку и, если задано, файл с закреплённой суммой.
    fn fake_core(dir: &Path, content: &str, pinned: Option<&str>) -> PathBuf {
        let path = dir.join("fake-core");
        std::fs::write(&path, content).unwrap();

        let sums = dir.join("fake-core.sha256");
        match pinned {
            // Формат `sha256sum`: хэш, два пробела, имя файла.
            Some(hex) => std::fs::write(&sums, format!("{hex}  fake-core\n")).unwrap(),
            None => {
                let _ = std::fs::remove_file(&sums);
            }
        }
        path
    }

    #[test]
    fn checksum_mismatch_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_core(dir.path(), "содержимое", Some(&"0".repeat(64)));

        match CoreLauncher::new(&path).verify() {
            Err(CoreError::ChecksumMismatch { actual, .. }) => {
                assert_eq!(actual.len(), 64, "хэш должен быть шестнадцатеричным SHA-256");
            }
            other => panic!("ожидалось несовпадение суммы, получено {other:?}"),
        }
    }

    #[test]
    fn matching_checksum_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_core(dir.path(), "содержимое", None);
        let actual = sha256_file(&path).unwrap();

        let path = fake_core(dir.path(), "содержимое", Some(&actual));
        assert!(CoreLauncher::new(&path).verify().is_ok());
    }

    #[test]
    fn checksum_comparison_ignores_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_core(dir.path(), "x", None);
        let upper = sha256_file(&path).unwrap().to_uppercase();

        let path = fake_core(dir.path(), "x", Some(&upper));
        assert!(CoreLauncher::new(&path).verify().is_ok());
    }

    #[test]
    fn malformed_pinned_checksum_is_ignored_rather_than_blocking_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_core(dir.path(), "x", Some("не хэш"));
        assert!(
            CoreLauncher::new(&path).verify().is_ok(),
            "испорченный файл суммы не должен делать ядро незапускаемым"
        );
    }

    #[test]
    fn verification_is_skipped_when_no_checksum_is_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let path = fake_core(dir.path(), "x", None);
        assert!(CoreLauncher::new(&path).verify().is_ok());
    }

    #[test]
    fn assets_directory_defaults_to_the_binary_location() {
        let launcher = CoreLauncher::new("/opt/sont/core/xray");
        assert_eq!(launcher.assets, PathBuf::from("/opt/sont/core"));
    }

    #[test]
    fn recent_output_skips_banner_lines() {
        // В причине отказа баннер запуска бесполезен, а место занимает.
        let core = CoreProcess::placeholder();
        {
            let mut buf = core.recent.lock().unwrap();
            buf.push_back("Xray 26.3.27 (Xray, Penetrates Everything.)".into());
            buf.push_back("A unified platform for anti-censorship.".into());
            buf.push_back("Failed to register rings: ERROR_ALREADY_INITIALIZED".into());
        }
        assert_eq!(
            core.recent_output(),
            "Failed to register rings: ERROR_ALREADY_INITIALIZED"
        );
    }

    #[test]
    fn recent_output_is_empty_without_any_lines() {
        assert!(CoreProcess::placeholder().recent_output().is_empty());
    }

    #[test]
    fn permission_failures_are_recognised_in_both_languages() {
        // Настоящее сообщение, полученное при запуске без прав администратора.
        assert!(looks_like_permission_error(
            "Failed to take device installation mutex: Отказано в доступе. (Code 0x00000005)"
        ));
        assert!(looks_like_permission_error(
            "Failed to create adapter: Access is denied."
        ));
        assert!(looks_like_permission_error("open /dev/net/tun: operation not permitted"));
    }

    #[test]
    fn genuine_config_errors_are_not_mistaken_for_permission_problems() {
        assert!(!looks_like_permission_error(
            "main: failed to load config: unknown transport xhttp"
        ));
        assert!(!looks_like_permission_error(""));
    }
}

//! Транспорт поверх unix-сокета.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use tokio::net::{UnixListener, UnixStream};

use crate::endpoint::SOCKET_MODE;
use crate::peer::PeerIdentity;

pub type ServerStream = UnixStream;
pub type ClientStream = UnixStream;

/// Слушатель unix-сокета.
pub struct IpcListener {
    inner: UnixListener,
    path: PathBuf,
}

impl IpcListener {
    pub fn bind(addr: &str) -> io::Result<Self> {
        let path = PathBuf::from(addr);

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }

        // Осиротевший сокет от прошлого запуска не даёт забиндиться. Демон —
        // единственный владелец этого пути, так что удалить его безопасно.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        // Права выставляем через umask *до* bind, а не chmod после.
        //
        // Иначе между созданием сокета и chmod существует окно, в котором
        // права определяются umask процесса — обычно 0755, то есть подключиться
        // может кто угодно. Для канала управления службой, работающей от root,
        // такое окно недопустимо.
        //
        // SAFETY: umask — процессный вызов без указателей. Он глобальный, и
        // здесь мы полагаемся на то, что bind слушателя происходит на старте
        // демона, до появления других потоков, работающих с файлами.
        let previous = unsafe { libc::umask(0o177) };
        let bound = UnixListener::bind(&path);
        // SAFETY: восстанавливаем ровно то значение, что вернул предыдущий вызов.
        unsafe { libc::umask(previous) };
        let inner = bound?;

        // Сокет создан с 0600. Расширяем до 0660: группу `sont` назначает
        // установщик, и именно через неё tray получает доступ.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))?;

        Ok(Self { inner, path })
    }

    pub async fn accept(&mut self) -> io::Result<(UnixStream, PeerIdentity)> {
        let (stream, _) = self.inner.accept().await?;
        let peer = identify(&stream);
        Ok((stream, peer))
    }
}

impl Drop for IpcListener {
    fn drop(&mut self) {
        // Не оставляем за собой файл сокета: иначе следующий запуск упрётся в
        // «address already in use», а пользователь — в неработающий клиент.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn identify(stream: &UnixStream) -> PeerIdentity {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: fd принадлежит живому потоку, буфер и его длина согласованы.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return PeerIdentity::default();
    }

    let pid = u32::try_from(cred.pid).ok();
    PeerIdentity {
        pid,
        uid: Some(cred.uid),
        gid: Some(cred.gid),
        // /proc/<pid>/exe — симлинк на исполняемый файл. Читаем без
        // канонизации: политика допуска канонизирует сама.
        exe_path: pid.and_then(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok()),
    }
}

#[cfg(target_os = "macos")]
fn identify(stream: &UnixStream) -> PeerIdentity {
    /// Уровень опций локального сокета на macOS.
    const SOL_LOCAL: libc::c_int = 0;
    /// Идентификатор процесса на другом конце.
    const LOCAL_PEERPID: libc::c_int = 0x002;

    let fd = stream.as_raw_fd();

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: fd валиден, оба указателя ведут на стек.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return PeerIdentity::default();
    }

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: то же самое; неуспех обрабатывается ниже.
    let pid_rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };

    PeerIdentity {
        pid: if pid_rc == 0 {
            u32::try_from(pid).ok()
        } else {
            None
        },
        uid: Some(uid),
        gid: Some(gid),
        // Путь к образу процесса на macOS требует libproc; политика допуска
        // здесь опирается на uid, а не на путь.
        exe_path: None,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn identify(_stream: &UnixStream) -> PeerIdentity {
    // На прочих Unix механизм получения учётных данных пира отличается.
    // Возвращаем пустую личность: политика по умолчанию такое соединение
    // отклонит, и это правильнее, чем пустить непроверенного клиента.
    PeerIdentity::default()
}

pub async fn connect(addr: &str) -> io::Result<UnixStream> {
    UnixStream::connect(addr).await
}

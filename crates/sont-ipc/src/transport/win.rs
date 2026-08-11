//! Транспорт поверх named pipe.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_PIPE_BUSY, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::endpoint::PIPE_SDDL;
use crate::peer::PeerIdentity;

pub type ServerStream = NamedPipeServer;
pub type ClientStream = NamedPipeClient;

/// Дескриптор безопасности, освобождаемый при уничтожении.
struct SecurityDescriptor(*mut c_void);

// Указатель на дескриптор безопасности после создания только читается
// системными вызовами, поэтому его безопасно держать в структуре слушателя,
// которая живёт в одной задаче.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd: *mut c_void = std::ptr::null_mut();

        // SAFETY: `wide` — валидная строка, завершённая нулём; `psd` —
        // корректный указатель на выходной параметр. Освобождение — в Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1, // SDDL_REVISION_1
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(psd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: указатель получен от Convert…SecurityDescriptorW,
            // который документированно требует освобождения через LocalFree.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Слушатель named pipe.
pub struct IpcListener {
    addr: String,
    /// Заранее созданный незанятый экземпляр канала.
    ///
    /// Named pipe устроен не как TCP-сокет: экземпляр создаётся до
    /// подключения клиента, и следующий надо создать сразу после того, как
    /// текущий занят. Если этого не делать, между `accept` образуется окно, в
    /// котором клиент получает ERROR_FILE_NOT_FOUND.
    pending: Option<NamedPipeServer>,
    security: SecurityDescriptor,
}

impl IpcListener {
    /// Открывает канал с дескриптором безопасности из [`PIPE_SDDL`].
    pub fn bind(addr: &str) -> io::Result<Self> {
        let security = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
        let pending = create_instance(addr, &security, true)?;
        Ok(Self {
            addr: addr.to_owned(),
            pending: Some(pending),
            security,
        })
    }

    /// Ждёт клиента и возвращает поток вместе с тем, что удалось о нём узнать.
    pub async fn accept(&mut self) -> io::Result<(NamedPipeServer, PeerIdentity)> {
        let server = match self.pending.take() {
            Some(s) => s,
            None => create_instance(&self.addr, &self.security, false)?,
        };

        server.connect().await?;

        // Готовим следующий экземпляр до того, как отдать текущий наверх.
        self.pending = Some(create_instance(&self.addr, &self.security, false)?);

        let peer = identify(&server);
        Ok((server, peer))
    }
}

fn create_instance(
    addr: &str,
    security: &SecurityDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };

    // SAFETY: `attrs` живёт до конца вызова, `lpSecurityDescriptor` указывает
    // на валидный дескриптор, владелец которого переживёт создание канала.
    unsafe {
        ServerOptions::new()
            // Первый экземпляр создаём с флагом эксклюзивности: если канал с
            // таким именем уже существует, вызов упадёт. Это правильное
            // поведение — значит, имя занял кто-то другой, и «поделиться» с
            // ним каналом управления службой нельзя.
            .first_pipe_instance(first)
            // Канал только локальный.
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(addr, &mut attrs as *mut _ as *mut c_void)
    }
}

/// Достаёт pid клиента и путь к его исполняемому файлу.
///
/// Ошибки не фатальны: политика допуска сама решит, что делать с неполной
/// информацией. Здесь важно не выдать неверные сведения за верные.
fn identify(server: &NamedPipeServer) -> PeerIdentity {
    let handle = server.as_raw_handle() as HANDLE;
    let mut pid: u32 = 0;

    // SAFETY: handle принадлежит живому объекту `server`, `pid` — валидный
    // указатель на стек.
    let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) };
    if ok == 0 {
        return PeerIdentity::default();
    }

    PeerIdentity {
        pid: Some(pid),
        exe_path: process_image_path(pid),
        ..Default::default()
    }
}

fn process_image_path(pid: u32) -> Option<PathBuf> {
    // PROCESS_QUERY_LIMITED_INFORMATION хватает для имени образа и, в отличие
    // от PROCESS_QUERY_INFORMATION, работает для процессов другого уровня
    // целостности — то есть для обычного пользовательского tray.
    // SAFETY: параметры примитивные, результат проверяется.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buf = [0u16; 32_768];
    let mut len = buf.len() as u32;

    // SAFETY: handle валиден, буфер и длина согласованы.
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    // SAFETY: handle получен из OpenProcess и больше не используется.
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
}

/// Подключается к каналу демона.
pub async fn connect(addr: &str) -> io::Result<NamedPipeClient> {
    // Все экземпляры канала могут быть заняты — это штатная гонка, а не
    // ошибка. Windows на этот случай возвращает ERROR_PIPE_BUSY и ожидает,
    // что клиент подождёт и повторит.
    const ATTEMPTS: u32 = 20;
    const DELAY: Duration = Duration::from_millis(50);

    for _ in 0..ATTEMPTS {
        match ClientOptions::new().open(addr) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "все экземпляры канала заняты",
    ))
}

//! Платформенный транспорт: named pipe на Windows, unix-сокет на macOS/Linux.
//!
//! Оба варианта дают одинаковый интерфейс: [`IpcListener::bind`] +
//! [`IpcListener::accept`], возвращающий поток вместе с личностью пира, и
//! [`connect`] на стороне клиента.

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::{connect, ClientStream, IpcListener, ServerStream};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{connect, ClientStream, IpcListener, ServerStream};

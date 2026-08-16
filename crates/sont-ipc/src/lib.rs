//! Локальный IPC между демоном `sontd` и tray-приложением.
//!
//! # Почему не готовый RPC-фреймворк
//!
//! Требования к этому каналу нестандартные: он обязан быть строго локальным,
//! обязан устанавливать личность процесса на другом конце и обязан работать
//! поверх named pipe на Windows и unix-сокета на macOS/Linux с *разными*
//! моделями разграничения доступа (SDDL против прав на inode). Любая
//! кроссплатформенная абстракция здесь протекает ровно в том месте, которое
//! для нас критично, поэтому транспорт написан на tokio напрямую: на Windows
//! `tokio::net::windows::named_pipe`, на Unix `tokio::net::UnixListener`.
//!
//! # Формат
//!
//! Кадры длиной-префиксом (u32 BE) с JSON внутри. Один и тот же канал несёт
//! ответы (с `id` запроса) и события (без `id`).
//!
//! # Граница безопасности
//!
//! Демон работает от SYSTEM/root, клиент — от обычного пользователя. Поэтому:
//!
//! * протокол не принимает сырой конфиг ядра, только типизированные структуры
//!   (см. [`sont_core::Transport`]);
//! * наружу уходят [`ServerView`] без учётных данных — UI незачем знать UUID и
//!   пароли, а лишняя копия секрета в непривилегированном процессе это лишняя
//!   поверхность атаки;
//! * каждое соединение проходит проверку личности пира (см. [`peer`]).

pub mod client;
pub mod codec;
pub mod endpoint;
pub mod peer;
pub mod protocol;
pub mod server;
pub mod transport;

pub use client::{Client, ClientError};
pub use endpoint::endpoint_name;
pub use peer::{AuthPolicy, PeerIdentity};
pub use protocol::{
    DaemonInfo, Event, Frame, Hello, IpcError, ProxyEndpoints, Request, Response, ServerFailure,
    ServerView, StatusSnapshot, SubscriptionStatus,
};
pub use sont_core::PROTOCOL_VERSION;

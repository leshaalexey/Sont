//! Клиентская сторона: используется tray-приложением и CLI `sontd`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::Framed;

use crate::codec::{CodecError, FrameCodec};
use crate::protocol::{Event, Frame, Hello, IpcError, Request, Response};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Демон не запущен или канал недоступен. Самая частая и самая важная для
    /// UI ошибка: показывать надо «служба не запущена», а не общий сбой.
    #[error("демон недоступен: {0}")]
    Unavailable(#[source] std::io::Error),

    #[error("версии протокола не совпадают: демон {daemon}, приложение {client}")]
    ProtocolMismatch { daemon: u32, client: u32 },

    #[error("демон разорвал соединение")]
    Disconnected,

    #[error("ошибка протокола: {0}")]
    Codec(#[from] CodecError),

    #[error(transparent)]
    Ipc(#[from] IpcError),
}

/// Подключение к демону.
///
/// Клонируется дёшево: сам сокет обслуживает фоновая задача, а `Client` —
/// только ручка к ней.
#[derive(Clone, Debug)]
pub struct Client {
    outbox: mpsc::Sender<Pending>,
    next_id: Arc<AtomicU64>,
}

struct Pending {
    request: Request,
    reply: oneshot::Sender<Response>,
}

impl Client {
    /// Подключается, здоровается и проверяет версию протокола.
    ///
    /// Возвращает ручку и поток событий. Событий не будет, пока не отправлен
    /// [`Request::SubscribeEvents`].
    pub async fn connect(
        addr: &str,
        agent_version: impl Into<String>,
    ) -> Result<(Self, mpsc::Receiver<Event>), ClientError> {
        let stream = crate::transport::connect(addr)
            .await
            .map_err(ClientError::Unavailable)?;
        let mut framed = Framed::new(stream, FrameCodec::new());

        framed
            .send(Frame::Hello(Hello::new(agent_version)))
            .await?;

        match framed.next().await {
            Some(Ok(Frame::Hello(hello))) => {
                if !hello.is_compatible() {
                    return Err(ClientError::ProtocolMismatch {
                        daemon: hello.protocol_version,
                        client: sont_core::PROTOCOL_VERSION,
                    });
                }
            }
            // Демон отвечает на неудачное рукопожатие событием-ошибкой:
            // несовместимая версия или отказ в допуске.
            Some(Ok(Frame::Event(Event::Error(e)))) => return Err(ClientError::Ipc(e)),
            Some(Ok(_)) => return Err(ClientError::Disconnected),
            Some(Err(e)) => return Err(ClientError::Codec(e)),
            None => return Err(ClientError::Disconnected),
        }

        let (outbox_tx, outbox_rx) = mpsc::channel::<Pending>(64);
        let (event_tx, event_rx) = mpsc::channel::<Event>(256);

        tokio::spawn(pump(framed, outbox_rx, event_tx));

        Ok((
            Self {
                outbox: outbox_tx,
                next_id: Arc::new(AtomicU64::new(1)),
            },
            event_rx,
        ))
    }

    /// Отправляет запрос и ждёт ответ.
    ///
    /// Ошибку уровня IPC разворачивает в `Err`, чтобы вызывающему коду не
    /// приходилось каждый раз разбирать `Response::Error` вручную.
    pub async fn request(&self, request: Request) -> Result<Response, ClientError> {
        let (tx, rx) = oneshot::channel();
        self.outbox
            .send(Pending { request, reply: tx })
            .await
            .map_err(|_| ClientError::Disconnected)?;

        match rx.await.map_err(|_| ClientError::Disconnected)? {
            Response::Error(e) => Err(ClientError::Ipc(e)),
            other => Ok(other),
        }
    }

    /// Идентификатор для следующего запроса — на случай, если вызывающему коду
    /// нужна собственная корреляция.
    pub fn next_request_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// Фоновая задача: единственная, кто трогает сокет.
///
/// Сопоставляет ответы с запросами по `id` и раздаёт события. Держать это в
/// одной задаче проще и надёжнее, чем разделять сокет на половины и
/// синхронизировать доступ.
async fn pump(
    mut framed: Framed<crate::transport::ClientStream, FrameCodec>,
    mut outbox: mpsc::Receiver<Pending>,
    events: mpsc::Sender<Event>,
) {
    let mut waiting: HashMap<u64, oneshot::Sender<Response>> = HashMap::new();
    let mut next_id: u64 = 1;

    loop {
        tokio::select! {
            outgoing = outbox.recv() => {
                let Some(pending) = outgoing else { break };
                let id = next_id;
                next_id += 1;

                if let Err(e) = framed.send(Frame::Request { id, payload: pending.request }).await {
                    tracing::debug!(error = %e, "не удалось отправить запрос");
                    let _ = pending.reply.send(Response::Error(IpcError::Internal {
                        detail: "соединение с демоном потеряно".into(),
                    }));
                    break;
                }
                waiting.insert(id, pending.reply);
            }

            incoming = framed.next() => {
                match incoming {
                    Some(Ok(Frame::Response { id, payload })) => {
                        if let Some(tx) = waiting.remove(&id) {
                            let _ = tx.send(payload);
                        } else {
                            tracing::debug!(id, "ответ на неизвестный запрос");
                        }
                    }
                    Some(Ok(Frame::Event(ev))) => {
                        // Переполнение канала событий означает, что UI не
                        // успевает. Роняем событие, а не соединение.
                        if events.try_send(ev).is_err() {
                            tracing::debug!("очередь событий переполнена, событие отброшено");
                        }
                    }
                    Some(Ok(Frame::Hello(_))) | Some(Ok(Frame::Request { .. })) => {
                        tracing::debug!("неожиданный кадр от демона");
                    }
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "ошибка чтения кадра");
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    // Разрыв соединения не должен оставить вызывающий код висеть на await.
    for (_, tx) in waiting {
        let _ = tx.send(Response::Error(IpcError::Internal {
            detail: "соединение с демоном потеряно".into(),
        }));
    }
}

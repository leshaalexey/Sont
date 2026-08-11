//! Серверная сторона: приём соединений, рукопожатие, допуск, обслуживание.
//!
//! Сервер намеренно не знает ничего о туннеле. Он превращает кадры в
//! [`Command`] и отдаёт их наверх — состоянием владеет supervisor демона, и
//! только он. Так исключается вторая копия истины, которая иначе неизбежно
//! разъедется с первой.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::codec::Framed;

use crate::codec::FrameCodec;
use crate::peer::{AuthPolicy, PeerIdentity};
use crate::protocol::{Event, Frame, Hello, IpcError, Request, Response};
use crate::transport::IpcListener;

/// Запрос, переданный наверх, вместе с каналом для ответа.
#[derive(Debug)]
pub struct Command {
    pub request: Request,
    pub peer: PeerIdentity,
    pub reply: oneshot::Sender<Response>,
}

/// Размер очереди событий на одного подписчика.
///
/// Если UI не успевает читать, старые события теряются, а подписчик получает
/// уведомление об отставании. Это правильный компромисс: состояние всё равно
/// передаётся целиком в каждом `StateChanged`, и лучше пропустить промежуточные
/// значения, чем раздувать память демона из-за подвисшего окна.
const EVENT_BUFFER: usize = 256;

pub struct IpcServer {
    listener: IpcListener,
    commands: mpsc::Sender<Command>,
    events: broadcast::Sender<Event>,
    policy: Arc<dyn AuthPolicy>,
    agent_version: String,
}

impl IpcServer {
    /// Открывает слушатель.
    pub fn bind(
        addr: &str,
        commands: mpsc::Sender<Command>,
        policy: Arc<dyn AuthPolicy>,
        agent_version: impl Into<String>,
    ) -> std::io::Result<(Self, broadcast::Sender<Event>)> {
        let listener = IpcListener::bind(addr)?;
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let server = Self {
            listener,
            commands,
            events: events.clone(),
            policy,
            agent_version: agent_version.into(),
        };
        Ok((server, events))
    }

    /// Крутит цикл приёма соединений до отмены.
    pub async fn run(mut self) {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    // Обрыв одного соединения не повод останавливать службу:
                    // упавший клиент не должен уносить с собой VPN.
                    tracing::warn!(error = %e, "не удалось принять соединение");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            let commands = self.commands.clone();
            let events = self.events.clone();
            let policy = Arc::clone(&self.policy);
            let version = self.agent_version.clone();

            tokio::spawn(async move {
                if let Err(e) = serve_connection(stream, peer.clone(), commands, events, policy, version).await {
                    tracing::debug!(peer = %peer.describe(), error = %e, "соединение завершено");
                }
            });
        }
    }
}

async fn serve_connection(
    stream: crate::transport::ServerStream,
    peer: PeerIdentity,
    commands: mpsc::Sender<Command>,
    events: broadcast::Sender<Event>,
    policy: Arc<dyn AuthPolicy>,
    agent_version: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut framed = Framed::new(stream, FrameCodec::new());

    // ── 1. Рукопожатие ───────────────────────────────────────────────
    let Some(first) = framed.next().await else {
        return Ok(()); // клиент отсоединился, не представившись
    };
    let Frame::Hello(hello) = first? else {
        // Первым кадром обязан быть Hello. Всё остальное — либо старый
        // клиент, либо что-то, что тут делать не должно.
        framed
            .send(Frame::Event(Event::Error(IpcError::InvalidRequest {
                detail: "первым кадром должен быть hello".into(),
            })))
            .await?;
        return Ok(());
    };

    if !hello.is_compatible() {
        tracing::warn!(
            peer = %peer.describe(),
            client = hello.protocol_version,
            daemon = sont_core::PROTOCOL_VERSION,
            "несовместимая версия протокола"
        );
        framed
            .send(Frame::Event(Event::Error(IpcError::ProtocolMismatch {
                daemon: sont_core::PROTOCOL_VERSION,
                client: hello.protocol_version,
            })))
            .await?;
        return Ok(());
    }

    // ── 2. Допуск ────────────────────────────────────────────────────
    if let Err(reason) = policy.authorize(&peer) {
        tracing::warn!(peer = %peer.describe(), %reason, "отказано в доступе");
        framed
            .send(Frame::Event(Event::Error(IpcError::Unauthorized {
                detail: reason,
            })))
            .await?;
        return Ok(());
    }

    tracing::info!(
        peer = %peer.describe(),
        client_version = %hello.agent_version,
        "клиент подключён"
    );
    framed.send(Frame::Hello(Hello::new(agent_version))).await?;

    // ── 3. Обслуживание ──────────────────────────────────────────────
    // Получателя создаём в момент подписки, а не при подключении.
    //
    // Разница не косметическая. Во-первых, `broadcast::Receiver` копит
    // сообщения с момента создания, так что ранняя подписка привела бы к
    // выдаче пачки устаревших событий сразу после `SubscribeEvents`.
    // Во-вторых, `receiver_count()` — это то, по чему supervisor решает,
    // считать ли статистику вообще; если подписываться заранее, счётчик
    // всегда ненулевой и экономия теряется.
    let mut subscription: Option<broadcast::Receiver<Event>> = None;

    loop {
        tokio::select! {
            incoming = framed.next() => {
                let Some(frame) = incoming else { break };
                let Frame::Request { id, payload } = frame? else {
                    framed.send(Frame::Event(Event::Error(IpcError::InvalidRequest {
                        detail: "клиент может присылать только запросы".into(),
                    }))).await?;
                    continue;
                };

                if matches!(payload, Request::SubscribeEvents) {
                    if subscription.is_none() {
                        subscription = Some(events.subscribe());
                    }
                    framed.send(Frame::Response { id, payload: Response::Accepted }).await?;
                    continue;
                }

                let (tx, rx) = oneshot::channel();
                if commands.send(Command { request: payload, peer: peer.clone(), reply: tx }).await.is_err() {
                    // Supervisor больше не принимает команды — демон
                    // останавливается.
                    framed.send(Frame::Response {
                        id,
                        payload: Response::Error(IpcError::NotReady),
                    }).await?;
                    break;
                }

                let response = rx.await.unwrap_or(Response::Error(IpcError::Internal {
                    detail: "обработчик не ответил".into(),
                }));
                framed.send(Frame::Response { id, payload: response }).await?;
            }

            // Пока подписки нет, ветка никогда не срабатывает: `pending`
            // не завершается, и select просто ждёт входящие кадры.
            event = async {
                match subscription.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Ok(ev) => framed.send(Frame::Event(ev)).await?,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!(skipped = n, peer = %peer.describe(), "подписчик отстаёт");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    tracing::info!(peer = %peer.describe(), "клиент отключён");
    Ok(())
}

//! Сквозные тесты транспорта: настоящий named pipe / unix-сокет, настоящее
//! рукопожатие, настоящая проверка пира.
//!
//! Юнит-тесты кодека проверяют разбор кадров, но не отвечают на главный
//! вопрос — поднимается ли канал с нужным дескриптором безопасности и удаётся
//! ли опознать подключившийся процесс. Проверяется это только вживую.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sont_ipc::peer::DefaultPolicy;
use sont_ipc::protocol::{Event, IpcError, Request, Response, StatusSnapshot};
use sont_ipc::server::{Command, IpcServer};
use sont_ipc::{Client, ClientError};
use sont_core::{Stats, TunnelState};
use tokio::sync::{broadcast, mpsc};

/// Уникальное имя точки подключения, чтобы параллельные тесты не мешали друг
/// другу и не цеплялись за рабочий канал демона.
fn unique_endpoint(tag: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    #[cfg(windows)]
    {
        format!(r"\\.\pipe\sont-test-{tag}-{pid}-{n}")
    }
    #[cfg(unix)]
    {
        format!("{}/sont-test-{tag}-{pid}-{n}.sock", std::env::temp_dir().display())
    }
}

/// Поднимает сервер, отвечающий на запросы функцией `handler`.
fn spawn_server<F>(addr: &str, handler: F) -> broadcast::Sender<Event>
where
    F: Fn(Request) -> Response + Send + 'static,
{
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(16);
    let (server, events) =
        IpcServer::bind(addr, cmd_tx, Arc::new(DefaultPolicy::new()), "test-daemon")
            .expect("слушатель должен открыться");

    tokio::spawn(server.run());
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            let _ = cmd.reply.send(handler(cmd.request));
        }
    });

    events
}

fn snapshot() -> StatusSnapshot {
    StatusSnapshot {
        state: TunnelState::default(),
        stats: Stats::default(),
        subscription: None,
        server_count: 0,
        proxy: None,
    }
}

#[tokio::test]
async fn request_response_roundtrip_over_real_transport() {
    let addr = unique_endpoint("rr");
    spawn_server(&addr, |req| match req {
        Request::GetStatus => Response::Status(snapshot()),
        _ => Response::Accepted,
    });

    let (client, _events) = Client::connect(&addr, "test-client")
        .await
        .expect("клиент должен подключиться");

    let response = client.request(Request::GetStatus).await.unwrap();
    match response {
        Response::Status(s) => assert_eq!(s.state, TunnelState::default()),
        other => panic!("ожидался Status, получено {other:?}"),
    }

    // Второй запрос по тому же соединению — проверяем, что сопоставление
    // ответов по id работает не только для первого.
    assert_eq!(
        client.request(Request::Disconnect).await.unwrap(),
        Response::Accepted
    );
}

#[tokio::test]
async fn events_arrive_only_after_subscription() {
    let addr = unique_endpoint("ev");
    let events = spawn_server(&addr, |_| Response::Accepted);

    let (client, mut rx) = Client::connect(&addr, "test-client").await.unwrap();

    // До подписки события уходить не должны: пока UI закрыт, демону незачем
    // рассылать статистику.
    let _ = events.send(Event::Stats(Stats {
        up_bps: 111,
        ..Default::default()
    }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        rx.try_recv().is_err(),
        "событие пришло без подписки"
    );

    client.request(Request::SubscribeEvents).await.unwrap();
    // Даём серверу дойти до ветки подписки.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sent = Event::Stats(Stats {
        up_bps: 42,
        down_bps: 84,
        ..Default::default()
    });
    events.send(sent.clone()).unwrap();

    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("событие не пришло за отведённое время")
        .expect("канал событий закрыт");
    assert_eq!(got, sent);
}

#[tokio::test]
async fn several_clients_are_served_concurrently() {
    // Named pipe требует заранее создавать следующий экземпляр канала.
    // Если этого не делать, второй клиент упирается в «файл не найден».
    let addr = unique_endpoint("multi");
    spawn_server(&addr, |_| Response::Status(snapshot()));

    let (a, _ea) = Client::connect(&addr, "client-a").await.unwrap();
    let (b, _eb) = Client::connect(&addr, "client-b").await.unwrap();

    let (ra, rb) = tokio::join!(a.request(Request::GetStatus), b.request(Request::GetStatus));
    assert!(matches!(ra.unwrap(), Response::Status(_)));
    assert!(matches!(rb.unwrap(), Response::Status(_)));
}

#[tokio::test]
async fn peer_identity_is_established() {
    // Ради этого весь платформенный код и написан: демон обязан знать, кто к
    // нему подключился. Клиент здесь — текущий тестовый процесс.
    let addr = unique_endpoint("peer");

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(16);
    let (server, _events) =
        IpcServer::bind(&addr, cmd_tx, Arc::new(DefaultPolicy::new()), "test-daemon").unwrap();
    tokio::spawn(server.run());

    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Some(cmd) = cmd_rx.recv().await {
            let _ = seen_tx.send(cmd.peer.clone());
            let _ = cmd.reply.send(Response::Accepted);
        }
    });

    let (client, _rx) = Client::connect(&addr, "test-client").await.unwrap();
    client.request(Request::GetStatus).await.unwrap();

    let peer = tokio::time::timeout(Duration::from_secs(2), seen_rx)
        .await
        .expect("команда не дошла")
        .unwrap();

    assert!(
        peer.pid.is_some() || peer.uid.is_some(),
        "личность пира не установлена: {peer:?}"
    );

    #[cfg(windows)]
    {
        assert_eq!(
            peer.pid,
            Some(std::process::id()),
            "pid клиента должен совпадать с текущим процессом"
        );
        let exe = peer.exe_path.expect("путь к образу процесса не определён");
        assert!(
            exe.exists(),
            "определённый путь к клиенту должен существовать: {}",
            exe.display()
        );
    }
}

#[tokio::test]
async fn unauthorized_client_is_rejected_at_handshake() {
    /// Политика, отвергающая всех, — имитация клиента не из каталога установки.
    struct DenyAll;
    impl sont_ipc::AuthPolicy for DenyAll {
        fn authorize(&self, _peer: &sont_ipc::PeerIdentity) -> Result<(), String> {
            Err("клиент запущен вне каталога установки".to_owned())
        }
    }

    let addr = unique_endpoint("deny");
    let (cmd_tx, _cmd_rx) = mpsc::channel::<Command>(16);
    let (server, _events) =
        IpcServer::bind(&addr, cmd_tx, Arc::new(DenyAll), "test-daemon").unwrap();
    tokio::spawn(server.run());

    let err = Client::connect(&addr, "test-client")
        .await
        .expect_err("подключение должно быть отклонено");

    match err {
        ClientError::Ipc(IpcError::Unauthorized { detail }) => {
            assert!(detail.contains("каталога установки"));
        }
        other => panic!("ожидался отказ в доступе, получено {other:?}"),
    }
}

#[tokio::test]
async fn missing_daemon_reports_unavailable() {
    // Самая частая ситуация у пользователя: служба не запущена. UI обязан
    // отличать её от прочих сбоев, чтобы предложить запустить службу.
    let addr = unique_endpoint("absent");
    let err = Client::connect(&addr, "test-client")
        .await
        .expect_err("подключения быть не должно");
    assert!(
        matches!(err, ClientError::Unavailable(_)),
        "ожидался Unavailable, получено {err:?}"
    );
}

#[tokio::test]
async fn client_survives_daemon_going_away() {
    // Демон может перезапуститься (обновление, падение). Клиент обязан
    // получить ошибку, а не зависнуть навсегда на await.
    let addr = unique_endpoint("drop");
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(16);
    let (server, _events) =
        IpcServer::bind(&addr, cmd_tx, Arc::new(DefaultPolicy::new()), "test-daemon").unwrap();
    let handle = tokio::spawn(server.run());

    let (client, _rx) = Client::connect(&addr, "test-client").await.unwrap();

    // Обработчик команд исчезает — supervisor «остановился».
    drop(cmd_rx);
    handle.abort();

    let result = tokio::time::timeout(Duration::from_secs(3), client.request(Request::GetStatus))
        .await
        .expect("запрос завис вместо того, чтобы вернуть ошибку");
    assert!(result.is_err(), "ожидалась ошибка, получено {result:?}");
}

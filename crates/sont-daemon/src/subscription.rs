//! Получение подписки по HTTP.

use std::time::Duration;

use sont_core::{Secret, ServerProfile, SubscriptionId, SubscriptionInfo};

/// Сколько ждём ответа панели.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Потолок размера тела подписки.
///
/// Осмысленная подписка — это единицы килобайт. Ограничение защищает от
/// сломанной или враждебной панели, отдающей бесконечный поток: демон работает
/// от SYSTEM/root, и раздувать его память по указке внешнего сервера нельзя.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// User-Agent, под которым мы приходим к панели.
///
/// Панели отдают разный формат в зависимости от UA: для одних клиентов —
/// base64-список ссылок, для других — YAML или JSON. Под своим именем мы, как
/// неизвестный клиент, обычно получаем именно список ссылок, что нам и нужно.
const USER_AGENT: &str = concat!("Sont/", env!("CARGO_PKG_VERSION"));

/// Запасной User-Agent.
///
/// Часть панелей на незнакомый UA отвечает страницей личного кабинета вместо
/// подписки. В этом случае повторяем запрос под именем распространённого
/// клиента — иначе пользователь получает «в подписке нет серверов» и не имеет
/// никакой возможности понять, почему.
const FALLBACK_USER_AGENT: &str = "v2rayNG/1.9.16";

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("ссылка подписки некорректна: {0}")]
    BadUrl(String),

    #[error("панель недоступна: {0}")]
    Network(String),

    #[error("панель ответила кодом {0}")]
    Status(u16),

    #[error("ответ панели больше {} МиБ", MAX_BODY_BYTES / 1024 / 1024)]
    TooLarge,

    #[error("ответ панели не является текстом")]
    NotText,

    #[error("в подписке не найдено поддерживаемых серверов (пропущено строк: {skipped})")]
    NoServers { skipped: usize },
}

/// Результат успешного получения подписки.
#[derive(Debug)]
pub struct Fetched {
    pub profiles: Vec<ServerProfile>,
    pub info: SubscriptionInfo,
    /// Сколько строк не удалось разобрать.
    pub skipped: usize,
}

pub struct SubscriptionClient {
    http: reqwest::Client,
}

impl SubscriptionClient {
    pub fn new() -> Result<Self, FetchError> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .user_agent(USER_AGENT)
            // Панели любят редиректы через сокращатели ссылок.
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| FetchError::Network(e.to_string()))?;

        Ok(Self { http })
    }

    /// Скачивает и разбирает подписку.
    pub async fn fetch(&self, url: &Secret) -> Result<Fetched, FetchError> {
        let raw = url.expose();
        if !(raw.starts_with("https://") || raw.starts_with("http://")) {
            return Err(FetchError::BadUrl(
                "ожидается http:// или https://".to_owned(),
            ));
        }

        let source = SubscriptionId::from_url(raw);

        let first = self.request(raw, USER_AGENT).await?;
        let report = sont_sub::parse_document(&first.body, &source);

        if !report.profiles.is_empty() {
            return Ok(Fetched {
                profiles: report.profiles,
                info: stamp(first.info),
                skipped: report.skipped.len(),
            });
        }

        tracing::warn!(
            "под своим User-Agent серверов не получено, повтор под именем распространённого клиента"
        );
        let second = self.request(raw, FALLBACK_USER_AGENT).await?;
        let report = sont_sub::parse_document(&second.body, &source);

        if report.profiles.is_empty() {
            return Err(FetchError::NoServers {
                skipped: report.skipped.len(),
            });
        }

        Ok(Fetched {
            profiles: report.profiles,
            info: stamp(second.info),
            skipped: report.skipped.len(),
        })
    }

    async fn request(&self, url: &str, agent: &str) -> Result<Response, FetchError> {
        let response = self
            .http
            .get(url)
            .header(reqwest::header::USER_AGENT, agent)
            .send()
            .await
            .map_err(|e| {
                // Сообщение reqwest содержит URL целиком, а в нём токен
                // подписки. В лог и в UI такое отдавать нельзя.
                FetchError::Network(redact(&e.to_string(), url))
            })?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status().as_u16()));
        }

        let info = response
            .headers()
            .get("subscription-userinfo")
            .and_then(|v| v.to_str().ok())
            .map(sont_sub::parse_user_info)
            .unwrap_or_default();

        // Проверяем заявленную длину до чтения тела, чтобы не начинать
        // качать заведомо слишком большой ответ.
        if response
            .content_length()
            .is_some_and(|l| l as usize > MAX_BODY_BYTES)
        {
            return Err(FetchError::TooLarge);
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| FetchError::Network(redact(&e.to_string(), url)))?;

        if bytes.len() > MAX_BODY_BYTES {
            return Err(FetchError::TooLarge);
        }

        let body = String::from_utf8(bytes.to_vec()).map_err(|_| FetchError::NotText)?;
        Ok(Response { body, info })
    }
}

struct Response {
    body: String,
    info: SubscriptionInfo,
}

/// Проставляет отметку времени получения.
fn stamp(mut info: SubscriptionInfo) -> SubscriptionInfo {
    info.fetched_at_unix = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    info
}

/// Вырезает секретную часть ссылки подписки из текста ошибки.
///
/// Убираем путь и параметры запроса — токен находится именно там. Хост
/// оставляем намеренно: по нему пользователь понимает, до какой панели не
/// достучались, и секретом он не является.
fn redact(message: &str, url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        // Ссылку разобрать не удалось, а значит и вычленить в ней секрет.
        // Вырезаем целиком: потеря диагностики лучше утечки ключа.
        return message.replace(url, "<ссылка подписки>");
    };

    let mut result = message.to_owned();

    if let Some(query) = parsed.query().filter(|q| !q.is_empty()) {
        result = result.replace(query, "<скрыто>");
    }

    let path = parsed.path();
    if path.len() > 1 {
        result = result.replace(path, "/<скрыто>");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Одноразовый HTTP-сервер на localhost.
    ///
    /// Настоящий сокет, а не заглушка клиента: только так проверяется, что мы
    /// действительно отправляем нужные заголовки, читаем `subscription-userinfo`
    /// и разбираем тело ровно так, как его отдаёт панель.
    struct FakePanel {
        url: String,
        /// Текст первого полученного запроса.
        request: tokio::sync::oneshot::Receiver<String>,
    }

    impl FakePanel {
        async fn serve(status_line: &'static str, headers: &'static str, body: String) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tx, rx) = tokio::sync::oneshot::channel();

            tokio::spawn(async move {
                // Соединений может быть несколько: если под своим User-Agent
                // серверов не получено, клиент повторяет запрос под именем
                // распространённого клиента. Панель, умеющая обслужить лишь
                // одно соединение, ломала бы именно этот сценарий.
                let mut first = Some(tx);

                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };

                    let mut buf = vec![0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if let Some(tx) = first.take() {
                        let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                    }

                    let response = format!(
                        "{status_line}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                }
            });

            Self {
                url: format!("http://127.0.0.1:{port}/sub/TESTTOKEN"),
                request: rx,
            }
        }
    }

    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=KEY&sid=ab&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam";
    const HY2: &str = "hysteria2://pw@de.example.com:443?sni=de.example.com#Frankfurt";

    #[tokio::test]
    async fn fetches_and_parses_a_base64_subscription() {
        use base64::Engine;

        let body = base64::engine::general_purpose::STANDARD.encode(format!("{VLESS}\n{HY2}\n"));
        let panel = FakePanel::serve(
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain\r\nsubscription-userinfo: upload=1073741824; download=3221225472; total=10737418240; expire=1893456000\r\n",
            body,
        )
        .await;

        let client = SubscriptionClient::new().unwrap();
        let fetched = client
            .fetch(&Secret::new(panel.url.clone()))
            .await
            .expect("подписка должна прочитаться");

        assert_eq!(fetched.profiles.len(), 2);
        assert_eq!(fetched.skipped, 0);
        assert_eq!(fetched.profiles[0].name, "🇳🇱 Amsterdam");
        assert_eq!(
            fetched.profiles[0].country.map(|c| c.as_str().to_owned()),
            Some("NL".into())
        );

        // Заголовок панели должен превратиться в показатели подписки.
        assert_eq!(fetched.info.used_percent(), Some(40));
        assert_eq!(fetched.info.expires_at_unix, Some(1_893_456_000));
        assert!(fetched.info.fetched_at_unix.is_some());

        // Имена заголовков в HTTP/1.1 регистронезависимы, и клиент отправляет
        // их в нижнем регистре — сравниваем соответственно.
        let request = panel.request.await.unwrap().to_lowercase();
        assert!(
            request.contains("user-agent: sont/"),
            "должен отправляться наш User-Agent: {request}"
        );
        assert!(request.starts_with("get /sub/testtoken "));
    }

    #[tokio::test]
    async fn plain_text_subscription_is_accepted() {
        let panel = FakePanel::serve(
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain\r\n",
            format!("{VLESS}\n{HY2}\n"),
        )
        .await;

        let client = SubscriptionClient::new().unwrap();
        let fetched = client.fetch(&Secret::new(panel.url)).await.unwrap();
        assert_eq!(fetched.profiles.len(), 2);
    }

    #[tokio::test]
    async fn unsupported_links_are_counted_but_do_not_fail_the_fetch() {
        let panel = FakePanel::serve(
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain\r\n",
            format!("{VLESS}\ntrojan://pw@example.com:443#T\n"),
        )
        .await;

        let client = SubscriptionClient::new().unwrap();
        let fetched = client.fetch(&Secret::new(panel.url)).await.unwrap();
        assert_eq!(fetched.profiles.len(), 1);
        assert_eq!(fetched.skipped, 1);
    }

    #[tokio::test]
    async fn http_error_status_is_reported_with_its_code() {
        let panel = FakePanel::serve("HTTP/1.1 403 Forbidden", "", "nope".to_owned()).await;

        let client = SubscriptionClient::new().unwrap();
        let err = client.fetch(&Secret::new(panel.url)).await.unwrap_err();
        assert!(matches!(err, FetchError::Status(403)), "получено {err:?}");
    }

    #[tokio::test]
    async fn html_response_yields_a_clear_no_servers_error() {
        // Панель, не узнавшая клиента, отдаёт страницу личного кабинета.
        // Пользователь должен получить внятную причину, а не пустой список.
        let panel = FakePanel::serve(
            "HTTP/1.1 200 OK",
            "Content-Type: text/html\r\n",
            "<html><body>Login</body></html>".to_owned(),
        )
        .await;

        let client = SubscriptionClient::new().unwrap();
        let err = client.fetch(&Secret::new(panel.url)).await.unwrap_err();
        assert!(
            matches!(err, FetchError::NoServers { .. }),
            "получено {err:?}"
        );
    }

    #[tokio::test]
    async fn unreachable_panel_error_does_not_leak_the_token() {
        // Порт, на котором никто не слушает.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let url = format!("http://127.0.0.1:{port}/sub/SUPER-SECRET-TOKEN");
        let client = SubscriptionClient::new().unwrap();
        let err = client.fetch(&Secret::new(url)).await.unwrap_err();

        let text = err.to_string();
        assert!(
            !text.contains("SUPER-SECRET-TOKEN"),
            "токен утёк в текст ошибки: {text}"
        );
    }

    #[tokio::test]
    async fn non_http_scheme_is_rejected_without_network_access() {
        let client = SubscriptionClient::new().unwrap();
        let err = client
            .fetch(&Secret::new("vless://not-a-subscription"))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::BadUrl(_)));
    }

    #[test]
    fn redaction_removes_the_token_from_error_text() {
        let url = "https://panel.example/sub/SECRET-TOKEN-123";
        let message = format!("error sending request for url ({url}): connection refused");
        let clean = redact(&message, url);

        assert!(!clean.contains("SECRET-TOKEN-123"), "токен остался: {clean}");
        assert!(
            clean.contains("panel.example"),
            "хост стоит оставить для диагностики: {clean}"
        );
    }

    #[test]
    fn redaction_handles_path_mentioned_separately() {
        let url = "https://panel.example/sub/TOKEN";
        let message = "failed to resolve /sub/TOKEN".to_owned();
        assert!(!redact(&message, url).contains("TOKEN"));
    }

    #[test]
    fn redaction_covers_token_passed_as_query_parameter() {
        // Часть панелей передаёт токен параметром, а не в пути.
        let url = "https://panel.example/sub?token=SECRET123";
        let message = format!("error fetching {url}");
        let clean = redact(&message, url);
        assert!(!clean.contains("SECRET123"), "токен остался: {clean}");
    }

    #[test]
    fn unparseable_url_is_removed_entirely() {
        let url = "не ссылка вовсе";
        let message = format!("сбой при обращении к {url}");
        assert!(!redact(&message, url).contains("не ссылка вовсе"));
    }

    #[test]
    fn fetched_info_gets_a_timestamp() {
        let info = stamp(SubscriptionInfo::default());
        assert!(info.fetched_at_unix.is_some());
    }

    #[test]
    fn error_messages_are_actionable() {
        assert!(FetchError::Status(403).to_string().contains("403"));
        assert!(FetchError::NoServers { skipped: 3 }.to_string().contains("3"));
    }
}

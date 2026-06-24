use anyhow::{Context, Result};
use egrok_protocol::{AuthMessage, AuthResponse, Message, TunnelRequest, TunnelResponse};
use futures_util::{SinkExt, StreamExt};
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use log::{error, info};
use rustls::pki_types::ServerName;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static TUNNELS: OnceLock<Mutex<Vec<tokio::task::AbortHandle>>> = OnceLock::new();

fn init_logging() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("egrokshim"),
    );
}

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("egrokshim: tokio runtime init failed")
    })
}

fn tunnels() -> &'static Mutex<Vec<tokio::task::AbortHandle>> {
    TUNNELS.get_or_init(|| Mutex::new(Vec::new()))
}

async fn forward_request(local_port: u16, request: TunnelRequest) -> TunnelResponse {
    let url = format!("http://127.0.0.1:{}{}", local_port, request.uri);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let method = match request.method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut req_builder = client.request(method, &url);

    for (key, value) in &request.headers {
        let key_lower = key.to_lowercase();
        if key_lower != "host" && key_lower != "content-length" && key_lower != "transfer-encoding" {
            req_builder = req_builder.header(key, value);
        }
    }

    if !request.body.is_empty() {
        req_builder = req_builder.body(request.body.clone());
    }

    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            match response.bytes().await {
                Ok(body) => TunnelResponse::new(request.request_id, status, headers, body.to_vec()),
                Err(e) => {
                    error!("failed to read response body: {e}");
                    TunnelResponse::error(request.request_id, 502, "Failed to read response body")
                }
            }
        }
        Err(e) => {
            error!("failed to forward request: {e}");
            TunnelResponse::error(
                request.request_id,
                502,
                &format!("Failed to connect to local server: {e}"),
            )
        }
    }
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

async fn run_tunnel(
    server: String,
    port: u16,
    local_port: u16,
    token: String,
    insecure: bool,
) -> Result<()> {
    let addr = format!("{}:{}", server, port);
    let tcp_stream = TcpStream::connect(&addr)
        .await
        .context(format!("TCP connect to {addr} failed"))?;

    let server_name: ServerName<'_> = server
        .clone()
        .try_into()
        .context("Invalid server name")?;

    let config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .context("TLS handshake failed")?;

    let (ws_stream, _) = tokio_tungstenite::client_async(
        format!("wss://{}:{}/", server, port),
        tls_stream,
    )
    .await
    .context("WebSocket handshake failed")?;

    let (mut ws_sink, mut ws_rx) = ws_stream.split();

    let auth_msg = Message::Auth(AuthMessage { token });
    ws_sink
        .send(WsMessage::Text(serde_json::to_string(&auth_msg)?.into()))
        .await
        .context("Failed to send auth")?;

    let auth_response = match ws_rx.next().await {
        Some(Ok(WsMessage::Text(text))) => {
            serde_json::from_str::<Message>(&text).context("Failed to parse auth response")?
        }
        Some(Ok(WsMessage::Binary(data))) => {
            let text = String::from_utf8(data.to_vec())?;
            serde_json::from_str::<Message>(&text).context("Failed to parse auth response")?
        }
        Some(Err(e)) => return Err(anyhow::anyhow!("WebSocket error: {}", e)),
        None => return Err(anyhow::anyhow!("Connection closed before auth response")),
        _ => return Err(anyhow::anyhow!("Unexpected auth response type")),
    };

    match auth_response {
        Message::AuthResponse(AuthResponse { success: true, customer_name, .. }) => {
            info!("authenticated as {:?} on port {port}", customer_name);
        }
        Message::AuthResponse(AuthResponse { success: false, error, .. }) => {
            return Err(anyhow::anyhow!(
                "Auth failed: {}",
                error.unwrap_or_default()
            ));
        }
        _ => return Err(anyhow::anyhow!("Unexpected response type")),
    }

    info!("tunnel up {}:{} -> local:{}", server, port, local_port);

    let (resp_tx, mut resp_rx) = mpsc::channel::<TunnelResponse>(100);

    let send_task = tokio::spawn(async move {
        while let Some(response) = resp_rx.recv().await {
            let msg = Message::HttpResponse(response);
            let json = serde_json::to_string(&msg).unwrap();
            if ws_sink.send(WsMessage::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(msg_result) = ws_rx.next().await {
            match msg_result {
                Ok(WsMessage::Text(text)) => {
                    if let Ok(Message::HttpRequest(request)) = serde_json::from_str(&text) {
                        let resp_tx = resp_tx.clone();
                        tokio::spawn(async move {
                            let response = forward_request(local_port, request).await;
                            let _ = resp_tx.send(response).await;
                        });
                    }
                }
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(text) = String::from_utf8(data.to_vec()) {
                        if let Ok(Message::HttpRequest(request)) = serde_json::from_str(&text) {
                            let resp_tx = resp_tx.clone();
                            tokio::spawn(async move {
                                let response = forward_request(local_port, request).await;
                                let _ = resp_tx.send(response).await;
                            });
                        }
                    }
                }
                Ok(WsMessage::Close(_)) => {
                    info!("server closed connection on port {port}");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error on port {port}: {e}");
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    Ok(())
}

/// Called from Java: NativeBridge.startEgrok(server, subdomain, token, remotePort, localPort, insecure)
///
/// `subdomain` is used by the Java layer for IAM registration and URL display — the egrok
/// protocol doesn't send it; the server maps backhaul ports to customers server-side.
#[no_mangle]
pub extern "system" fn Java_com_example_rustapp_NativeBridge_startEgrok(
    mut env: JNIEnv,
    _class: JClass,
    j_server: JString,
    _j_subdomain: JString,
    j_token: JString,
    j_remote_port: jni::sys::jint,
    j_local_port: jni::sys::jint,
    j_insecure: jboolean,
) {
    init_logging();

    let server: String = match env.get_string(&j_server) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("failed to read server param: {e}");
            return;
        }
    };
    let token: String = match env.get_string(&j_token) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("failed to read token param: {e}");
            return;
        }
    };
    let remote_port = j_remote_port as u16;
    let local_port = j_local_port as u16;
    let insecure = j_insecure != 0;
    info!(
        "startEgrok {}:{} -> :{} insecure={}",
        server, remote_port, local_port, insecure
    );

    let handle = runtime().spawn(async move {
        loop {
            match run_tunnel(server.clone(), remote_port, local_port, token.clone(), insecure).await {
                Ok(()) => {
                    info!("{}:{} closed cleanly, reconnecting...", server, remote_port);
                }
                Err(e) => {
                    error!("{}:{} error: {e}, retrying in 5s...", server, remote_port);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    tunnels().lock().unwrap().push(handle.abort_handle());
}

/// Called from Java: NativeBridge.stopEgrok()
#[no_mangle]
pub extern "system" fn Java_com_example_rustapp_NativeBridge_stopEgrok(
    _env: JNIEnv,
    _class: JClass,
) {
    let mut handles = tunnels().lock().unwrap();
    let count = handles.len();
    for handle in handles.drain(..) {
        handle.abort();
    }
    info!("stopped {count} tunnel(s)");
}

/// Called from Java: NativeBridge.getLastUrl()
/// egrok URLs are known upfront by the Java layer, so this always returns "".
#[no_mangle]
pub extern "system" fn Java_com_example_rustapp_NativeBridge_getLastUrl(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    env.new_string("").unwrap().into_raw()
}

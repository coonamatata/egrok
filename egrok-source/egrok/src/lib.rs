use anyhow::{Context, Result};
use egrok_protocol::{AuthMessage, AuthResponse, Message, TunnelRequest, TunnelResponse};
use futures_util::{SinkExt, StreamExt};
use jni::objects::{JClass, JString};
use jni::sys::{jint};
use jni::JNIEnv;
use rustls::pki_types::ServerName;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use android_logger::Config;
use log::LevelFilter;

lazy_static::lazy_static! {
    static ref LAST_URL: Mutex<String> = Mutex::new(String::new());
    // CHANGED: Now holds a LIST of shutdown signals, not just one.
    static ref SHUTDOWN_HANDLES: Mutex<Vec<broadcast::Sender<()>>> = Mutex::new(Vec::new());
}

#[no_mangle]
pub extern "system" fn Java_com_example_rustapp_NativeBridge_startEgrok(
    mut env: JNIEnv,
    _class: JClass,
    j_server: JString,
    j_token: JString,
    j_remote_port: jint,
    j_local_port: jint
) {
    android_logger::init_once(
        Config::default().with_max_level(LevelFilter::Debug).with_tag("EgrokNative"),
    );

    let server: String = env.get_string(&j_server).expect("Invalid server string").into();
    let token: String = env.get_string(&j_token).expect("Invalid token string").into();
    let remote_port = j_remote_port as u16;
    let local_port = j_local_port as u16;

    log::info!(">>> STARTING TUNNEL: Remote={} -> Local={}", remote_port, local_port);

    // Create a unique shutdown signal for THIS specific tunnel
    let (tx, _) = broadcast::channel(1);
    
    // Store it in the global list
    SHUTDOWN_HANDLES.lock().unwrap().push(tx.clone());

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut rx = tx.subscribe();
            tokio::select! {
                res = run_client_internal(server, remote_port, local_port, true, token) => {
                    if let Err(e) = res {
                        log::error!("Tunnel (Local {}) CRASHED: {}", local_port, e);
                    } else {
                        log::info!("Tunnel (Local {}) finished normally", local_port);
                    }
                }
                _ = rx.recv() => {
                    log::info!("Tunnel (Local {}) stopping via signal.", local_port);
                }
            }
        });
    });
}

#[no_mangle]
pub extern "system" fn Java_com_example_rustapp_NativeBridge_stopEgrok(
    _env: JNIEnv,
    _class: JClass,
) {
    log::info!(">>> STOPPING ALL TUNNELS <<<");
    let mut handles = SHUTDOWN_HANDLES.lock().unwrap();
    for tx in handles.iter() {
        let _ = tx.send(()); // Fire every shutdown signal
    }
    handles.clear(); // Clear the list
    *LAST_URL.lock().unwrap() = String::new();
}

#[no_mangle]
pub extern "system" fn Java_com_example_rustapp_NativeBridge_getLastUrl(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jstring {
    let url = LAST_URL.lock().unwrap().clone();
    let output = env.new_string(url).expect("Failed to create Java String");
    output.into_raw()
}

// ... (Copy existing run_client_internal, process_incoming_msg, forward_request, InsecureVerifier below) ...
// ... (Use the exact same logic code from the previous working step) ...

// PASTE THE REST OF THE CODE HERE (The logic functions)
// Ensure "run_client_internal" uses the "log::info!" macros we added previously.

async fn run_client_internal(server: String, port: u16, local_port: u16, insecure: bool, token: String) -> Result<()> {
    
    log::info!("Connecting to {}:{}", server, port);

    let addr = format!("{}:{}", server, port);
    let tcp_stream = TcpStream::connect(&addr).await
        .context(format!("Failed to connect to {}", addr))?;

    let server_name: ServerName<'_> = server.clone().try_into().context("Invalid server name")?;
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = connector.connect(server_name, tcp_stream).await.context("TLS handshake failed")?;

    let (ws_stream, _) = tokio_tungstenite::client_async(
        format!("wss://{}:{}/", server, port),
        tls_stream,
    ).await.context("WebSocket handshake failed")?;

    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    let auth_msg = Message::Auth(AuthMessage { token: token.clone() });
    let auth_json = serde_json::to_string(&auth_msg)?;
    ws_sink.send(WsMessage::Text(auth_json.into())).await?;

    let auth_response = match ws_stream.next().await {
        Some(Ok(WsMessage::Text(text))) => serde_json::from_str::<Message>(&text)?,
        Some(Ok(WsMessage::Binary(data))) => {
            let text = String::from_utf8(data.to_vec())?;
            serde_json::from_str::<Message>(&text)?
        }
        _ => return Err(anyhow::anyhow!("Connection closed or invalid auth response")),
    };

    match auth_response {
        Message::AuthResponse(AuthResponse { success: true, customer_name, .. }) => {
            let name = customer_name.unwrap_or_else(|| "unknown".to_string());
            log::info!("Authenticated: {} -> Local {}", name, local_port);
            let full_url = format!("https://{}.{}", name, server);
            *LAST_URL.lock().unwrap() = full_url; // Update UI (will show last one connected)
        }
        _ => return Err(anyhow::anyhow!("Authentication Failed!")),
    }

    let (resp_tx, mut resp_rx) = mpsc::channel::<TunnelResponse>(100);

    let send_task = tokio::spawn(async move {
        while let Some(response) = resp_rx.recv().await {
            let msg = Message::HttpResponse(response);
            if let Ok(json) = serde_json::to_string(&msg) {
                if ws_sink.send(WsMessage::Text(json.into())).await.is_err() { break; }
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(msg_result) = ws_stream.next().await {
            match msg_result {
                Ok(WsMessage::Text(text)) => process_incoming_msg(&text, &resp_tx, local_port).await,
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(text) = String::from_utf8(data.to_vec()) {
                        process_incoming_msg(&text, &resp_tx, local_port).await;
                    }
                }
                Ok(WsMessage::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
    Ok(())
}

async fn process_incoming_msg(text: &str, resp_tx: &mpsc::Sender<TunnelResponse>, local_port: u16) {
    if let Ok(Message::HttpRequest(request)) = serde_json::from_str::<Message>(text) {
        log::info!("REQ (Local {}): {} {}", local_port, request.method, request.uri);
        
        let resp_tx = resp_tx.clone();
        tokio::spawn(async move {
            let response = forward_request(local_port, request).await;
            let _ = resp_tx.send(response).await;
        });
    }
}

async fn forward_request(local_port: u16, request: TunnelRequest) -> TunnelResponse {
    let url = format!("http://127.0.0.1:{}{}", local_port, request.uri);
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();
    
    let method = match request.method.to_uppercase().as_str() {
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        _ => reqwest::Method::GET,
    };

    let mut req_builder = client.request(method, &url);
    for (k, v) in &request.headers {
         if k.to_lowercase() != "host" { req_builder = req_builder.header(k, v); }
    }
    if !request.body.is_empty() { req_builder = req_builder.body(request.body); }

    match req_builder.send().await {
        Ok(res) => {
            let status = res.status().as_u16();
            let headers: Vec<(String, String)> = res.headers().iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
            let body = res.bytes().await.unwrap_or_default().to_vec();
            TunnelResponse::new(request.request_id, status, headers, body)
        }
        Err(e) => {
            log::error!("FORWARD FAIL ({}): {}", local_port, e);
            TunnelResponse::error(request.request_id, 502, &e.to_string())
        }
    }
}

#[derive(Debug)]
struct InsecureVerifier;
impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(&self, _end_entity: &rustls::pki_types::CertificateDer<'_>, _intermediates: &[rustls::pki_types::CertificateDer<'_>], _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::RSA_PKCS1_SHA256, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ED25519]
    }
}
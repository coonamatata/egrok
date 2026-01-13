use anyhow::{Context, Result};
use clap::Parser;
use egrok_protocol::{AuthMessage, AuthResponse, Message, TunnelRequest, TunnelResponse};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "egrok")]
#[command(about = "Reverse tunnel client (like ngrok)")]
struct Cli {
    #[arg(short, long)]
    server: String,

    #[arg(short, long)]
    port: u16,

    #[arg(short, long)]
    local: u16,

    #[arg(long, default_value = "false")]
    insecure: bool,
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
        if key_lower != "host" && key_lower != "content-length" && key_lower != "transfer-encoding"
        {
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
                    error!("Failed to read response body: {}", e);
                    TunnelResponse::error(request.request_id, 502, "Failed to read response body")
                }
            }
        }
        Err(e) => {
            error!("Failed to forward request to local server: {}", e);
            TunnelResponse::error(
                request.request_id,
                502,
                &format!("Failed to connect to local server: {}", e),
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

async fn run_client(server: String, port: u16, local_port: u16, insecure: bool) -> Result<()> {
    let token = std::env::var("EGROK_TOKEN")
        .context("EGROK_TOKEN environment variable not set. Set it with: export EGROK_TOKEN=your-token")?;

    info!("Connecting to {}:{}", server, port);

    let addr = format!("{}:{}", server, port);
    let tcp_stream = TcpStream::connect(&addr)
        .await
        .context(format!("Failed to connect to {}", addr))?;

    let server_name: ServerName<'_> = server
        .clone()
        .try_into()
        .context("Invalid server name")?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = if insecure {
        warn!("Using insecure TLS verification - only use for testing!");
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
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .context("TLS handshake failed")?;

    info!("TLS connection established");

    let (ws_stream, _) = tokio_tungstenite::client_async(
        format!("wss://{}:{}/", server, port),
        tls_stream,
    )
    .await
    .context("WebSocket handshake failed")?;

    info!("WebSocket connection established");

    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    let auth_msg = Message::Auth(AuthMessage { token });
    let auth_json = serde_json::to_string(&auth_msg)?;
    ws_sink.send(WsMessage::Text(auth_json.into())).await?;

    info!("Sent authentication message");

    let auth_response = match ws_stream.next().await {
        Some(Ok(WsMessage::Text(text))) => {
            serde_json::from_str::<Message>(&text).context("Failed to parse auth response")?
        }
        Some(Ok(WsMessage::Binary(data))) => {
            let text = String::from_utf8(data.to_vec())?;
            serde_json::from_str::<Message>(&text).context("Failed to parse auth response")?
        }
        Some(Err(e)) => return Err(anyhow::anyhow!("WebSocket error: {}", e)),
        None => return Err(anyhow::anyhow!("Connection closed before auth response")),
        _ => return Err(anyhow::anyhow!("Unexpected message type")),
    };

    match auth_response {
        Message::AuthResponse(AuthResponse {
            success: true,
            customer_name,
            ..
        }) => {
            info!(
                "Authenticated as: {}",
                customer_name.unwrap_or_else(|| "unknown".to_string())
            );
        }
        Message::AuthResponse(AuthResponse {
            success: false,
            error,
            ..
        }) => {
            return Err(anyhow::anyhow!(
                "Authentication failed: {}",
                error.unwrap_or_else(|| "unknown error".to_string())
            ));
        }
        _ => return Err(anyhow::anyhow!("Unexpected response type")),
    }

    info!(
        "Tunnel established. Forwarding requests to localhost:{}",
        local_port
    );

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
        while let Some(msg_result) = ws_stream.next().await {
            match msg_result {
                Ok(WsMessage::Text(text)) => {
                    if let Ok(Message::HttpRequest(request)) = serde_json::from_str(&text) {
                        info!("Received request: {} {}", request.method, request.uri);
                        let resp_tx = resp_tx.clone();
                        let local_port = local_port;
                        tokio::spawn(async move {
                            let response = forward_request(local_port, request).await;
                            let _ = resp_tx.send(response).await;
                        });
                    }
                }
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(text) = String::from_utf8(data.to_vec()) {
                        if let Ok(Message::HttpRequest(request)) = serde_json::from_str(&text) {
                            info!("Received request: {} {}", request.method, request.uri);
                            let resp_tx = resp_tx.clone();
                            let local_port = local_port;
                            tokio::spawn(async move {
                                let response = forward_request(local_port, request).await;
                                let _ = resp_tx.send(response).await;
                            });
                        }
                    }
                }
                Ok(WsMessage::Ping(data)) => {
                    info!("Received ping");
                    let _ = data;
                }
                Ok(WsMessage::Close(_)) => {
                    info!("Server closed connection");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {
            info!("Send task completed");
        }
        _ = recv_task => {
            info!("Receive task completed");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("egrok=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    run_client(cli.server, cli.port, cli.local, cli.insecure).await
}

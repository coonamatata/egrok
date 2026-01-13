use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use egrok_protocol::{
    hash_token, verify_token, AuthMessage, AuthResponse, Message, TunnelRequest, TunnelResponse,
};
use futures_util::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "egrok-server")]
#[command(about = "Reverse tunnel server (like ngrok)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    HashToken {
        token: String,
    },
}

#[derive(Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    customers: Vec<CustomerConfig>,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    public_port: u16,
    cert_path: String,
    key_path: String,
    domain: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CustomerConfig {
    name: String,
    backhaul_port: u16,
    token_hash: String,
}

type PendingRequests = Arc<RwLock<HashMap<String, oneshot::Sender<TunnelResponse>>>>;

struct TunnelConnection {
    sender: mpsc::Sender<TunnelRequest>,
    pending: PendingRequests,
}

struct TunnelManager {
    tunnels: RwLock<HashMap<String, Arc<TunnelConnection>>>,
    customers_by_port: HashMap<u16, CustomerConfig>,
    customers_by_name: HashMap<String, CustomerConfig>,
}

impl TunnelManager {
    fn new(customers: Vec<CustomerConfig>) -> Self {
        let mut by_port = HashMap::new();
        let mut by_name = HashMap::new();
        for c in customers {
            by_port.insert(c.backhaul_port, c.clone());
            by_name.insert(c.name.clone(), c);
        }
        Self {
            tunnels: RwLock::new(HashMap::new()),
            customers_by_port: by_port,
            customers_by_name: by_name,
        }
    }

    fn get_customer_by_port(&self, port: u16) -> Option<&CustomerConfig> {
        self.customers_by_port.get(&port)
    }

    fn get_customer_by_name(&self, name: &str) -> Option<&CustomerConfig> {
        self.customers_by_name.get(name)
    }

    async fn register(&self, name: String, conn: Arc<TunnelConnection>) {
        let mut tunnels = self.tunnels.write().await;
        tunnels.insert(name, conn);
    }

    async fn unregister(&self, name: &str) {
        let mut tunnels = self.tunnels.write().await;
        tunnels.remove(name);
    }

    async fn get(&self, name: &str) -> Option<Arc<TunnelConnection>> {
        let tunnels = self.tunnels.read().await;
        tunnels.get(name).cloned()
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).context("Failed to open cert file")?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certs")?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).context("Failed to open key file")?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::private_key(&mut reader)
        .context("Failed to parse private key")?
        .context("No private key found")?;
    Ok(keys)
}

async fn handle_backhaul_connection(
    manager: Arc<TunnelManager>,
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    port: u16,
) {
    let customer = match manager.get_customer_by_port(port) {
        Some(c) => c.clone(),
        None => {
            error!("No customer configured for port {}", port);
            return;
        }
    };

    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            error!("TLS handshake failed for port {}: {}", port, e);
            return;
        }
    };

    let ws_stream = match tokio_tungstenite::accept_async(tls_stream).await {
        Ok(s) => s,
        Err(e) => {
            error!("WebSocket handshake failed for port {}: {}", port, e);
            return;
        }
    };

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    let first_msg = match ws_stream_rx.next().await {
        Some(Ok(WsMessage::Text(text))) => text,
        Some(Ok(WsMessage::Binary(data))) => match String::from_utf8(data.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                error!("Invalid UTF-8 in auth message");
                return;
            }
        },
        _ => {
            error!("Expected auth message as first message");
            return;
        }
    };

    let auth_msg: Message = match serde_json::from_str(&first_msg) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to parse auth message: {}", e);
            return;
        }
    };

    let token = match auth_msg {
        Message::Auth(AuthMessage { token }) => token,
        _ => {
            error!("Expected Auth message, got something else");
            return;
        }
    };

    if !verify_token(&token, &customer.token_hash) {
        error!("Authentication failed for customer {}", customer.name);
        let response = Message::AuthResponse(AuthResponse {
            success: false,
            customer_name: None,
            error: Some("Invalid token".to_string()),
        });
        let _ = ws_sink
            .send(WsMessage::Text(serde_json::to_string(&response).unwrap().into()))
            .await;
        return;
    }

    info!("Customer {} authenticated successfully", customer.name);

    let response = Message::AuthResponse(AuthResponse {
        success: true,
        customer_name: Some(customer.name.clone()),
        error: None,
    });
    if ws_sink
        .send(WsMessage::Text(serde_json::to_string(&response).unwrap().into()))
        .await
        .is_err()
    {
        return;
    }

    let (req_tx, mut req_rx) = mpsc::channel::<TunnelRequest>(100);
    let pending: PendingRequests = Arc::new(RwLock::new(HashMap::new()));

    let conn = Arc::new(TunnelConnection {
        sender: req_tx,
        pending: pending.clone(),
    });

    manager.register(customer.name.clone(), conn).await;
    info!("Tunnel registered for customer: {}", customer.name);

    let customer_name = customer.name.clone();
    let manager_clone = manager.clone();
    let pending_clone = pending.clone();

    let send_task = tokio::spawn(async move {
        while let Some(request) = req_rx.recv().await {
            let msg = Message::HttpRequest(request);
            let json = serde_json::to_string(&msg).unwrap();
            if ws_sink.send(WsMessage::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(msg_result) = ws_stream_rx.next().await {
            match msg_result {
                Ok(WsMessage::Text(text)) => {
                    if let Ok(Message::HttpResponse(response)) = serde_json::from_str(&text) {
                        let mut pending = pending_clone.write().await;
                        if let Some(sender) = pending.remove(&response.request_id) {
                            let _ = sender.send(response);
                        }
                    }
                }
                Ok(WsMessage::Binary(data)) => {
                    if let Ok(text) = String::from_utf8(data.to_vec()) {
                        if let Ok(Message::HttpResponse(response)) = serde_json::from_str(&text) {
                            let mut pending = pending_clone.write().await;
                            if let Some(sender) = pending.remove(&response.request_id) {
                                let _ = sender.send(response);
                            }
                        }
                    }
                }
                Ok(WsMessage::Ping(data)) => {
                    info!("Received ping from {}", customer_name);
                    let _ = data;
                }
                Ok(WsMessage::Close(_)) => break,
                Err(e) => {
                    warn!("WebSocket error for {}: {}", customer_name, e);
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    manager_clone.unregister(&customer.name).await;
    info!("Tunnel disconnected for customer: {}", customer.name);
}

async fn handle_public_request(
    req: Request<Incoming>,
    manager: Arc<TunnelManager>,
    domain: String,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let customer_name = if host.ends_with(&domain) {
        host.strip_suffix(&format!(".{}", domain))
            .map(|s| s.to_string())
    } else {
        None
    };

    let customer_name = match customer_name {
        Some(name) => name,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Invalid host header")))
                .unwrap());
        }
    };

    let tunnel = match manager.get(&customer_name).await {
        Some(t) => t,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from(format!(
                    "Tunnel not connected for: {}",
                    customer_name
                ))))
                .unwrap());
        }
    };

    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = req.collect().await?.to_bytes().to_vec();

    let tunnel_req = TunnelRequest::new(method, uri, headers, body);
    let request_id = tunnel_req.request_id.clone();

    let (resp_tx, resp_rx) = oneshot::channel();
    {
        let mut pending = tunnel.pending.write().await;
        pending.insert(request_id.clone(), resp_tx);
    }

    if tunnel.sender.send(tunnel_req).await.is_err() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send request to tunnel")))
            .unwrap());
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), resp_rx).await {
        Ok(Ok(tunnel_resp)) => {
            let mut builder = Response::builder().status(tunnel_resp.status_code);
            for (key, value) in tunnel_resp.headers {
                builder = builder.header(key, value);
            }
            Ok(builder
                .body(Full::new(Bytes::from(tunnel_resp.body)))
                .unwrap())
        }
        Ok(Err(_)) => Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Tunnel response channel closed")))
            .unwrap()),
        Err(_) => {
            let mut pending = tunnel.pending.write().await;
            pending.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Full::new(Bytes::from("Request timeout")))
                .unwrap())
        }
    }
}

async fn run_server(config_path: &str) -> Result<()> {
    let config_content = fs::read_to_string(config_path)
        .context(format!("Failed to read config file: {}", config_path))?;
    let config: Config = toml::from_str(&config_content).context("Failed to parse config")?;

    info!("Loaded configuration with {} customers", config.customers.len());

    let certs = load_certs(&config.server.cert_path)?;
    let key = load_key(&config.server.key_path)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let manager = Arc::new(TunnelManager::new(config.customers.clone()));

    for customer in &config.customers {
        let port = customer.backhaul_port;
        let acceptor = tls_acceptor.clone();
        let manager = manager.clone();

        tokio::spawn(async move {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind backhaul port {}: {}", port, e);
                    return;
                }
            };
            info!("Backhaul listener started on port {}", port);

            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Backhaul connection from {} on port {}", addr, port);
                        let acceptor = acceptor.clone();
                        let manager = manager.clone();
                        tokio::spawn(async move {
                            handle_backhaul_connection(manager, acceptor, stream, port).await;
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept backhaul connection: {}", e);
                    }
                }
            }
        });
    }

    let public_addr = SocketAddr::from(([0, 0, 0, 0], config.server.public_port));
    let public_listener = TcpListener::bind(public_addr).await?;
    info!("Public HTTPS listener started on port {}", config.server.public_port);

    let domain = config.server.domain.clone();

    loop {
        let (stream, addr) = public_listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let manager = manager.clone();
        let domain = domain.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed for {}: {}", addr, e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req| {
                let manager = manager.clone();
                let domain = domain.clone();
                async move { handle_public_request(req, manager, domain).await }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                warn!("HTTP error for {}: {}", addr, e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("egrok_server=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config } => {
            run_server(&config).await?;
        }
        Commands::HashToken { token } => {
            let hash = hash_token(&token);
            println!("{}", hash);
        }
    }

    Ok(())
}

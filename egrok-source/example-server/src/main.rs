use axum::{
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;

#[derive(Serialize)]
struct VersionInfo {
    version: String,
    name: String,
    description: String,
}

#[derive(Serialize)]
struct HealthInfo {
    status: String,
    uptime: String,
}

async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        version: "1.0.0".to_string(),
        name: "Example Server".to_string(),
        description: "A simple test server for egrok tunnel testing".to_string(),
    })
}

async fn health() -> Json<HealthInfo> {
    Json(HealthInfo {
        status: "healthy".to_string(),
        uptime: "running".to_string(),
    })
}

async fn hello() -> &'static str {
    "Hello from behind the firewall!"
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a number");

    let app = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/health", get(health));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Example server listening on http://{}", addr);
    println!("Endpoints:");
    println!("  GET /         - Hello message");
    println!("  GET /version  - Version info");
    println!("  GET /health   - Health check");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

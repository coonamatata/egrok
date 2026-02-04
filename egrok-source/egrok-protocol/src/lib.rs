use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelRequest {
    pub request_id: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl TunnelRequest {
    pub fn new(method: String, uri: String, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            method,
            uri,
            headers,
            body,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelResponse {
    pub request_id: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl TunnelResponse {
    pub fn new(request_id: String, status_code: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        let mut header_map = HashMap::new();
        for (k, v) in headers { header_map.insert(k, v); }
        Self { request_id, status_code, headers: header_map, body }
    }
    pub fn error(request_id: String, status_code: u16, message: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        Self { request_id, status_code, headers, body: message.as_bytes().to_vec() }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Auth(AuthMessage),
    AuthResponse(AuthResponse),
    HttpRequest(TunnelRequest),
    HttpResponse(TunnelResponse),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthMessage { pub token: String }

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub success: bool,
    pub customer_name: Option<String>,
    pub error: Option<String>,
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn verify_token(token: &str, hash: &str) -> bool {
    let computed = hash_token(token);
    computed == hash
}

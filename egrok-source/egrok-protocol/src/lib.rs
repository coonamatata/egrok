use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Authentication failed")]
    AuthFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Auth(AuthMessage),
    AuthResponse(AuthResponse),
    HttpRequest(TunnelRequest),
    HttpResponse(TunnelResponse),
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMessage {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub customer_name: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub request_id: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelResponse {
    pub request_id: String,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Message {
    pub fn to_bytes(&self) -> Result<Bytes, ProtocolError> {
        let json = serde_json::to_vec(self)?;
        Ok(Bytes::from(json))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(data).map_err(ProtocolError::from)
    }
}

impl TunnelRequest {
    pub fn new(method: String, uri: String, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            method,
            uri,
            headers,
            body,
        }
    }
}

impl TunnelResponse {
    pub fn new(
        request_id: String,
        status_code: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            request_id,
            status_code,
            headers,
            body,
        }
    }

    pub fn error(request_id: String, status_code: u16, message: &str) -> Self {
        Self {
            request_id,
            status_code,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: message.as_bytes().to_vec(),
        }
    }
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

pub fn verify_token(token: &str, stored_hash: &str) -> bool {
    if !stored_hash.starts_with("sha256:") {
        return false;
    }
    let expected_hex = &stored_hash[7..];
    let expected_bytes = match hex::decode(expected_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let actual_bytes = hasher.finalize();

    actual_bytes.as_slice().ct_eq(&expected_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let token = "super-secret-token-12345";
        let hash = hash_token(token);
        assert!(hash.starts_with("sha256:"));
        assert!(verify_token(token, &hash));
        assert!(!verify_token("wrong-token", &hash));
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::Auth(AuthMessage {
            token: "test".to_string(),
        });
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        match decoded {
            Message::Auth(auth) => assert_eq!(auth.token, "test"),
            _ => panic!("Wrong message type"),
        }
    }
}

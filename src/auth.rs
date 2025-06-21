use axum::extract::State;
use axum::http::HeaderValue;
use axum::{extract::Request, http::header, middleware::Next, response::Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_engine;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

pub(crate) async fn basic_auth(State(users): State<Users>, req: Request, next: Next) -> Response {
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64_engine.decode(encoded) {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        let mut parts = decoded_str.split(':');
                        let username = parts.next().unwrap_or("");
                        let password = parts.next().unwrap_or("");

                        if let Some(expected_hash) = users.get(username) {
                            if bcrypt::verify(password, expected_hash).unwrap_or(false) {
                                return next.run(req).await;
                            }
                        }
                    }
                }
            }
        }
    }

    Response::builder()
        .status(401)
        .header(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str("Basic realm=\"Files\"").unwrap(),
        )
        .body("Unautorized".into())
        .unwrap()
}

pub(crate) type Users = Arc<HashMap<String, String>>;

pub(crate) fn load_users(path: &str) -> Users {
    let data = fs::read_to_string(path).expect("Failed to read json");
    let map: HashMap<String, String> =
        serde_json::from_str(&data).expect("Invalid JSON format");
    Arc::new(map)
}

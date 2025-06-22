use axum::extract::State;
use axum::http::HeaderValue;
use axum::{extract::Request, http::header, middleware::Next, response::Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

#[derive(Deserialize)]
pub(crate) struct UserData {
    password: String,
    directory: String,
}

#[derive(Clone)]
pub(crate) struct AuthenticatedUser {
    pub(crate) username: String,
    pub(crate) directory: String,
}

pub(crate) type Users = Arc<HashMap<String, UserData>>;

pub(crate) fn load_users(path: &str) -> Users {
    let data = fs::read_to_string(path).expect("Failed to read json");
    let map: HashMap<String, UserData> = serde_json::from_str(&data).expect("Invalid JSON format");
    Arc::new(map)
}

pub(crate) async fn basic_auth(State(users): State<Users>, mut req: Request, next: Next) -> Response {
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64_engine.decode(encoded) {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        let mut provided_auth = decoded_str.split(':');
                        let username = provided_auth.next().unwrap_or("");
                        let password = provided_auth.next().unwrap_or("");

                        if let Some(user) = users.get(username) {

                            if bcrypt::verify(password, &user.password).unwrap_or(false) {
                                let au = AuthenticatedUser {
                                    username: String::from(username),
                                    directory: user.directory.clone()
                                };
                                req.extensions_mut().insert(au);
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
        .body("Unauthorized".into())
        .unwrap()
}
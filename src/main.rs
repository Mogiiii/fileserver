mod auth;

use dotenvy::dotenv;
use log::{debug, info, warn};
use std::{
    collections::HashMap,
    env,
    fs::{canonicalize, exists},
    path::{Component, Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Response, header},
    response::IntoResponse,
    routing::get,
};
use mime_guess;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

#[derive(Clone)]
struct Context {
    directory: String,
    users: Arc<HashMap<String, String>>,
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // initialize tracing
    tracing_subscriber::fmt::init();

    let ctx = Context {
        directory: env::var("FILES_PATH").expect("Missing Env var: FILE_PATH"),
        users: auth::load_users(
            &env::var("USERS_JSON_PATH").expect("Missing Env var: USERS_JSON_PATH"),
        ),
    };

    let app = Router::new()
        .route("/files", get(request_handler))
        .route("/files/", get(request_handler))
        .route("/files/{*wildcard}", get(request_handler))
        .layer(axum::middleware::from_fn_with_state(
            ctx.users.clone(),
            auth::basic_auth,
        ))
        .with_state(ctx);

    let host = env::var("HTTP_HOST").expect("Missing Env var: HTTP_HOST");
    let port = env::var("HTTP_PORT").expect("Missing Env var: HTTP_PORT");
    info!("Starting webserver on {host}:{port}");
    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}"))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

macro_rules! not_found {
    () => {
        Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap()
    };
}

async fn request_handler(
    State(context): State<Context>,
    path: Option<axum::extract::Path<String>>,
) -> impl IntoResponse {
    let file_path = match path {
        Some(p) => Path::new(&context.directory).join(p.0),
        None => PathBuf::from(&context.directory),
    };
    info!("GET {}", &file_path.to_str().unwrap());
    if exists(&file_path).unwrap_or(false) {
        if is_safe(&file_path, &context.directory) {
            if file_path.is_file() {
                match File::open(&file_path).await {
                    Ok(f) => {
                        info!("200 Success");
                        handle_file(f, file_path)
                    }
                    Err(e) => {
                        debug!("{e}");
                        not_found!()
                    }
                }
            } else {
                if file_path.is_dir() {
                    info!("200 Success");
                    handle_dir(file_path, &PathBuf::from(context.directory))
                } else {
                    warn!("500 unexpected code path: Not file or directory?");
                    Response::builder()
                        .status(500)
                        .body("Internal server error".into())
                        .unwrap()
                }
            }
        } else {
            warn!(
                "404 Ignored due to malicious request: {}",
                file_path.to_str().unwrap()
            );
            return not_found!();
        }
    } else {
        info!("404 File not found");
        return not_found!();
    }
}

fn is_safe(path: &PathBuf, base_dir: &str) -> bool {
    //check if path contains ".." (path traversal)
    if path.components().any(|c| c == Component::ParentDir) {
        warn!("Potential path traversal");
        return false;
    }
    match canonicalize(path) {
        Ok(true_path) => {
            if true_path.starts_with(Path::new(base_dir)) {
                return true;
            } else {
                warn!(
                    "found difference in requested and absolute paths (symlink shenanigans?): {} | {}",
                    path.to_str().unwrap(),
                    true_path.to_str().unwrap()
                );
                return false;
            }
        }
        Err(e) => {
            debug!("{e}");
            return false;
        }
    }
}

fn handle_file(f: tokio::fs::File, file_path: PathBuf) -> Response<axum::body::Body> {
    let stream = ReaderStream::new(f);
    let body = axum::body::Body::from_stream(stream);
    let filetype = mime_guess::from_path(&file_path).first_or_octet_stream();
    let filename = file_path.file_name().unwrap().to_str().unwrap_or("file");

    Response::builder()
        .status(200)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_str(filetype.essence_str()).unwrap(),
        )
        .header(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)).unwrap(),
        )
        .body(body)
        .unwrap()
}

fn handle_dir(file_path: PathBuf, base_dir: &PathBuf) -> Response<axum::body::Body> {
    let mut children = vec![];
    for entry in file_path.read_dir().unwrap() {
        if let Ok(entry) = entry {
            children.push(entry.path());
        }
    }
    let mut r = String::new();

    //parent dir link
    let dir = remove_base_dir(file_path, base_dir);
    if let Some(parent) = dir.parent() {
        r.push_str(html_link(parent).as_str());
        r.push_str("<br>\n");
    }

    for c in children {
        let p = remove_base_dir(c, &base_dir);
        r.push_str(html_link(&p).as_str());
        r.push_str("<br>\n");
    }
    let body = Body::from(r);
    Response::builder().status(200).body(body).unwrap()
}

fn remove_base_dir(path: PathBuf, base: &PathBuf) -> PathBuf {
    let new_path = path
        .to_str()
        .unwrap()
        .split_once(base.to_str().unwrap())
        .unwrap()
        .1;
    PathBuf::from(new_path)
}

fn html_link(pb: &Path) -> String {
    let mut s = pb.to_str().unwrap();
    let mut href = String::from_str("/files/").unwrap();
    href.push_str(s);
    if s == "" {
        s = ".."
    }

    format!("<a href=\"{href}\">{s}</a>")
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::{
    Json, Router, extract::Path as AxumPath, http::StatusCode, response::Response, routing::get,
};
use cargo::util::errors::*;
use reqwest::Client;

use crate::utils::{
    get_crates_io_index_url, get_index_path, parse_crate_filename, remove_prior_versions,
};

pub const DEFAULT_REFRESH_TTL_SECS: u64 = 15 * 60; // 15 minutes

#[derive(Clone)]
pub struct CachedIndex {
    pub content: bytes::Bytes,
    pub last_check: Instant,
}

#[derive(Clone)]
pub struct ExecutionControl {
    pub registry_path: PathBuf,
    pub server_url: String,
    pub reqwest_client: Client,
    pub enable_proxy: bool,
    pub clean: bool,
    pub index_cache: Arc<RwLock<HashMap<String, CachedIndex>>>,
    pub cache_ttl: Duration,
}

pub async fn serve_registry(
    host: String,
    port: u16,
    path: String,
    enable_proxy: bool,
    clean: bool,
) -> CargoResult<()> {
    let registry_path = PathBuf::from(path);
    let server_url = format!("http://{}:{}", host, port);
    let client = Client::new();

    let state = ExecutionControl {
        registry_path: registry_path.clone(),
        server_url: server_url.clone(),
        reqwest_client: client.clone(),
        enable_proxy,
        clean,
        index_cache: Arc::new(RwLock::new(HashMap::new())),
        cache_ttl: Duration::from_secs(DEFAULT_REFRESH_TTL_SECS),
    };

    let app = Router::new()
        .route("/index/config.json", get(serve_config))
        .route("/index/{*path}", get(serve_index_generic))
        .route("/{filename}", get(serve_crate_file))
        .fallback(serve_file)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}:{}: {}", host, port, e))?;

    tracing::info!(host, port, "starting registry server");

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}

pub async fn serve_config(
    axum::extract::State(ExecutionControl { server_url, .. }): axum::extract::State<
        ExecutionControl,
    >,
) -> Json<serde_json::Value> {
    tracing::info!("serving config endpoint");
    let config = serde_json::json!({
        "dl": format!("{}/{{crate}}-{{version}}.crate", server_url),
        "api": server_url
    });
    tracing::debug!(
        config = %serde_json::to_string_pretty(&config).unwrap(),
        "returning config response"
    );
    Json(config)
}

pub async fn serve_index_generic(
    axum::extract::State(ExecutionControl {
        registry_path,
        reqwest_client,
        enable_proxy,
        index_cache,
        cache_ttl,
        ..
    }): axum::extract::State<ExecutionControl>,
    AxumPath(path): AxumPath<String>,
) -> Result<Response, StatusCode> {
    let crate_name = path.split('/').next_back().unwrap_or(&path).to_string();
    tracing::info!(crate_name, path, "serving index request");
    let crate_name = crate_name.to_lowercase();
    let index_path = get_index_path(&registry_path, &crate_name);

    tracing::debug!(index_path = %index_path.display(), "checking local index");

    if enable_proxy {
        let should_try_refresh = if let Ok(cache) = index_cache.read() {
            if let Some(cached) = cache.get(&crate_name) {
                let since_last_check = cached.last_check.elapsed();

                if since_last_check < cache_ttl {
                    tracing::info!(crate_name, elapsed = ?since_last_check, "serving from cache, within ttl");
                    let mut response =
                        Response::new(axum::body::Body::from(cached.content.clone()));
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain".parse().unwrap(),
                    );
                    return Ok(response);
                } else {
                    tracing::info!(crate_name, elapsed = ?since_last_check, "cache stale, checking upstream availability");
                    true
                }
            } else {
                true
            }
        } else {
            true
        };

        if should_try_refresh {
            tracing::info!(crate_name, "attempting fast fetch from upstream");

            let crates_io_url = get_crates_io_index_url(&crate_name);

            let fast_fail_duration = Duration::from_millis(500);

            let request = reqwest_client
                .get(&crates_io_url)
                .timeout(fast_fail_duration);

            match request.send().await {
                Ok(response) if response.status().is_success() => match response.bytes().await {
                    Ok(content) => {
                        tracing::info!(
                            crate_name,
                            bytes = content.len(),
                            "upstream fetch succeeded, caching fresh index"
                        );

                        if let Ok(mut cache) = index_cache.write() {
                            cache.insert(
                                crate_name.clone(),
                                CachedIndex {
                                    content: content.clone(),
                                    last_check: Instant::now(),
                                },
                            );
                            tracing::debug!(crate_name, "updated index cache");
                        }

                        let mut response = Response::new(axum::body::Body::from(content));
                        response.headers_mut().insert(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain".parse().unwrap(),
                        );
                        return Ok(response);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed reading upstream response body");
                    }
                },
                Ok(response) => {
                    tracing::warn!(
                        status = %response.status(),
                        crate_name,
                        "upstream returned non-success status"
                    );
                }
                Err(e) => {
                    tracing::info!(
                        crate_name,
                        error = %e,
                        "upstream timeout or error, falling back"
                    );
                }
            }

            if let Ok(mut cache) = index_cache.write()
                && let Some(cached) = cache.get_mut(&crate_name)
            {
                cached.last_check = Instant::now();
                tracing::debug!(crate_name, "updated cache timestamp");
            }
        }
    }

    match std::fs::read(&index_path) {
        Ok(content) => {
            tracing::info!(crate_name, bytes = content.len(), "serving cached index");
            let mut response = Response::new(axum::body::Body::from(content));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                "text/plain".parse().unwrap(),
            );
            Ok(response)
        }
        Err(e) => {
            tracing::warn!(
                crate_name,
                error = %e,
                "no local index and fast fetch failed"
            );

            if enable_proxy {
                tracing::info!(crate_name, "attempting full proxy to upstream");

                let crates_io_url = get_crates_io_index_url(&crate_name);

                match reqwest_client.get(&crates_io_url).send().await {
                    Ok(response) if response.status().is_success() => {
                        match response.bytes().await {
                            Ok(content) => {
                                tracing::info!(
                                    crate_name,
                                    bytes = content.len(),
                                    "proxied index from upstream"
                                );

                                tracing::info!(crate_name, "caching proxied index locally");

                                if let Some(parent) = index_path.parent()
                                    && let Err(e) = std::fs::create_dir_all(parent)
                                {
                                    tracing::warn!(error = %e, "failed creating index directory");
                                }

                                if let Err(e) = std::fs::write(&index_path, &content) {
                                    tracing::warn!(error = %e, "failed writing index cache");
                                } else {
                                    tracing::info!(crate_name, "index cached successfully");
                                }

                                let mut response = Response::new(axum::body::Body::from(content));
                                response.headers_mut().insert(
                                    axum::http::header::CONTENT_TYPE,
                                    "text/plain".parse().unwrap(),
                                );
                                Ok(response)
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "failed reading upstream response body"
                                );
                                Err(StatusCode::INTERNAL_SERVER_ERROR)
                            }
                        }
                    }
                    Ok(response) => {
                        tracing::warn!(
                            status = %response.status(),
                            crate_name,
                            "upstream returned non-success status"
                        );
                        Err(StatusCode::NOT_FOUND)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "proxy request to upstream failed");
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
    }
}

pub async fn serve_crate_file(
    axum::extract::State(state): axum::extract::State<ExecutionControl>,
    AxumPath(filename): AxumPath<String>,
) -> Result<Response, StatusCode> {
    if filename.ends_with(".crate") {
        tracing::info!(filename, "serving crate file request");
        let crate_path = state.registry_path.join(&filename);

        tracing::debug!(crate_path = %crate_path.display(), "checking local crate file");

        match std::fs::read(&crate_path) {
            Ok(content) => {
                tracing::info!(filename, bytes = content.len(), "served crate file");
                let mut response = Response::new(axum::body::Body::from(content));
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    "application/octet-stream".parse().unwrap(),
                );
                Ok(response)
            }
            Err(e) => {
                tracing::warn!(filename, error = %e, "local crate file not found");

                if state.enable_proxy {
                    tracing::info!(filename, "attempting to proxy crate from upstream");

                    let crate_info = parse_crate_filename(&filename);

                    let crates_io_url = if let Some((crate_name, version)) = crate_info {
                        format!(
                            "https://crates.io/api/v1/crates/{}/{}/download",
                            crate_name, version
                        )
                    } else {
                        tracing::error!(filename, "invalid crate filename format");
                        return Err(StatusCode::BAD_REQUEST);
                    };

                    match state.reqwest_client.get(&crates_io_url).send().await {
                        Ok(response) if response.status().is_success() => {
                            match response.bytes().await {
                                Ok(content) => {
                                    tracing::info!(
                                        filename,
                                        bytes = content.len(),
                                        "proxied crate from upstream"
                                    );

                                    if let Some((crate_name, version)) = crate_info {
                                        if state.clean {
                                            remove_prior_versions(
                                                &state.registry_path,
                                                crate_name,
                                                version,
                                            );
                                        }

                                        if let Err(e) = std::fs::write(&crate_path, &content) {
                                            tracing::warn!(
                                                error = %e,
                                                "failed caching crate file"
                                            );
                                        }

                                        cache_specific_index_version(
                                            &state.reqwest_client,
                                            &state.registry_path,
                                            crate_name,
                                            version,
                                            state.clean,
                                        )
                                        .await;
                                    } else if let Err(e) = std::fs::write(&crate_path, &content) {
                                        tracing::warn!(error = %e, "failed caching crate file");
                                    }

                                    let mut response =
                                        Response::new(axum::body::Body::from(content));
                                    response.headers_mut().insert(
                                        axum::http::header::CONTENT_TYPE,
                                        "application/octet-stream".parse().unwrap(),
                                    );
                                    Ok(response)
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "failed reading upstream crate response body"
                                    );
                                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                                }
                            }
                        }
                        Ok(response) => {
                            tracing::warn!(
                                status = %response.status(),
                                filename,
                                "upstream returned non-success for crate"
                            );
                            Err(StatusCode::NOT_FOUND)
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "crate proxy request to upstream failed");
                            Err(StatusCode::INTERNAL_SERVER_ERROR)
                        }
                    }
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn serve_file(
    axum::extract::State(ExecutionControl { registry_path, .. }): axum::extract::State<
        ExecutionControl,
    >,
    uri: axum::http::Uri,
) -> Result<Response, StatusCode> {
    let file_path = uri.path().trim_start_matches('/');
    tracing::info!(file_path, "fallback file request");
    let full_path = registry_path.join(file_path);

    tracing::debug!(full_path = %full_path.display(), "checking local file");

    if !full_path.starts_with(&registry_path) {
        return Err(StatusCode::FORBIDDEN);
    }

    match std::fs::read(&full_path) {
        Ok(content) => {
            let content_len = content.len();
            let mut response = Response::new(axum::body::Body::from(content));

            if let Some(ext) = full_path.extension().and_then(|e| e.to_str()) {
                let content_type = match ext {
                    "json" => "application/json",
                    "tar" | "gz" => "application/gzip",
                    _ => "application/octet-stream",
                };

                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    content_type.parse().unwrap(),
                );
            }

            tracing::info!(file_path, bytes = content_len, "served file");
            Ok(response)
        }
        Err(e) => {
            tracing::warn!(file_path, error = %e, "file not found");
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn cache_specific_index_version(
    client: &Client,
    registry_path: &Path,
    crate_name: &str,
    version: &str,
    clean: bool,
) {
    tracing::info!(crate_name, version, "caching index entry");

    let index_path = get_index_path(registry_path, crate_name);
    let crates_io_url = get_crates_io_index_url(crate_name);

    match client.get(&crates_io_url).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(content) = response.bytes().await {
                let content_str = String::from_utf8_lossy(&content);

                for line in content_str.lines() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line)
                        && let Some(version_str) = parsed.get("vers").and_then(|v| v.as_str())
                        && version_str == version
                    {
                        let mut cached_content = String::new();

                        if clean {
                            cached_content.push_str(line);
                            cached_content.push('\n');
                        } else {
                            if let Ok(existing) = std::fs::read_to_string(&index_path) {
                                cached_content = existing;
                            }

                            if !cached_content.contains(&format!("\"vers\":\"{}\"", version)) {
                                cached_content.push_str(line);
                                cached_content.push('\n');
                            } else {
                                return;
                            }
                        }

                        if let Some(parent) = index_path.parent()
                            && let Err(e) = std::fs::create_dir_all(parent)
                        {
                            tracing::warn!(error = %e, "failed creating index directory");
                            return;
                        }

                        if let Err(e) = std::fs::write(&index_path, cached_content.as_bytes()) {
                            tracing::warn!(error = %e, "failed writing index entry");
                        } else {
                            tracing::info!(crate_name, version, "index entry cached");
                        }
                        return;
                    }
                }
                tracing::warn!(version, crate_name, "version not found in upstream index");
            }
        }
        Ok(response) => {
            tracing::warn!(
                status = %response.status(),
                "upstream returned non-success for index fetch"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "index fetch from upstream failed");
        }
    }
}

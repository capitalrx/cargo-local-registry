mod crates;
mod index;
mod parsing;
mod types;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::{
    Json, Router, extract::Path as AxumPath, http::StatusCode, response::Response, routing::get,
};
use cargo::util::errors::*;
use reqwest::Client;

use parsing::parse_crate_filename;
pub use types::{CachedIndex, DEFAULT_REFRESH_TTL_SECS, ExecutionControl};

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
    let index_path = index::get_index_path(&registry_path, &crate_name);

    tracing::debug!(index_path = %index_path.display(), "checking local index");

    if enable_proxy {
        let should_try_refresh = if let Ok(cache) = index_cache.read() {
            if let Some(cached) = cache.get(&crate_name) {
                let since_last_check = cached.last_check.elapsed();
                if since_last_check < cache_ttl {
                    tracing::info!(
                        crate_name,
                        elapsed = ?since_last_check,
                        "serving from cache, within ttl"
                    );
                    let mut response =
                        Response::new(axum::body::Body::from(cached.content.clone()));
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain".parse().unwrap(),
                    );
                    return Ok(response);
                } else {
                    tracing::info!(
                        crate_name,
                        elapsed = ?since_last_check,
                        "cache stale, checking upstream availability"
                    );
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

            let crates_io_url = index::get_crates_io_index_url(&crate_name);

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

                let crates_io_url = index::get_crates_io_index_url(&crate_name);

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
                                            crates::remove_prior_versions(
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

    let index_path = index::get_index_path(registry_path, crate_name);
    let crates_io_url = index::get_crates_io_index_url(crate_name);

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

/// Check if the local registry contains all dependencies from one or more projects
pub fn check_registry(
    projects: &[impl AsRef<Path>],
    registry_path: impl AsRef<Path>,
    include_git: bool,
    config: &cargo::util::GlobalContext,
) -> CargoResult<()> {
    use anyhow::Context as _;
    use cargo::core::Workspace;
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;

    let projects: Vec<&Path> = projects.iter().map(|p| p.as_ref()).collect();
    let registry_path = registry_path.as_ref();

    let canonical_registry = registry_path
        .canonicalize()
        .unwrap_or_else(|_| registry_path.to_path_buf());

    if !canonical_registry.exists() {
        anyhow::bail!(
            "registry path does not exist: {}",
            canonical_registry.display()
        );
    }

    let mut all_required_crates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut project_count = 0;

    for path in &projects {
        let (lockfile, project_name) =
            if path.is_file() && path.file_name() == Some(std::ffi::OsStr::new("Cargo.lock")) {
                (
                    path.to_path_buf(),
                    path.parent()
                        .and_then(|p| p.file_name())
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                )
            } else if path.is_dir() {
                let lock = path.join("Cargo.lock");
                if !lock.exists() {
                    tracing::warn!(path = %path.display(), "skipping directory without lockfile");
                    continue;
                }
                (
                    lock,
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                )
            } else {
                tracing::warn!(path = %path.display(), "skipping non-directory, non-lockfile path");
                continue;
            };

        if !lockfile.exists() {
            tracing::warn!(lockfile = %lockfile.display(), "skipping missing lockfile");
            continue;
        }

        project_count += 1;
        tracing::debug!(project_name, lockfile = %lockfile.display(), "processing project dependencies");

        let manifest = lockfile.parent().unwrap().join("Cargo.toml");
        let manifest = env::current_dir()?.join(&manifest);

        let ws = Workspace::new(&manifest, config)
            .with_context(|| format!("failed to create workspace for {}", manifest.display()))?;
        let (packages, resolve) = cargo::ops::resolve_ws(&ws, false).with_context(|| {
            format!(
                "failed to resolve dependencies from lockfile: {}",
                lockfile.display()
            )
        })?;

        packages.get_many(resolve.iter()).with_context(|| {
            format!(
                "failed to get packages from lockfile: {}",
                lockfile.display()
            )
        })?;

        for id in resolve.iter() {
            if id.source_id().is_git() {
                if !include_git {
                    continue;
                }
            } else if !id.source_id().is_registry() {
                continue;
            }

            let name = id.name().to_string();
            let version = id.version().to_string();

            all_required_crates.entry(name).or_default().insert(version);
        }
    }

    if project_count == 0 {
        anyhow::bail!("no valid projects found to check");
    }

    tracing::debug!(
        unique_crates = all_required_crates.len(),
        project_count,
        "verifying registry against project dependencies"
    );

    let mut missing_crates = Vec::new();
    let mut missing_versions = Vec::new();

    for (crate_name, versions) in &all_required_crates {
        for version in versions {
            let crate_file = format!("{}-{}.crate", crate_name, version);
            let crate_path = canonical_registry.join(&crate_file);

            if !crate_path.exists() {
                missing_crates.push((crate_name.clone(), version.clone()));
            }

            let index_path = index::get_index_path(&canonical_registry, crate_name);
            if index_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&index_path) {
                    let has_version = content.lines().any(|line| {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                            parsed.get("vers").and_then(|v| v.as_str()) == Some(version.as_str())
                        } else {
                            false
                        }
                    });

                    if !has_version {
                        missing_versions.push((crate_name.clone(), version.clone()));
                    }
                }
            } else {
                missing_versions.push((crate_name.clone(), version.clone()));
            }
        }
    }

    let mut extra_crates = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&canonical_registry) {
        for entry in entries.flatten() {
            if let Some(filename) = entry.file_name().to_str()
                && filename.ends_with(".crate")
                && let Some((crate_name, version)) = parse_crate_filename(filename)
            {
                let is_needed = all_required_crates
                    .get(crate_name)
                    .map(|versions| versions.contains(version))
                    .unwrap_or(false);

                if !is_needed {
                    extra_crates.push((crate_name.to_string(), version.to_string()));
                }
            }
        }
    }

    let has_issues =
        !missing_crates.is_empty() || !missing_versions.is_empty() || !extra_crates.is_empty();

    if !has_issues {
        tracing::info!(
            crate_count = all_required_crates.len(),
            "registry verification successful"
        );
        Ok(())
    } else {
        if !missing_crates.is_empty() {
            eprintln!("missing crate files:");
            for (name, version) in &missing_crates {
                eprintln!("  {}-{}.crate", name, version);
            }
            eprintln!();
        }

        if !missing_versions.is_empty() {
            eprintln!("missing index entries:");
            for (name, version) in &missing_versions {
                eprintln!("  {} version {}", name, version);
            }
            eprintln!();
        }

        if !extra_crates.is_empty() {
            eprintln!("extra crates not needed by any project:");
            for (name, version) in &extra_crates {
                eprintln!("  {}-{}.crate", name, version);
            }
            eprintln!();
        }

        if !missing_crates.is_empty() || !missing_versions.is_empty() {
            eprintln!("to add missing crates, run:");
            for project_path in &projects {
                let lockfile = if project_path.is_file() {
                    project_path.to_path_buf()
                } else {
                    project_path.join("Cargo.lock")
                };

                if lockfile.exists() {
                    eprintln!(
                        "  cargo local-registry create --sync {} {}",
                        lockfile.display(),
                        canonical_registry.display()
                    );
                }
            }
            eprintln!();
        }

        if !extra_crates.is_empty() {
            eprintln!("to remove extra crates:");
            eprintln!("  1. sync all projects without --no-delete flag");
            eprintln!("  2. or manually delete the .crate files listed above");
            eprintln!();
        }

        anyhow::bail!(
            "registry has {} missing crate(s), {} missing index entry(ies), {} extra crate(s)",
            missing_crates.len(),
            missing_versions.len(),
            extra_crates.len()
        );
    }
}

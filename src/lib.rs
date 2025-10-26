mod utils;

pub use utils::*;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::{self, Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::{
    Json, Router, extract::Path as AxumPath, http::StatusCode, response::Response, routing::get,
};
use cargo::core::dependency::DepKind;
use cargo::core::resolver::Resolve;
use cargo::core::{Package, SourceId, Workspace};
use cargo::sources::PathSource;
use cargo::util::GlobalContext;
use cargo::util::errors::*;
use cargo_platform::Platform;
use flate2::write::GzEncoder;
use rayon::prelude::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tar::{Builder, Header};

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

#[derive(Debug, Clone)]
pub struct RegistryDelta {
    pub missing_crates: Vec<(String, String)>,
    pub missing_versions: Vec<(String, String)>,
    pub extra_crates: Vec<(String, String)>,
}

impl RegistryDelta {
    pub fn has_issues(&self) -> bool {
        !self.missing_crates.is_empty()
            || !self.missing_versions.is_empty()
            || !self.extra_crates.is_empty()
    }

    pub fn has_missing(&self) -> bool {
        !self.missing_crates.is_empty() || !self.missing_versions.is_empty()
    }
}

pub fn determine_registry_delta(
    projects: &[impl AsRef<Path>],
    registry_path: impl AsRef<Path>,
    include_git: bool,
    config: &cargo::util::GlobalContext,
) -> CargoResult<RegistryDelta> {
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
                    anyhow::bail!(
                        "cargo.lock not found in project directory: {}",
                        path.display()
                    );
                }
                (
                    lock,
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                )
            } else {
                anyhow::bail!(
                    "path must be a cargo.lock file or project directory: {}",
                    path.display()
                );
            };

        let manifest = lockfile.parent().unwrap().join("Cargo.toml");
        let manifest = env::current_dir()?.join(&manifest);

        let ws = Workspace::new(&manifest, config)
            .with_context(|| format!("failed to load workspace for {}", project_name))?;

        let (_packages, resolve) = cargo::ops::resolve_ws(&ws, false)
            .with_context(|| format!("failed to resolve dependencies for {}", project_name))?;

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

    let mut missing_crates = Vec::new();
    let mut missing_versions = Vec::new();

    for (name, versions) in &all_required_crates {
        for version in versions {
            let crate_file = canonical_registry.join(format!("{}-{}.crate", name, version));

            if !crate_file.exists() {
                missing_crates.push((name.clone(), version.clone()));
            }

            let index_path = get_index_path(&canonical_registry, name);
            if let Ok(content) = std::fs::read_to_string(&index_path) {
                let has_version = content.lines().any(|line| {
                    line.contains(&format!("\"vers\":\"{}\"", version))
                        || line.contains(&format!("\"vers\": \"{}\"", version))
                });

                if !has_version {
                    missing_versions.push((name.clone(), version.clone()));
                }
            } else {
                missing_versions.push((name.clone(), version.clone()));
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

    Ok(RegistryDelta {
        missing_crates,
        missing_versions,
        extra_crates,
    })
}

pub fn add_missing_crates(
    delta: &RegistryDelta,
    projects: &[impl AsRef<Path>],
    registry_path: impl AsRef<Path>,
    include_git: bool,
    config: &cargo::util::GlobalContext,
) -> CargoResult<()> {
    if !delta.has_missing() {
        return Ok(());
    }

    let registry_path = registry_path.as_ref();
    let canonical_registry = registry_path
        .canonicalize()
        .unwrap_or_else(|_| registry_path.to_path_buf());

    let projects: Vec<&Path> = projects.iter().map(|p| p.as_ref()).collect();

    let registry_id = SourceId::crates_io_maybe_sparse_http(config)?;

    for path in &projects {
        let lockfile = if path.is_file() {
            path.to_path_buf()
        } else {
            path.join("Cargo.lock")
        };

        if lockfile.exists() {
            sync_crates_to_registry(
                &lockfile,
                &canonical_registry,
                &registry_id,
                include_git,
                false, // sync_public_deps = false
                config,
            )?;
        }
    }

    Ok(())
}
pub fn remove_extra_crates(
    delta: &RegistryDelta,
    registry_path: impl AsRef<Path>,
) -> CargoResult<()> {
    if delta.extra_crates.is_empty() {
        return Ok(());
    }

    let registry_path = registry_path.as_ref();
    let canonical_registry = registry_path
        .canonicalize()
        .unwrap_or_else(|_| registry_path.to_path_buf());

    for (name, version) in &delta.extra_crates {
        let crate_file = canonical_registry.join(format!("{}-{}.crate", name, version));
        if crate_file.exists() {
            std::fs::remove_file(&crate_file)?;
        }
    }

    Ok(())
}

#[derive(Debug)]
enum FileTask {
    Copy {
        src: PathBuf,
        dst: PathBuf,
    },
    CreateArchive {
        files: Vec<PathBuf>,
        pkg_root: PathBuf,
        pkg_name: String,
        pkg_version: String,
        dst: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct RegistryPackage {
    name: String,
    vers: String,
    deps: Vec<RegistryDependency>,
    cksum: String,
    features: BTreeMap<String, Vec<String>>,
    yanked: Option<bool>,
}

#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
struct RegistryDependency {
    name: String,
    req: String,
    features: Vec<String>,
    optional: bool,
    default_features: bool,
    target: Option<String>,
    kind: Option<String>,
    package: Option<String>,
}

pub fn sync_crates_to_registry(
    lockfile: &Path,
    local_dst: &Path,
    registry_id: &SourceId,
    include_git: bool,
    remove_previously_synced: bool,
    config: &GlobalContext,
) -> CargoResult<()> {
    use anyhow::Context as _;
    use std::env;

    let canonical_local_dst = local_dst.canonicalize().unwrap_or(local_dst.to_path_buf());
    let manifest = lockfile.parent().unwrap().join("Cargo.toml");
    let manifest = env::current_dir().unwrap().join(&manifest);
    let ws = Workspace::new(&manifest, config)?;
    let (packages, resolve) =
        cargo::ops::resolve_ws(&ws, false).with_context(|| "failed to load pkg lockfile")?;
    packages.get_many(resolve.iter())?;

    let hash = cargo::util::hex::short_hash(registry_id);
    let ident = registry_id.url().host().unwrap().to_string();
    let part = format!("{}-{}", ident, hash);

    let cache = config.registry_cache_path().join(&part);

    let mut file_tasks = Vec::new();
    let mut package_metadata = Vec::new();

    for id in resolve.iter() {
        if id.source_id().is_git() {
            if !include_git {
                continue;
            }
        } else if !id.source_id().is_registry() {
            continue;
        }

        let pkg = packages
            .get_one(id)
            .with_context(|| "failed to fetch package")?;
        let filename = format!("{}-{}.crate", id.name(), id.version());
        let dst = canonical_local_dst.join(&filename);

        if id.source_id().is_registry() {
            let src = cache.join(&filename).into_path_unlocked();
            file_tasks.push(FileTask::Copy {
                src,
                dst: dst.clone(),
            });
        } else {
            let src = PathSource::new(pkg.root(), pkg.package_id().source_id(), config);
            let files = src
                .list_files(pkg)?
                .iter()
                .map(|f| f.to_path_buf())
                .collect();
            file_tasks.push(FileTask::CreateArchive {
                files,
                pkg_root: pkg.root().to_path_buf(),
                pkg_name: pkg.name().to_string(),
                pkg_version: pkg.version().to_string(),
                dst: dst.clone(),
            });
        }

        let name = id.name().to_lowercase();
        let index_dir = canonical_local_dst.join("index");
        let index_dst = match name.len() {
            1 => index_dir.join("1").join(&name),
            2 => index_dir.join("2").join(&name),
            3 => index_dir.join("3").join(&name[..1]).join(&name),
            _ => index_dir.join(&name[..2]).join(&name[2..4]).join(&name),
        };

        package_metadata.push((
            dst,
            index_dst,
            serde_json::to_string(&registry_pkg(pkg, &resolve)).unwrap(),
            id.version().to_string(),
        ));
    }

    file_tasks
        .par_iter()
        .try_for_each(|task| -> Result<(), anyhow::Error> {
            match task {
                FileTask::Copy { src, dst } => {
                    fs::copy(src, dst).with_context(|| {
                        format!("failed to copy `{}` to `{}`", src.display(), dst.display())
                    })?;
                }
                FileTask::CreateArchive {
                    files,
                    pkg_root,
                    pkg_name,
                    pkg_version,
                    dst,
                } => {
                    let file = File::create(dst)?;
                    let gz = GzEncoder::new(file, flate2::Compression::best());
                    let mut ar = Builder::new(gz);
                    ar.mode(tar::HeaderMode::Deterministic);
                    build_ar_from_files(&mut ar, files, pkg_root, pkg_name, pkg_version)?;
                }
            }
            Ok(())
        })?;

    let mut added_crates = HashSet::new();
    let mut added_index = HashSet::new();

    for (crate_dst, index_dst, line, version) in package_metadata {
        added_crates.insert(crate_dst);

        fs::create_dir_all(index_dst.parent().unwrap())?;

        let prev = if !remove_previously_synced || added_index.contains(&index_dst) {
            read_file_to_string(&index_dst).unwrap_or_default()
        } else {
            String::new()
        };
        let mut prev_entries = prev
            .lines()
            .filter(|entry_line| {
                let pkg: RegistryPackage = serde_json::from_str(entry_line).unwrap();
                pkg.vers != version
            })
            .collect::<Vec<_>>();
        prev_entries.push(&line);
        prev_entries.sort();
        let new_contents = prev_entries.join("\n");

        File::create(&index_dst).and_then(|mut f| f.write_all(new_contents.as_bytes()))?;
        added_index.insert(index_dst);
    }

    if remove_previously_synced {
        let existing_crates: Vec<PathBuf> = canonical_local_dst
            .read_dir()
            .map(|iter| {
                iter.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|name| name.ends_with(".crate"))
                    })
                    .map(|e| e.path())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|_| Vec::new());

        for path in existing_crates {
            if !added_crates.contains(&path) {
                fs::remove_file(&path)?;
            }
        }

        scan_delete(&canonical_local_dst.join("index"), 3, &added_index)?;
    }
    Ok(())
}

fn scan_delete(path: &Path, depth: usize, keep: &HashSet<PathBuf>) -> CargoResult<()> {
    if path.is_file() && !keep.contains(path) {
        fs::remove_file(path)?;
    } else if path.is_dir() && depth > 0 {
        for entry in (path.read_dir()?).flatten() {
            scan_delete(&entry.path(), depth - 1, keep)?;
        }

        let is_empty = path.read_dir()?.next().is_none();
        if is_empty && depth != 3 {
            fs::remove_dir(path)?;
        }
    }
    Ok(())
}

fn build_ar_from_files(
    ar: &mut Builder<GzEncoder<File>>,
    files: &[PathBuf],
    pkg_root: &Path,
    pkg_name: &str,
    pkg_version: &str,
) -> Result<(), anyhow::Error> {
    use anyhow::Context as _;

    for file_path in files {
        let relative = file_path
            .strip_prefix(pkg_root)
            .with_context(|| format!("failed to strip prefix from {}", file_path.display()))?;
        let relative_str = relative
            .to_str()
            .with_context(|| format!("invalid unicode in path: {}", relative.display()))?;

        let mut file = File::open(file_path)
            .with_context(|| format!("failed to open file: {}", file_path.display()))?;

        let path = format!(
            "{}-{}{}{}",
            pkg_name,
            pkg_version,
            path::MAIN_SEPARATOR,
            relative_str
        );

        let mut header = Header::new_ustar();
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to get metadata for: {}", file_path.display()))?;
        header
            .set_path(&path)
            .with_context(|| format!("failed to set header path: {}", path))?;
        header.set_metadata(&metadata);
        header.set_cksum();

        ar.append(&header, &mut file).with_context(|| {
            format!("failed to append file to archive: {}", file_path.display())
        })?;
    }
    Ok(())
}

fn registry_pkg(pkg: &Package, resolve: &Resolve) -> RegistryPackage {
    let id = pkg.package_id();
    let mut deps = pkg
        .dependencies()
        .iter()
        .map(|dep| {
            let (name, package) = match &dep.explicit_name_in_toml() {
                Some(explicit) => (explicit.to_string(), Some(dep.package_name().to_string())),
                None => (dep.package_name().to_string(), None),
            };

            RegistryDependency {
                name,
                req: dep.version_req().to_string(),
                features: dep.features().iter().map(|s| s.to_string()).collect(),
                optional: dep.is_optional(),
                default_features: dep.uses_default_features(),
                target: dep.platform().map(|platform| match *platform {
                    Platform::Name(ref s) => s.to_string(),
                    Platform::Cfg(ref s) => format!("cfg({})", s),
                }),
                kind: match dep.kind() {
                    DepKind::Normal => None,
                    DepKind::Development => Some("dev".to_string()),
                    DepKind::Build => Some("build".to_string()),
                },
                package,
            }
        })
        .collect::<Vec<_>>();
    deps.sort();

    let features = pkg
        .summary()
        .features()
        .iter()
        .map(|(k, v)| {
            let mut v = v.iter().map(|fv| fv.to_string()).collect::<Vec<_>>();
            v.sort();
            (k.to_string(), v)
        })
        .collect();

    RegistryPackage {
        name: id.name().to_string(),
        vers: id.version().to_string(),
        deps,
        cksum: resolve
            .checksums()
            .get(&id)
            .cloned()
            .unwrap_or_default()
            .unwrap_or_default(),
        features,
        yanked: Some(false),
    }
}

fn read_file_to_string(path: &Path) -> CargoResult<String> {
    use anyhow::Context as _;
    use std::io;

    let s = (|| -> io::Result<_> {
        let mut contents = String::new();
        let mut f = File::open(path)?;
        f.read_to_string(&mut contents)?;
        Ok(contents)
    })()
    .with_context(|| format!("failed to read: {}", path.display()))?;
    Ok(s)
}

pub fn get_crate_from_cache(
    name: &str,
    version: &str,
    config: &cargo::util::GlobalContext,
) -> CargoResult<PathBuf> {
    use cargo::core::SourceId;

    let registry_id = SourceId::crates_io_maybe_sparse_http(config)?;
    let hash = cargo::util::hex::short_hash(&registry_id);
    let ident = registry_id.url().host().unwrap().to_string();
    let part = format!("{}-{}", ident, hash);
    let cache = config.registry_cache_path().join(&part);

    let filename = format!("{}-{}.crate", name, version);
    let cache_path = cache.join(&filename).into_path_unlocked();

    if !cache_path.exists() {
        anyhow::bail!(
            "crate {}-{} not found in cache at {}",
            name,
            version,
            cache_path.display()
        );
    }

    tracing::debug!(
        name,
        version,
        cache_path = %cache_path.display(),
        "found crate in cache"
    );

    Ok(cache_path)
}

pub fn copy_crate_to_registry(
    cache_path: impl AsRef<Path>,
    registry_path: impl AsRef<Path>,
    name: &str,
    version: &str,
) -> CargoResult<PathBuf> {
    let cache_path = cache_path.as_ref();
    let registry_path = registry_path.as_ref();

    let canonical_registry = registry_path
        .canonicalize()
        .unwrap_or_else(|_| registry_path.to_path_buf());

    let filename = format!("{}-{}.crate", name, version);
    let dst = canonical_registry.join(&filename);

    std::fs::copy(cache_path, &dst)?;

    tracing::debug!(
        name,
        version,
        dst = %dst.display(),
        "copied crate to registry"
    );

    Ok(dst)
}

pub fn read_index_entry(
    registry_path: impl AsRef<Path>,
    name: &str,
) -> CargoResult<Vec<serde_json::Value>> {
    let registry_path = registry_path.as_ref();
    let canonical_registry = registry_path
        .canonicalize()
        .unwrap_or_else(|_| registry_path.to_path_buf());

    let index_path = get_index_path(&canonical_registry, name);

    if !index_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&index_path)?;
    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    Ok(entries)
}

pub fn update_index_entry(
    registry_path: impl AsRef<Path>,
    name: &str,
    version: &str,
    entry_json: &str,
) -> CargoResult<()> {
    let registry_path = registry_path.as_ref();
    let canonical_registry = registry_path
        .canonicalize()
        .unwrap_or_else(|_| registry_path.to_path_buf());

    let index_path = get_index_path(&canonical_registry, name);

    std::fs::create_dir_all(index_path.parent().unwrap())?;

    let prev = std::fs::read_to_string(&index_path).unwrap_or_default();
    let mut prev_entries: Vec<&str> = prev
        .lines()
        .filter(|entry_line| {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(entry_line) {
                parsed.get("vers").and_then(|v| v.as_str()) != Some(version)
            } else {
                true
            }
        })
        .collect();

    prev_entries.push(entry_json);
    prev_entries.sort();
    let new_contents = prev_entries.join("\n");

    std::fs::write(&index_path, new_contents)?;

    tracing::debug!(
        name,
        version,
        index_path = %index_path.display(),
        "updated index entry"
    );

    Ok(())
}

/// check if the local registry contains all dependencies from one or more projects
pub fn check_registry(
    projects: &[impl AsRef<Path>],
    registry_path: impl AsRef<Path>,
    include_git: bool,
    fix: bool,
    config: &cargo::util::GlobalContext,
) -> CargoResult<()> {
    let delta = determine_registry_delta(projects, &registry_path, include_git, config)?;

    if !delta.has_issues() {
        return Ok(());
    }

    if fix {
        if delta.has_missing() {
            add_missing_crates(&delta, projects, &registry_path, include_git, config)?;
        }
        if !delta.extra_crates.is_empty() {
            remove_extra_crates(&delta, &registry_path)?;
        }
        Ok(())
    } else {
        if !delta.missing_crates.is_empty() {
            eprintln!("missing crate files:");
            for (name, version) in &delta.missing_crates {
                eprintln!("  {}-{}.crate", name, version);
            }
            eprintln!();
        }

        if !delta.missing_versions.is_empty() {
            eprintln!("missing index entries:");
            for (name, version) in &delta.missing_versions {
                eprintln!("  {} version {}", name, version);
            }
            eprintln!();
        }

        if !delta.extra_crates.is_empty() {
            eprintln!("extra crates not needed by any project:");
            for (name, version) in &delta.extra_crates {
                eprintln!("  {}-{}.crate", name, version);
            }
            eprintln!();
        }

        if delta.has_missing() {
            let registry_path = registry_path.as_ref();
            let canonical_registry = registry_path
                .canonicalize()
                .unwrap_or_else(|_| registry_path.to_path_buf());

            eprintln!("to add missing crates, run:");
            let projects: Vec<&Path> = projects.iter().map(|p| p.as_ref()).collect();
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

        if !delta.extra_crates.is_empty() {
            eprintln!("to remove extra crates:");
            eprintln!("  1. sync all projects without --no-delete flag");
            eprintln!("  2. or manually delete the .crate files listed above");
            eprintln!();
        }

        anyhow::bail!(
            "registry has {} missing crate(s), {} missing index entry(ies), {} extra crate(s)",
            delta.missing_crates.len(),
            delta.missing_versions.len(),
            delta.extra_crates.len()
        );
    }
}

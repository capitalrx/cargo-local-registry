use cargo::util::GlobalContext;
use clap::Parser as _;
use std::path::PathBuf;

use cargo_local_registry::{check_registry, create_registry, serve_registry};

const DEFAULT_CRATE_PORT: u16 = 27283;

#[derive(clap::Parser)]
#[command(version, about)]
struct Options {
    /// Registry index to sync with
    #[arg(long)]
    host: Option<String>,
    /// Vendor git dependencies as well
    #[arg(long, default_value_t = false)]
    git: bool,
    /// Use verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// No output printed to stdout
    #[arg(short, long, default_value_t = false)]
    quiet: bool,
    /// Coloring: auto, always, never
    #[arg(short, long)]
    color: Option<String>,
    /// Don't delete older crates in the local registry directory
    #[arg(long)]
    no_delete: bool,

    #[command(subcommand)]
    command: SubCommands,
}

#[derive(clap::Parser)]
enum SubCommands {
    /// Create a local registry
    Create {
        /// Path to Cargo.lock to sync from
        #[arg(long)]
        sync: Option<String>,

        /// Path to the local registry
        path: String,
    },

    /// Serve local registry over HTTP
    Serve {
        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port to bind to
        #[arg(long, default_value_t = DEFAULT_CRATE_PORT)]
        port: u16,

        /// Path to the local registry
        path: String,

        /// Disable proxying to crates.io when crates are not found locally
        #[arg(long, default_value_t = false)]
        no_proxy: bool,

        /// Disable cleaning old versions when caching new ones (keeps all versions)
        #[arg(long, default_value_t = false)]
        no_clean: bool,
    },

    /// Check if local registry is in sync with project dependencies
    Check {
        /// Path to the local registry
        registry: PathBuf,

        /// Path(s) to Cargo.lock file(s) or project directories to check
        #[arg(required = true)]
        projects: Vec<PathBuf>,

        /// Vendor git dependencies as well
        #[arg(long, default_value_t = false)]
        git: bool,

        /// Fix missing dependencies by syncing them to the registry
        #[arg(long, default_value_t = false)]
        fix: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // We're doing the vendoring operation ourselves, so we don't actually want
    // to respect any of the `source` configuration in Cargo itself. That's
    // intended for other consumers of Cargo, but we want to go straight to the
    // source, e.g. crates.io, to fetch crates.
    let mut config = {
        let config_orig = GlobalContext::default().unwrap();
        let mut values = config_orig.values().unwrap().clone();
        values.remove("source");
        let config = GlobalContext::default().unwrap();
        config.set_values(values).unwrap();
        config
    };

    let options = if std::env::var("CARGO").is_err() || std::env::var("CARGO_PKG_NAME").is_ok() {
        // We're running the binary directly or inside `cargo run`.
        Options::parse()
    } else {
        // We're running as a `cargo` subcommand. Let's skip the second argument.
        let mut args = std::env::args().collect::<Vec<_>>();
        args.remove(1);
        Options::parse_from(args)
    };

    if let Err(err) = config.configure(
        options.verbose as u32,
        options.quiet,
        options.color.as_deref(),
        false,
        false,
        false,
        &None,
        &[],
        &[],
    ) {
        cargo::exit_with_error(err.into(), &mut config.shell());
    }

    let registry_url = options.host;
    let include_git = options.git;
    let remove_previously_synced = !options.no_delete;

    if let Err(err) = match options.command {
        SubCommands::Create { path, sync } => create_registry(
            path,
            sync,
            registry_url,
            include_git,
            remove_previously_synced,
            &config,
        ),
        SubCommands::Serve {
            host,
            port,
            path,
            no_proxy,
            no_clean,
        } => serve_registry(host, port, path, !no_proxy, !no_clean).await,
        SubCommands::Check {
            registry,
            projects,
            git,
            fix,
        } => check_registry(&projects, &registry, git, fix, &config),
    } {
        cargo::exit_with_error(err.into(), &mut config.shell());
    }
}

//! npkg: apt and dnf repositories for software released on Nostr.
//!
//! Each NIP-82 application the team publishes gets its own repository at
//! `/deb/<owner>/<d>` and `/rpm/<owner>/<d>`, where the owner is its author's
//! npub or NIP-05 address, kept current from the author's events as they're
//! published and signed with the gateway's key.

mod apt;
mod config;
mod db;
mod der;
mod fdroid;
mod gvariant;
mod http;
mod inspect;
mod net;
mod nip82;
mod nostr;
mod ostree;
mod pages;
mod rate_limit;
mod repo;
mod rpmmd;
mod signing;
mod sync;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Configuration file [default: the first that exists of
    /// $XDG_CONFIG_HOME/npkg/npkg.toml
    /// (~/.config/npkg/npkg.toml) and
    /// /etc/npkg/npkg.toml]
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make the gateway's signing key. Once only: users trust it.
    Keygen {
        /// The key's user ID.
        #[arg(long, default_value = "npkg")]
        user_id: String,
    },
    /// Serve repositories.
    Serve,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(cli.config.as_deref(), &config::Environment::current())?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_new(&config.log).context("log must be tracing EnvFilter directives.")?)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    std::fs::create_dir_all(&config.data_dir).with_context(|| format!("Couldn't create {}.", config.data_dir.display()))?;
    let key_path = config.key_path();

    match cli.command {
        Command::Keygen { user_id } => {
            let signer = signing::Signer::generate(&key_path, &user_id)?;
            println!("Made {} ({}).", key_path.display(), signer.fingerprint());
        }
        Command::Serve => {
            let signer = Arc::new(signing::Signer::load(&key_path)?);
            let db = db::Db::open(&config.database_path())?;
            let names = nostr::nip05::Resolver::new(db.clone(), config.authors.clone())?;
            let store = ostree::Store::open(&config.ostree_path())?;
            let repos = repo::Repos::new(config.public_url.clone(), config.blossom_servers.clone(), db.clone(), store, signer)?;
            sync::Worker {
                relays: config.relays.clone(),
                authors: config.authors.clone(),
                resync_interval: config.resync_interval,
                db,
                repos: repos.clone(),
                names: names.clone(),
            }
            .start();
            let public_url = config.public_url.clone();
            let app =
                http::router(Arc::new(http::AppState { repos, names, public_url: public_url.clone(), authors: config.authors.clone() }));

            let bind = config.bind;
            let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("Couldn't listen on {bind}."))?;
            tracing::info!(%bind, public_url, config = %config.source.display(), "listening");
            if public_url.starts_with("http://") {
                // Signed indexes never expire, so whoever sits on the
                // connection could hold users on old ones, unseen.
                tracing::warn!(public_url, "public_url is plain http: fine for testing, but serve users over https");
            }
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}

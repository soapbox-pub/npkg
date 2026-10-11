//! npkg-gateway: apt and dnf repositories for software released on Nostr.
//!
//! Each NIP-82 application gets its own repository at `/apt/<owner>/<d>` and
//! `/rpm/<owner>/<d>`, where the owner is its author's npub or NIP-05
//! address, built from the author's events and signed with the gateway's key.

mod apt;
mod config;
mod db;
mod http;
mod inspect;
mod nip82;
mod nostr;
mod repo;
mod rpmmd;
mod signing;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Configuration file [default: the first that exists of
    /// $XDG_CONFIG_HOME/npkg-gateway/npkg-gateway.toml
    /// (~/.config/npkg-gateway/npkg-gateway.toml) and
    /// /etc/npkg-gateway/npkg-gateway.toml]
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
        #[arg(long, default_value = "npkg-gateway")]
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
            let repos = repo::Repos::new(
                repo::Config { relays: config.relays.clone(), blossom: config.blossom_servers.clone(), ttl: config.ttl },
                db,
                signer,
            )?;
            let names = nostr::nip05::Resolver::new(config.ttl)?;
            let public_url = config.public_url.clone();
            let app =
                http::router(Arc::new(http::AppState { repos, names, public_url: public_url.clone(), authors: config.authors.clone() }));

            let bind = config.bind;
            let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("Couldn't listen on {bind}."))?;
            tracing::info!(%bind, public_url, config = %config.source.display(), "listening");
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}

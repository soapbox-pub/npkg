//! npkg-gateway: apt and dnf repositories for software released on Nostr.
//!
//! Each NIP-82 application gets its own repository at `/apt/<owner>/<d>` and
//! `/rpm/<owner>/<d>`, where the owner is its author's npub or NIP-05
//! address, built from the author's events and signed with the gateway's key.

mod apt;
mod db;
mod http;
mod inspect;
mod nip82;
mod nostr;
mod repo;
mod rpmmd;
mod signing;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Where the database and the signing key are kept.
    #[arg(long, global = true, default_value = "data")]
    data: PathBuf,
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
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// The URL users reach the gateway at, for the setup files.
        #[arg(long)]
        public_url: Option<String>,
        /// Relays to look for NIP-82 events on.
        #[arg(
            long = "relay",
            default_values = ["wss://relay.ditto.pub", "wss://relay.primal.net", "wss://relay.ngit.dev", "wss://relay.damus.io", "wss://nos.lol"]
        )]
        relays: Vec<String>,
        /// Blossom servers to look for package files on, when the URL an
        /// asset names doesn't serve it.
        #[arg(long = "blossom", default_values = ["https://blossom.ditto.pub", "https://blossom.primal.net"])]
        blossom: Vec<String>,
        /// How long a repository is served before it's rebuilt, in seconds.
        #[arg(long, default_value_t = 300)]
        ttl: u64,
    },
}

const KEY_FILE: &str = "signing-key.asc";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.data).with_context(|| format!("Couldn't create {}.", cli.data.display()))?;
    let key_path = cli.data.join(KEY_FILE);

    match cli.command {
        Command::Keygen { user_id } => {
            let signer = signing::Signer::generate(&key_path, &user_id)?;
            println!("Made {} ({}).", key_path.display(), signer.fingerprint());
        }
        Command::Serve { listen, public_url, relays, blossom, ttl } => {
            let signer = Arc::new(signing::Signer::load(&key_path)?);
            let db = db::Db::open(&cli.data.join("npkg-gateway.sqlite"))?;
            let ttl = Duration::from_secs(ttl);
            let config = repo::Config { relays, blossom, ttl };
            let repos = repo::Repos::new(config, db, signer)?;
            let names = nostr::nip05::Resolver::new(ttl)?;
            let public_url = public_url.unwrap_or_else(|| format!("http://{listen}")).trim_end_matches('/').to_string();
            let app = http::router(Arc::new(http::AppState { repos, names, public_url: public_url.clone() }));

            let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("Couldn't listen on {listen}."))?;
            tracing::info!(%listen, public_url, "listening");
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}

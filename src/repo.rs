//! A repository: one NIP-82 application's packages, built from its author's
//! events, rendered for apt and dnf, and signed.
//!
//! A repository is built the first time it's asked for, and that request
//! waits. After that it's served from memory, and rebuilt in the background
//! once it's older than the TTL, so no later request waits on relays.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::db::{Db, Inspected};
use crate::inspect::{self, Format, Meta};
use crate::nip82::{self, Asset};
use crate::nostr::nip19;
use crate::policy::{self, Candidate, Rejection};
use crate::signing::Signer;
use crate::{apt, rpmmd};

/// NIP-82's channels (Appendix B), most stable first. Each suite holds its
/// own channel's releases and every more stable one's: `beta` users get a
/// stable release that's newer than the last beta.
pub const CHANNELS: [&str; 4] = ["main", "beta", "nightly", "dev"];

/// The largest package file downloaded to inspect.
const MAX_PACKAGE: u64 = 512 << 20;

/// Package files downloaded at once, per repository.
const DOWNLOADS: usize = 4;

/// The most package files one repository considers.
const MAX_CANDIDATES: usize = 500;

/// How long a failed build is remembered before the next request tries again.
const FAILURE_TTL: Duration = Duration::from_secs(30);

pub struct Config {
    pub relays: Vec<String>,
    /// Blossom servers to look for a package file on, after its own URL.
    pub blossom: Vec<String>,
    pub ttl: Duration,
}

/// A suite or channel name as a rank in [`CHANNELS`]. `stable` is apt's
/// usual name for what NIP-82 calls `main`.
pub fn channel_rank(name: &str) -> Option<usize> {
    if name == "stable" {
        return Some(0);
    }
    CHANNELS.iter().position(|channel| *channel == name)
}

/// One file the repository serves.
#[derive(Clone, Debug)]
pub struct Package {
    pub d: String,
    /// The NIP-82 release's version.
    pub version: String,
    pub channel: usize,
    pub created_at: i64,
    pub arch: String,
    pub sha256: String,
    pub size: u64,
    pub url: String,
    pub meta: Meta,
}

pub struct Repo {
    pub pubkey: String,
    pub d: String,
    pub name: String,
    pub summary: Option<String>,
    pub packages: Vec<Package>,
    pub rejections: Vec<Rejection>,
    /// By suite, then by path below `dists/<suite>/`.
    apt: HashMap<String, HashMap<String, Vec<u8>>>,
    /// By channel, then by path below it.
    rpm: HashMap<usize, HashMap<String, Vec<u8>>>,
}

impl Repo {
    pub fn apt_file(&self, suite: &str, path: &str) -> Option<&[u8]> {
        self.apt.get(suite)?.get(path).map(Vec::as_slice)
    }

    pub fn rpm_file(&self, channel: usize, path: &str) -> Option<&[u8]> {
        self.rpm.get(&channel)?.get(path).map(Vec::as_slice)
    }

    /// Where to download the file with this hash, if it's one of this
    /// repository's. Nothing else is redirected to.
    pub fn download_url(&self, format: Format, sha256: &str) -> Option<&str> {
        self.packages.iter().find(|package| package.sha256 == sha256 && package.meta.format() == format).map(|package| package.url.as_str())
    }
}

#[derive(Clone, Debug)]
pub enum BuildError {
    NotFound(String),
    Failed(String),
}

type BuildResult = Result<Arc<Repo>, BuildError>;

struct Built {
    at: Instant,
    result: BuildResult,
}

#[derive(Default)]
struct Slot {
    state: tokio::sync::Mutex<Option<Built>>,
    refreshing: AtomicBool,
}

pub struct Repos {
    config: Config,
    db: Db,
    http: reqwest::Client,
    signer: Arc<Signer>,
    /// Never held across an await.
    slots: std::sync::Mutex<HashMap<(String, String), Arc<Slot>>>,
}

impl Repos {
    pub fn new(config: Config, db: Db, signer: Arc<Signer>) -> anyhow::Result<Arc<Repos>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("npkg-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Arc::new(Repos { config, db, http, signer, slots: Default::default() }))
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// The repository for `pubkey`'s application `d`.
    pub async fn get(self: &Arc<Self>, pubkey: &str, d: &str) -> BuildResult {
        let key = (pubkey.to_string(), d.to_string());
        let slot = self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(key.clone()).or_default().clone();

        let mut state = slot.state.lock().await;
        if let Some(built) = &*state {
            let ttl = if built.result.is_ok() { self.config.ttl } else { FAILURE_TTL };
            if built.at.elapsed() < ttl {
                return built.result.clone();
            }
            if built.result.is_ok() {
                if !slot.refreshing.swap(true, Ordering::AcqRel) {
                    let (repos, slot) = (self.clone(), slot.clone());
                    tokio::spawn(async move {
                        let result = repos.build(&key.0, &key.1).await;
                        let mut state = slot.state.lock().await;
                        match result {
                            Ok(repo) => *state = Some(Built { at: Instant::now(), result: Ok(repo) }),
                            // What was built last stays up while relays or
                            // servers are failing.
                            Err(error) => tracing::warn!(pubkey = key.0, d = key.1, ?error, "rebuild failed"),
                        }
                        slot.refreshing.store(false, Ordering::Release);
                    });
                }
                return built.result.clone();
            }
        }

        let result = self.build(pubkey, d).await;
        *state = Some(Built { at: Instant::now(), result: result.clone() });
        result
    }

    async fn build(&self, pubkey: &str, d: &str) -> BuildResult {
        let started = Instant::now();
        let snapshot = nip82::fetch(&self.config.relays, pubkey, d).await.map_err(|error| BuildError::Failed(format!("{error:#}")))?;
        if snapshot.application.is_none() && snapshot.releases.is_empty() {
            return Err(BuildError::NotFound(format!(
                "No NIP-82 application {d:?} by {} was found on the gateway's relays.",
                nip19::npub_encode(pubkey)
            )));
        }

        let mut rejections = Vec::new();
        let mut wanted = Vec::new();
        for release in &snapshot.releases {
            let Some(channel) = channel_rank(&release.channel).filter(|_| release.channel != "stable") else {
                rejections.push(Rejection {
                    version: release.version.clone(),
                    sha256: String::new(),
                    reason: format!("The release's channel, {:?}, isn't one of NIP-82's: {}.", release.channel, CHANNELS.join(", ")),
                });
                continue;
            };
            for asset in &release.assets {
                if let Some(format) = Format::from_mime(&asset.mime) {
                    wanted.push((release.clone(), channel, asset.clone(), format));
                }
            }
        }
        wanted.truncate(MAX_CANDIDATES);

        let inspected: Vec<_> = futures_util::stream::iter(wanted)
            .map(|(release, channel, asset, format)| async move {
                let result = self.inspected(&asset, format).await;
                (release, channel, asset, result)
            })
            .buffer_unordered(DOWNLOADS)
            .collect()
            .await;

        let mut candidates = Vec::new();
        let mut found: HashMap<String, (i64, usize, Inspected)> = HashMap::new();
        for (release, channel, asset, result) in inspected {
            let reject = |reason: String| Rejection { version: release.version.clone(), sha256: asset.sha256.clone(), reason };
            match result {
                Ok(inspected) => match &inspected.meta {
                    Ok(meta) => {
                        candidates.push(Candidate {
                            release_version: release.version.clone(),
                            asset_version: asset.version.clone(),
                            platforms: asset.platforms.clone(),
                            sha256: asset.sha256.clone(),
                            meta: meta.clone(),
                        });
                        found.insert(asset.sha256.clone(), (release.created_at, channel, inspected));
                    }
                    Err(error) => rejections.push(reject(error.clone())),
                },
                Err(error) => rejections.push(reject(format!("{error:#}"))),
            }
        }

        let (chosen, rejected) = policy::choose(d, candidates);
        rejections.extend(rejected);

        let mut packages = Vec::new();
        for (candidate, arch) in chosen {
            let format = candidate.meta.format();
            let Some((created_at, channel, inspected)) = found.get(&candidate.sha256).cloned() else { continue };
            let pinned = self
                .db
                .pin(pubkey, d, format, &candidate.release_version, &arch, &candidate.sha256)
                .await
                .map_err(|error| BuildError::Failed(format!("{error:#}")))?;

            let (sha256, inspected) = if pinned == candidate.sha256 {
                (candidate.sha256, inspected)
            } else {
                rejections.push(Rejection {
                    version: candidate.release_version.clone(),
                    sha256: candidate.sha256.clone(),
                    reason: format!("The release was republished with a different {} for {arch}. The first one stays.", format.as_str()),
                });
                match self.db.inspected(&pinned).await {
                    Ok(Some(inspected)) if inspected.meta.is_ok() => (pinned, inspected),
                    _ => continue,
                }
            };
            let Ok(meta) = inspected.meta else { continue };
            packages.push(Package {
                d: d.to_string(),
                version: candidate.release_version,
                channel,
                created_at,
                arch,
                sha256,
                size: inspected.size,
                url: inspected.url,
                meta,
            });
        }
        packages.sort_by(|a, b| (a.created_at, &a.sha256).cmp(&(b.created_at, &b.sha256)));

        for rejection in &rejections {
            tracing::info!(
                pubkey,
                d,
                version = rejection.version,
                sha256 = rejection.sha256,
                reason = rejection.reason,
                "package left out"
            );
        }

        let name = snapshot.application.as_ref().and_then(|app| app.name.clone()).unwrap_or_else(|| d.to_string());
        let summary = snapshot.application.as_ref().and_then(|app| app.summary.clone());
        let signer = self.signer.clone();
        let description = format!("{name}, published on Nostr by {}", nip19::npub_encode(pubkey));
        let (pubkey, d) = (pubkey.to_string(), d.to_string());
        let repo = tokio::task::spawn_blocking(move || -> anyhow::Result<Repo> {
            let mut apt = HashMap::new();
            let mut rpm = HashMap::new();
            for (rank, channel) in CHANNELS.iter().enumerate() {
                let included: Vec<&Package> = packages.iter().filter(|package| package.channel <= rank).collect();
                apt.insert(channel.to_string(), apt::render(channel, &d, &description, &included, &signer)?);
                if rank == 0 {
                    apt.insert("stable".into(), apt::render("stable", &d, &description, &included, &signer)?);
                }
                rpm.insert(rank, rpmmd::render(&included, &signer)?);
            }
            Ok(Repo { pubkey, d, name, summary, packages, rejections, apt, rpm })
        })
        .await
        .map_err(|error| BuildError::Failed(error.to_string()))?
        .map_err(|error| BuildError::Failed(format!("{error:#}")))?;

        tracing::info!(
            pubkey = repo.pubkey,
            d = repo.d,
            packages = repo.packages.len(),
            rejected = repo.rejections.len(),
            ms = started.elapsed().as_millis() as u64,
            "built"
        );
        Ok(Arc::new(repo))
    }

    /// What the package file `asset` names is, from the database, or by
    /// downloading and reading it. Errors are what might go differently next
    /// time, such as a server being down; what the file itself is wrong about
    /// is in the result, and stored.
    async fn inspected(&self, asset: &Asset, format: Format) -> anyhow::Result<Inspected> {
        if let Some(inspected) = self.db.inspected(&asset.sha256).await? {
            return Ok(inspected);
        }

        let mut urls: Vec<String> = asset.url.iter().filter(|url| url.starts_with("https://")).cloned().collect();
        urls.extend(self.config.blossom.iter().map(|server| format!("{}/{}", server.trim_end_matches('/'), asset.sha256)));

        let mut last_error = anyhow::anyhow!("The asset has no https URL, and no Blossom server is configured.");
        for url in urls {
            match self.download(&url, &asset.sha256).await {
                Ok(bytes) => {
                    let size = bytes.len() as u64;
                    let meta =
                        tokio::task::spawn_blocking(move || inspect::inspect(format, &bytes)).await?.map_err(|error| format!("{error:#}"));
                    let inspected = Inspected { size, url, meta };
                    self.db.store_inspected(&asset.sha256, &inspected).await?;
                    return Ok(inspected);
                }
                Err(error) => {
                    tracing::debug!(url, %error, "download failed");
                    last_error = error;
                }
            }
        }
        Err(last_error.context(format!("Couldn't download the {} {}", format.as_str(), asset.sha256)))
    }

    async fn download(&self, url: &str, sha256: &str) -> anyhow::Result<Vec<u8>> {
        let response = self.http.get(url).send().await?.error_for_status()?;
        if response.content_length().is_some_and(|length| length > MAX_PACKAGE) {
            anyhow::bail!("{url} is larger than {MAX_PACKAGE} bytes.");
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
            if bytes.len() as u64 > MAX_PACKAGE {
                anyhow::bail!("{url} is larger than {MAX_PACKAGE} bytes.");
            }
        }
        let actual = hex::encode(Sha256::digest(&bytes));
        anyhow::ensure!(actual == sha256, "{url} served a file whose sha256 is {actual}, not {sha256}.");
        Ok(bytes)
    }
}

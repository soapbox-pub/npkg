//! A repository: one NIP-82 application's packages, built from its author's
//! events, rendered for apt and dnf, and signed.
//!
//! A repository serves every .deb and .rpm its application's releases list,
//! under whatever names the files give themselves, the way a PPA serves
//! whatever its owner uploads. The release is only how a file is found: what
//! a package is, is what the file says. Adding a repository trusts its author
//! as much as adding any third-party repository does.
//!
//! A repository is built the first time it's asked for, and that request
//! waits. After that it's served from memory, and rebuilt in the background
//! once it's older than the TTL, so no later request waits on relays.

use std::collections::{HashMap, HashSet};
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
use crate::signing::Signer;
use crate::{apt, rpmmd};

/// The channels a repository offers, most stable first: apt suites, and dnf
/// repositories. Each holds its own releases and every more stable channel's,
/// so `beta` users get a stable release that's newer than the last beta.
pub const CHANNELS: [&str; 4] = ["stable", "beta", "nightly", "dev"];

/// NIP-82's channel tags (Appendix B), in the same order as [`CHANNELS`].
/// NIP-82 calls the stable channel `main`, which is a component in apt, so
/// that name stays on the Nostr side.
const RELEASE_CHANNELS: [&str; 4] = ["main", "beta", "nightly", "dev"];

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

/// A channel's rank in [`CHANNELS`].
pub fn channel_rank(name: &str) -> Option<usize> {
    CHANNELS.iter().position(|channel| *channel == name)
}

/// One file the repository serves.
#[derive(Clone, Debug)]
pub struct Package {
    /// The version of the NIP-82 release it came from.
    pub release: String,
    pub channel: usize,
    pub created_at: i64,
    pub sha256: String,
    pub size: u64,
    pub url: String,
    pub meta: Meta,
}

/// Why a file was left out, for the log and the repository's status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    /// The version of the NIP-82 release it came from.
    pub release: String,
    pub sha256: String,
    pub reason: String,
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
            let Some(channel) = RELEASE_CHANNELS.iter().position(|channel| *channel == release.channel) else {
                rejections.push(Rejection {
                    release: release.version.clone(),
                    sha256: String::new(),
                    reason: format!(
                        "The release's channel, {:?}, isn't one of NIP-82's: {}.",
                        release.channel,
                        RELEASE_CHANNELS.join(", ")
                    ),
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
        for (release, channel, asset, result) in inspected {
            let reject = |reason: String| Rejection { release: release.version.clone(), sha256: asset.sha256.clone(), reason };
            match result.map(|inspected| (inspected.meta, inspected.size, inspected.url)) {
                Ok((Ok(meta), size, url)) => candidates.push(Package {
                    release: release.version.clone(),
                    channel,
                    created_at: release.created_at,
                    sha256: asset.sha256.clone(),
                    size,
                    url,
                    meta,
                }),
                Ok((Err(error), _, _)) => rejections.push(reject(error)),
                Err(error) => rejections.push(reject(format!("{error:#}"))),
            }
        }

        let (candidates, rejected) = select(candidates);
        rejections.extend(rejected);

        // apt and dnf refuse a package version whose file changed under them,
        // so the first file for each one is the one served from then on.
        let listed: HashSet<String> = candidates.iter().map(|package| package.sha256.clone()).collect();
        let mut packages: Vec<Package> = Vec::new();
        for candidate in candidates {
            let format = candidate.meta.format();
            let key = package_key(&candidate.meta);
            let pinned =
                self.db.pin(pubkey, d, format, &key, &candidate.sha256).await.map_err(|error| BuildError::Failed(format!("{error:#}")))?;
            if pinned == candidate.sha256 {
                packages.push(candidate);
                continue;
            }
            rejections.push(Rejection {
                release: candidate.release.clone(),
                sha256: candidate.sha256.clone(),
                reason: format!("{key} is served from an earlier file, {pinned}. The first file published for a package version stays."),
            });
            // The pinned file is served even once no release lists it, in the
            // place of the one that took its name.
            if !listed.contains(&pinned)
                && !packages.iter().any(|package| package.sha256 == pinned)
                && let Ok(Some(inspected)) = self.db.inspected(&pinned).await
                && let Ok(meta) = inspected.meta
            {
                packages.push(Package { sha256: pinned, size: inspected.size, url: inspected.url, meta, ..candidate });
            }
        }
        packages.sort_by(|a, b| (a.created_at, &a.sha256).cmp(&(b.created_at, &b.sha256)));

        for rejection in &rejections {
            tracing::info!(
                pubkey,
                d,
                release = rejection.release,
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

/// A package version, as apt and dnf tell one from another: name, version
/// and architecture.
fn package_key(meta: &Meta) -> String {
    format!("{} {} {}", meta.name(), meta.version(), meta.arch())
}

/// Of the files the releases list, those an index can hold, each once, in
/// the order they're pinned: oldest release first. A file in more than one
/// release is listed under the most stable of their channels.
fn select(candidates: Vec<Package>) -> (Vec<Package>, Vec<Rejection>) {
    let mut rejections = Vec::new();
    let mut chosen: HashMap<String, Package> = HashMap::new();
    for candidate in candidates {
        if let Some(reason) = unlistable(&candidate.meta) {
            rejections.push(Rejection { release: candidate.release, sha256: candidate.sha256, reason });
            continue;
        }
        match chosen.get(&candidate.sha256) {
            Some(existing) if (existing.channel, existing.created_at) <= (candidate.channel, candidate.created_at) => {}
            _ => {
                chosen.insert(candidate.sha256.clone(), candidate);
            }
        }
    }
    let mut chosen: Vec<Package> = chosen.into_values().collect();
    chosen.sort_by(|a, b| (a.created_at, &a.sha256).cmp(&(b.created_at, &b.sha256)));
    (chosen, rejections)
}

/// Why a file can't be listed, if it can't.
fn unlistable(meta: &Meta) -> Option<String> {
    match meta {
        Meta::Deb(deb) => {
            if !apt::valid_name(deb.package()) {
                return Some(format!("{:?} isn't a name dpkg accepts.", deb.package()));
            }
            let arch = deb.architecture();
            if arch != "all" && !apt::ARCHES.contains(&arch) {
                return Some(format!("The .deb is for {arch:?}, which isn't one of the architectures served: {}.", apt::ARCHES.join(", ")));
            }
        }
        Meta::Rpm(rpm) => {
            if !rpm.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) {
                return Some(format!("{:?} isn't a name rpm accepts.", rpm.name));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::deb::parse_control;

    fn deb(control: &str, channel: usize, created_at: i64, sha: char) -> Package {
        Package {
            release: "1".into(),
            channel,
            created_at,
            sha256: sha.to_string().repeat(64),
            size: 1,
            url: String::new(),
            meta: Meta::Deb(parse_control(control).unwrap()),
        }
    }

    #[test]
    fn serves_every_name_a_release_has() {
        let (chosen, rejected) = select(vec![
            deb("Package: netbird\nVersion: 1\nArchitecture: amd64\n", 0, 1, 'a'),
            deb("Package: netbird-ui\nVersion: 1\nArchitecture: amd64\n", 0, 1, 'b'),
        ]);
        assert!(rejected.is_empty());
        let names: Vec<_> = chosen.iter().map(|package| package.meta.name()).collect();
        assert_eq!(names, ["netbird", "netbird-ui"]);
    }

    #[test]
    fn leaves_out_what_an_index_cant_hold() {
        let (chosen, rejected) = select(vec![
            deb("Package: bat\nVersion: 1\nArchitecture: musl-linux-amd64\n", 0, 1, 'a'),
            deb("Package: Bat\nVersion: 1\nArchitecture: amd64\n", 0, 1, 'b'),
            deb("Package: bat\nVersion: 1\nArchitecture: all\n", 0, 1, 'c'),
        ]);
        assert_eq!(chosen.len(), 1);
        assert_eq!(rejected.len(), 2);
    }

    #[test]
    fn lists_a_file_once_under_its_most_stable_channel() {
        let control = "Package: x1\nVersion: 1\nArchitecture: amd64\n";
        let (chosen, _) = select(vec![deb(control, 2, 5, 'a'), deb(control, 0, 9, 'a'), deb(control, 1, 1, 'a')]);
        assert_eq!(chosen.len(), 1);
        assert_eq!((chosen[0].channel, chosen[0].created_at), (0, 9));
    }

    #[test]
    fn orders_files_oldest_release_first() {
        let (chosen, _) = select(vec![
            deb("Package: x1\nVersion: 2\nArchitecture: amd64\n", 0, 20, 'a'),
            deb("Package: x1\nVersion: 1\nArchitecture: amd64\n", 0, 10, 'b'),
        ]);
        let versions: Vec<_> = chosen.iter().map(|package| package.meta.version()).collect();
        assert_eq!(versions, ["1", "2"]);
    }

    #[test]
    fn keys_packages_as_apt_and_dnf_do() {
        let meta = crate::inspect::rpm::inspect(include_bytes!("../tests/fixtures/hello-1.2.0-rc.1.x86_64.rpm")).unwrap();
        assert_eq!(package_key(&Meta::Rpm(Box::new(meta))), "hello 0:1.2.0~rc.1-1 x86_64");
        let deb = parse_control("Package: hello\nVersion: 1:1.2-3\nArchitecture: arm64\n").unwrap();
        assert_eq!(package_key(&Meta::Deb(deb)), "hello 1:1.2-3 arm64");
    }

    #[tokio::test]
    async fn pins_the_first_file_for_a_package_version() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        assert_eq!(db.pin("pk", "app", Format::Deb, "x 1 amd64", &first).await.unwrap(), first);
        assert_eq!(db.pin("pk", "app", Format::Deb, "x 1 amd64", &second).await.unwrap(), first);
        // Another version, format, or repository is a package of its own.
        assert_eq!(db.pin("pk", "app", Format::Deb, "x 2 amd64", &second).await.unwrap(), second);
        assert_eq!(db.pin("pk", "app", Format::Rpm, "x 1 amd64", &second).await.unwrap(), second);
        assert_eq!(db.pin("pk", "other", Format::Deb, "x 1 amd64", &second).await.unwrap(), second);
    }
}

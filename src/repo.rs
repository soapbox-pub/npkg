//! A repository: one NIP-82 application's packages, built from its author's
//! events, rendered for apt and dnf, and signed.
//!
//! A repository serves every .deb and .rpm its application's releases list,
//! under whatever names the files give themselves, the way a PPA serves
//! whatever its owner uploads, and every Flatpak app its `.flatpak` bundles
//! carry, unpacked into the gateway's OSTree store. The release is only how a file is found: what
//! a package is, is what the file says. Adding a repository trusts its author
//! as much as adding any third-party repository does.
//!
//! Repositories are built by the sync worker (`sync.rs`) as their events
//! arrive, and served from memory: no request ever waits on relays or on
//! downloads.

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
use crate::ostree::delta::{self, Bundle};
use crate::ostree::{Kind, Store, appstream, summary};
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

/// A Flatpak bundle a release listed, and the commit it carried.
#[derive(Clone, Debug)]
pub struct FlatpakBundle {
    /// The version of the NIP-82 release it came from.
    pub release: String,
    pub created_at: i64,
    pub sha256: String,
    pub bundle: Bundle,
}

/// One channel's Flatpak remote: the newest commit of each ref, the
/// AppStream branches that list them, and the signed summary that says so.
pub struct FlatpakChannel {
    pub refs: Vec<FlatpakBundle>,
    pub appstream: Vec<Bundle>,
    summary: Vec<u8>,
    summary_sig: Vec<u8>,
}

/// A NIP-82 release, as the gateway lists it for downloading its files
/// directly.
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    /// A rank in [`CHANNELS`].
    pub channel: usize,
    pub created_at: i64,
    pub notes: String,
    /// Every asset, whatever its type. Each `url` is where a download
    /// redirects to: the asset's own https URL, or else a Blossom server's.
    pub assets: Vec<Asset>,
}

pub struct Repo {
    pub pubkey: String,
    pub d: String,
    pub name: String,
    pub summary: Option<String>,
    pub packages: Vec<Package>,
    pub rejections: Vec<Rejection>,
    /// Highest version first.
    pub releases: Vec<Release>,
    /// By suite, then by path below `dists/<suite>/`.
    apt: HashMap<String, HashMap<String, Vec<u8>>>,
    /// By channel, then by path below it.
    rpm: HashMap<usize, HashMap<String, Vec<u8>>>,
    /// Every bundle the releases list that unpacked, oldest first.
    pub bundles: Vec<FlatpakBundle>,
    /// By channel, for each channel some release has a bundle on.
    flatpak: HashMap<usize, FlatpakChannel>,
    /// The signature of each of `bundles`' commits, as a `.commitmeta`.
    commitmeta: HashMap<String, Vec<u8>>,
    /// What it was built from.
    pub snapshot: nip82::Snapshot,
    /// Whether a file was left out for a reason that might not hold next
    /// time, such as a server being down.
    pub incomplete: bool,
}

impl Repo {
    pub fn apt_file(&self, suite: &str, path: &str) -> Option<&[u8]> {
        self.apt.get(suite)?.get(path).map(Vec::as_slice)
    }

    pub fn rpm_file(&self, channel: usize, path: &str) -> Option<&[u8]> {
        self.rpm.get(&channel)?.get(path).map(Vec::as_slice)
    }

    /// The Flatpak remote of the channel ranked `rank`, if any release on it
    /// or a more stable one has a bundle.
    pub fn flatpak(&self, rank: usize) -> Option<&FlatpakChannel> {
        self.flatpak.get(&rank)
    }

    /// A file at the top of a channel's Flatpak remote.
    pub fn flatpak_file(&self, rank: usize, name: &str) -> Option<&[u8]> {
        let channel = self.flatpak.get(&rank)?;
        match name {
            "summary" => Some(&channel.summary),
            "summary.sig" => Some(&channel.summary_sig),
            _ => None,
        }
    }

    /// Every commit the repository's Flatpak remotes serve, or could: each
    /// release's, and each channel's AppStream branches'.
    pub fn commits(&self) -> impl Iterator<Item = &str> {
        self.commitmeta.keys().map(String::as_str)
    }

    /// The signature of one of the repository's commits.
    pub fn commitmeta(&self, commit: &str) -> Option<&[u8]> {
        self.commitmeta.get(commit).map(Vec::as_slice)
    }

    /// Where to download the file with this hash, if it's one of this
    /// repository's. Nothing else is redirected to.
    pub fn download_url(&self, format: Format, sha256: &str) -> Option<&str> {
        self.packages.iter().find(|package| package.sha256 == sha256 && package.meta.format() == format).map(|package| package.url.as_str())
    }

    /// The release with this version.
    pub fn release(&self, version: &str) -> Option<&Release> {
        self.releases.iter().find(|release| release.version == version)
    }

    /// The highest version on the channel ranked `rank` or a more stable
    /// one. On the stable channel a prerelease version, like `1.2.0-rc.1`,
    /// isn't the latest even when its author tags it `main`.
    pub fn latest(&self, rank: usize) -> Option<&Release> {
        latest(&self.releases, rank)
    }
}

fn latest(releases: &[Release], rank: usize) -> Option<&Release> {
    releases.iter().find(|release| release.channel <= rank && (rank > 0 || !nip82::is_prerelease(&release.version)))
}

/// `releases`, highest version first, and the newest first of equal ones.
fn sort_releases(releases: &mut [Release]) {
    releases.sort_by(|a, b| nip82::compare_versions(&b.version, &a.version).then_with(|| b.created_at.cmp(&a.created_at)));
}

/// What the gateway has for a repository someone asks for.
pub enum Lookup {
    Found(Arc<Repo>),
    /// Not built, and the first sync since startup hasn't finished: it may
    /// yet turn up.
    Syncing,
    Missing,
}

pub struct Repos {
    /// Blossom servers to look for a package file on, after its own URL.
    blossom: Vec<String>,
    db: Db,
    store: Store,
    http: reqwest::Client,
    signer: Arc<Signer>,
    /// By author and `d`. Never held across an await.
    built: std::sync::RwLock<HashMap<(String, String), Arc<Repo>>>,
    synced: AtomicBool,
}

impl Repos {
    pub fn new(blossom: Vec<String>, db: Db, store: Store, signer: Arc<Signer>) -> anyhow::Result<Arc<Repos>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("npkg-gateway/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Arc::new(Repos { blossom, db, store, http, signer, built: Default::default(), synced: AtomicBool::new(false) }))
    }

    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The repository for `pubkey`'s application `d`.
    pub fn get(&self, pubkey: &str, d: &str) -> Lookup {
        let built = self.built.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        match built.get(&(pubkey.to_string(), d.to_string())) {
            Some(repo) => Lookup::Found(repo.clone()),
            None if !self.synced.load(Ordering::Acquire) => Lookup::Syncing,
            None => Lookup::Missing,
        }
    }

    /// Every repository, by author and then `d`.
    pub fn all(&self) -> Vec<Arc<Repo>> {
        let mut all: Vec<Arc<Repo>> = self.built.read().unwrap_or_else(|poisoned| poisoned.into_inner()).values().cloned().collect();
        all.sort_by(|a, b| (&a.pubkey, &a.d).cmp(&(&b.pubkey, &b.d)));
        all
    }

    /// Serve `repo` in place of whatever was served for its application.
    pub fn publish(&self, repo: Repo) {
        let key = (repo.pubkey.clone(), repo.d.clone());
        self.built.write().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(key, Arc::new(repo));
    }

    /// Stop serving every repository `keep` says no to.
    pub fn retain(&self, keep: impl Fn(&str, &str) -> bool) {
        self.built.write().unwrap_or_else(|poisoned| poisoned.into_inner()).retain(|(pubkey, d), _| keep(pubkey, d));
    }

    /// From now on, a repository that isn't built doesn't exist.
    pub fn mark_synced(&self) {
        self.synced.store(true, Ordering::Release);
    }

    /// The repository `snapshot` describes. `offline`, a package file not
    /// inspected before is left out rather than downloaded. An error is the
    /// gateway's own, such as its database failing: what's wrong with the
    /// author's files is in the repository's rejections.
    pub async fn build(&self, pubkey: &str, d: &str, snapshot: &nip82::Snapshot, offline: bool) -> anyhow::Result<Repo> {
        let started = Instant::now();
        let mut rejections = Vec::new();
        let mut wanted = Vec::new();
        let mut wanted_bundles = Vec::new();
        let mut releases = Vec::new();
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
                } else if asset.mime == nip82::FLATPAK_MIME {
                    wanted_bundles.push((release.clone(), asset.clone()));
                }
            }
            let assets = release
                .assets
                .iter()
                .map(|asset| Asset {
                    url: asset
                        .url
                        .clone()
                        .filter(|url| url.starts_with("https://"))
                        .or_else(|| self.blossom.first().map(|server| format!("{}/{}", server.trim_end_matches('/'), asset.sha256))),
                    ..asset.clone()
                })
                .collect();
            releases.push(Release {
                version: release.version.clone(),
                channel,
                created_at: release.created_at,
                notes: release.notes.clone(),
                assets,
            });
        }
        sort_releases(&mut releases);
        wanted.truncate(MAX_CANDIDATES);
        wanted_bundles.truncate(MAX_CANDIDATES);

        let inspected: Vec<_> = futures_util::stream::iter(wanted)
            .map(|(release, channel, asset, format)| async move {
                let result = self.inspected(&asset, format, offline).await;
                (release, channel, asset, result)
            })
            .buffer_unordered(DOWNLOADS)
            .collect()
            .await;

        let mut candidates = Vec::new();
        let mut incomplete = false;
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
                Err(error) => {
                    incomplete = true;
                    rejections.push(reject(format!("{error:#}")));
                }
            }
        }

        let unpacked: Vec<_> = futures_util::stream::iter(wanted_bundles)
            .map(|(release, asset)| async move {
                let result = self.unpacked(&asset, offline).await;
                (release, asset, result)
            })
            .buffer_unordered(DOWNLOADS)
            .collect()
            .await;
        let mut bundles = Vec::new();
        for (release, asset, result) in unpacked {
            let reject = |reason: String| Rejection { release: release.version.clone(), sha256: asset.sha256.clone(), reason };
            match result {
                Ok(Ok(bundle)) => bundles.push(FlatpakBundle {
                    release: release.version.clone(),
                    created_at: release.created_at,
                    sha256: asset.sha256.clone(),
                    bundle,
                }),
                Ok(Err(error)) => rejections.push(reject(error)),
                Err(error) => {
                    incomplete = true;
                    rejections.push(reject(format!("{error:#}")));
                }
            }
        }
        bundles.sort_by(|a, b| (a.created_at, &a.sha256).cmp(&(b.created_at, &b.sha256)));

        let (candidates, rejected) = select(candidates);
        rejections.extend(rejected);

        // apt and dnf refuse a package version whose file changed under them,
        // so the first file for each one is the one served from then on.
        let listed: HashSet<String> = candidates.iter().map(|package| package.sha256.clone()).collect();
        let mut packages: Vec<Package> = Vec::new();
        for candidate in candidates {
            let format = candidate.meta.format();
            let key = package_key(&candidate.meta);
            let pinned = self.db.pin(pubkey, d, format, &key, &candidate.sha256).await?;
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
        let (pubkey, d, snapshot) = (pubkey.to_string(), d.to_string(), snapshot.clone());
        let store = self.store.clone();
        let repo = tokio::task::spawn_blocking(move || -> anyhow::Result<Repo> {
            let mut apt = HashMap::new();
            let mut rpm = HashMap::new();
            let mut flatpak = HashMap::new();
            // The newest app's date, so AppStream commits are made again
            // the same until an app changes, and never go back in time.
            let appstream_date = bundles.iter().map(|bundle| bundle.bundle.timestamp).max().unwrap_or(0);
            for (rank, channel) in CHANNELS.iter().enumerate() {
                let included: Vec<&Package> = packages.iter().filter(|package| package.channel <= rank).collect();
                apt.insert(channel.to_string(), apt::render(channel, &d, &description, &included, &signer)?);
                rpm.insert(rank, rpmmd::render(&included, &signer)?);
                let refs = flatpak_heads(&releases, &bundles, rank);
                if !refs.is_empty() {
                    let apps: Vec<&Bundle> = refs.iter().map(|head| &head.bundle).collect();
                    let appstream = appstream::build(&store, &apps, appstream_date)?;
                    let summary = summary::render(&apps.iter().copied().chain(&appstream).collect::<Vec<_>>());
                    let summary_sig = summary::signatures(&signer, &summary)?;
                    flatpak.insert(rank, FlatpakChannel { refs, appstream, summary, summary_sig });
                }
            }
            let mut commitmeta = HashMap::new();
            let appstream = flatpak.values().flat_map(|channel| channel.appstream.iter().map(|branch| &branch.commit));
            for commit in bundles.iter().map(|bundle| &bundle.bundle.commit).chain(appstream) {
                if !commitmeta.contains_key(commit) {
                    commitmeta.insert(commit.clone(), summary::signatures(&signer, &store.read(Kind::Commit, commit)?)?);
                }
            }
            Ok(Repo {
                pubkey,
                d,
                name,
                summary,
                packages,
                rejections,
                releases,
                apt,
                rpm,
                bundles,
                flatpak,
                commitmeta,
                snapshot,
                incomplete,
            })
        })
        .await??;

        tracing::info!(
            pubkey = repo.pubkey,
            d = repo.d,
            packages = repo.packages.len(),
            bundles = repo.bundles.len(),
            rejected = repo.rejections.len(),
            ms = started.elapsed().as_millis() as u64,
            offline,
            "built"
        );
        Ok(repo)
    }

    /// What the package file `asset` names is, from the database, or by
    /// downloading and reading it. Errors are what might go differently next
    /// time, such as a server being down; what the file itself is wrong about
    /// is in the result, and stored.
    async fn inspected(&self, asset: &Asset, format: Format, offline: bool) -> anyhow::Result<Inspected> {
        if let Some(inspected) = self.db.inspected(&asset.sha256).await? {
            return Ok(inspected);
        }
        // Only a file whose download failed last time gets here.
        anyhow::ensure!(!offline, "The file isn't downloaded yet. It will be tried again when the repository is next refreshed.");

        let mut urls: Vec<String> = asset.url.iter().filter(|url| url.starts_with("https://")).cloned().collect();
        urls.extend(self.blossom.iter().map(|server| format!("{}/{}", server.trim_end_matches('/'), asset.sha256)));

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

    /// The commit the Flatpak bundle `asset` names carried, from the
    /// database, or by downloading the bundle and unpacking it into the
    /// store. The bundle itself isn't kept. Errors are as [`Self::inspected`]
    /// has them.
    async fn unpacked(&self, asset: &Asset, offline: bool) -> anyhow::Result<Result<Bundle, String>> {
        match self.db.bundle(&asset.sha256).await? {
            // Pruning took its objects once no release listed it.
            Some(Ok(bundle)) if !self.store.has(Kind::Commit, &bundle.commit) => {}
            Some(known) => return Ok(known),
            None => {}
        }
        anyhow::ensure!(!offline, "The bundle isn't unpacked yet. It will be tried again when the repository is next refreshed.");

        let mut urls: Vec<String> = asset.url.iter().filter(|url| url.starts_with("https://")).cloned().collect();
        urls.extend(self.blossom.iter().map(|server| format!("{}/{}", server.trim_end_matches('/'), asset.sha256)));

        let mut last_error = anyhow::anyhow!("The asset has no https URL, and no Blossom server is configured.");
        for url in urls {
            let file = match self.download_to_file(&url, &asset.sha256).await {
                Ok(file) => file,
                Err(error) => {
                    tracing::debug!(url, %error, "download failed");
                    last_error = error;
                    continue;
                }
            };
            let store = self.store.clone();
            let bundle =
                tokio::task::spawn_blocking(move || delta::unpack(file.path(), &store)).await?.map_err(|error| format!("{error:#}"));
            self.db.store_bundle(&asset.sha256, &bundle).await?;
            return Ok(bundle);
        }
        Err(last_error.context(format!("Couldn't download the bundle {}", asset.sha256)))
    }

    /// Download `url` into a temporary file in the store, checking it's the
    /// file with hash `sha256`. Bundles are too big to hold in memory.
    async fn download_to_file(&self, url: &str, sha256: &str) -> anyhow::Result<tempfile::NamedTempFile> {
        use tokio::io::AsyncWriteExt;
        let response = self.http.get(url).send().await?.error_for_status()?;
        if response.content_length().is_some_and(|length| length > MAX_PACKAGE) {
            anyhow::bail!("{url} is larger than {MAX_PACKAGE} bytes.");
        }
        let file = tempfile::NamedTempFile::new_in(self.store.tmp())?;
        let mut writer = tokio::io::BufWriter::new(tokio::fs::File::from_std(file.reopen()?));
        let mut stream = response.bytes_stream();
        let (mut hasher, mut size) = (Sha256::new(), 0u64);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size += chunk.len() as u64;
            if size > MAX_PACKAGE {
                anyhow::bail!("{url} is larger than {MAX_PACKAGE} bytes.");
            }
            hasher.update(&chunk);
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        let actual = hex::encode(hasher.finalize());
        anyhow::ensure!(actual == sha256, "{url} served a file whose sha256 is {actual}, not {sha256}.");
        Ok(file)
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

/// The bundle each ref's newest commit came from, on the channel ranked
/// `rank`: from the release [`latest`] would pick, or else the next one down
/// that has a bundle for it, so an app is still there when the latest
/// release only shipped another architecture.
fn flatpak_heads(releases: &[Release], bundles: &[FlatpakBundle], rank: usize) -> Vec<FlatpakBundle> {
    let mut heads: Vec<FlatpakBundle> = Vec::new();
    for release in releases.iter().filter(|release| release.channel <= rank && (rank > 0 || !nip82::is_prerelease(&release.version))) {
        for bundle in bundles.iter().filter(|bundle| bundle.release == release.version && bundle.created_at == release.created_at) {
            if !heads.iter().any(|head| head.bundle.ref_name == bundle.bundle.ref_name) {
                heads.push(bundle.clone());
            }
        }
    }
    heads
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

    #[test]
    fn picks_the_latest_release_by_version_and_channel() {
        let release = |version: &str, channel, created_at| Release {
            version: version.into(),
            channel,
            created_at,
            notes: String::new(),
            assets: Vec::new(),
        };
        let mut releases = vec![
            release("1.9.0", 0, 30),
            release("1.10.0", 0, 10),
            release("1.11.0-rc.1", 0, 40),
            release("2.0.0-beta.1", 1, 50),
            release("1.10.0", 2, 5),
        ];
        sort_releases(&mut releases);
        let versions: Vec<_> = releases.iter().map(|release| release.version.as_str()).collect();
        assert_eq!(versions, ["2.0.0-beta.1", "1.11.0-rc.1", "1.10.0", "1.10.0", "1.9.0"]);
        // A republished old version doesn't win by being newer.
        assert_eq!(latest(&releases, 0).map(|release| release.version.as_str()), Some("1.10.0"));
        assert_eq!(latest(&releases, 1).map(|release| release.version.as_str()), Some("2.0.0-beta.1"));
        assert!(latest(&releases[..2], 0).is_none());
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

    /// The fixture .deb, inspected into `db`, and a snapshot of one release
    /// listing it and a file never seen before.
    async fn hello(db: &Db) -> nip82::Snapshot {
        let bytes = include_bytes!("../tests/fixtures/hello_1.2.0-rc.1_amd64.deb");
        let sha256 = hex::encode(Sha256::digest(bytes));
        let url = "https://example.com/hello.deb".to_string();
        let meta = inspect::inspect(Format::Deb, bytes).unwrap();
        db.store_inspected(&sha256, &Inspected { size: bytes.len() as u64, url: url.clone(), meta: Ok(meta) }).await.unwrap();
        let asset = |sha256: String| Asset {
            mime: nip82::DEB_MIME.into(),
            sha256,
            url: Some(url.clone()),
            filename: None,
            size: Some(bytes.len() as u64),
            platforms: vec!["linux-x86_64".into()],
        };
        nip82::Snapshot {
            application: Some(nip82::Application { name: Some("Hello".into()), summary: None }),
            releases: vec![nip82::Release {
                version: "1.2.0-rc.1".into(),
                channel: "main".into(),
                created_at: 1_700_000_000,
                notes: String::new(),
                assets: vec![asset(sha256), asset("c".repeat(64))],
            }],
        }
    }

    pub fn repos(dir: &std::path::Path, db: &Db) -> Arc<Repos> {
        let key = dir.join(format!("key-{}.asc", rand::random::<u32>()));
        let signer = Arc::new(Signer::generate(&key, "test").unwrap());
        let store = Store::open(&dir.join("ostree")).unwrap();
        Repos::new(Vec::new(), db.clone(), store, signer).unwrap()
    }

    #[tokio::test]
    async fn serves_the_newest_bundle_on_each_channel() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let repos = repos(dir.path(), &db);
        let fixture = include_bytes!("../tests/fixtures/hello.flatpak");
        let path = dir.path().join("hello.flatpak");
        std::fs::write(&path, fixture).unwrap();
        let bundle = delta::unpack(&path, repos.store()).unwrap();
        let sha256 = hex::encode(Sha256::digest(fixture));
        db.store_bundle(&sha256, &Ok(bundle.clone())).await.unwrap();

        let asset = |sha256: &str| Asset {
            mime: nip82::FLATPAK_MIME.into(),
            sha256: sha256.into(),
            url: None,
            filename: None,
            size: None,
            platforms: Vec::new(),
        };
        let release = |version: &str, channel: &str, created_at, assets| nip82::Release {
            version: version.into(),
            channel: channel.into(),
            created_at,
            notes: String::new(),
            assets,
        };
        let snapshot = nip82::Snapshot {
            application: None,
            releases: vec![
                release("1.0.0", "main", 100, vec![asset(&sha256)]),
                release("2.0.0-beta.1", "beta", 200, vec![asset(&sha256)]),
                // Newer, but its bundle was never unpacked.
                release("2.0.0-beta.2", "beta", 300, vec![asset(&"d".repeat(64))]),
            ],
        };
        let repo = repos.build("pk", "hello", &snapshot, true).await.unwrap();
        assert_eq!(repo.bundles.len(), 2);
        assert!(repo.incomplete);
        let head = |rank| repo.flatpak(rank).unwrap().refs.iter().map(|head| head.release.as_str()).collect::<Vec<_>>();
        assert_eq!(head(0), ["1.0.0"]);
        assert_eq!(head(1), ["2.0.0-beta.1"]);
        assert_eq!(head(3), ["2.0.0-beta.1"]);
        assert!(repo.flatpak_file(0, "summary").is_some() && repo.flatpak_file(0, "summary.sig").is_some());
        assert!(repo.commitmeta(&bundle.commit).is_some());
        let appstream: Vec<&str> = repo.flatpak(0).unwrap().appstream.iter().map(|branch| branch.ref_name.as_str()).collect();
        assert_eq!(appstream, ["appstream/x86_64", "appstream2/x86_64"]);
        assert_eq!(repo.commits().count(), 3);
        assert!(repo.flatpak_file(0, "config").is_none());
    }

    #[tokio::test]
    async fn builds_offline_from_what_was_inspected() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let snapshot = hello(&db).await;

        let repo = repos(dir.path(), &db).build("pk", "hello", &snapshot, true).await.unwrap();
        assert_eq!(repo.name, "Hello");
        assert_eq!(repo.packages.len(), 1);
        let packages = repo.apt_file("stable", "main/binary-amd64/Packages").unwrap();
        assert!(std::str::from_utf8(packages).unwrap().contains("Package: hello"));
        // The file never inspected isn't downloaded, and is tried again later.
        assert_eq!(repo.rejections.len(), 1);
        assert_eq!(repo.rejections[0].sha256, "c".repeat(64));
        assert!(repo.incomplete);

        // Another process, from the same database, serves the same index.
        let again = repos(dir.path(), &db).build("pk", "hello", &snapshot, true).await.unwrap();
        assert_eq!(again.apt_file("stable", "Release"), repo.apt_file("stable", "Release"));
    }

    #[test]
    fn says_whether_an_unbuilt_repository_may_turn_up() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
        let repos = repos(dir.path(), &db);
        assert!(matches!(repos.get("pk", "hello"), Lookup::Syncing));
        repos.mark_synced();
        assert!(matches!(repos.get("pk", "hello"), Lookup::Missing));
    }
}

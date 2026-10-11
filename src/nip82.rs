//! NIP-82 software applications (kind 32267), releases (kind 30063) and
//! assets (kind 3063): what an author has published, read from the events the
//! gateway has stored.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::nostr::{Event, is_hex64};

pub const APPLICATION: i64 = 32267;
pub const RELEASE: i64 = 30063;
pub const ASSET: i64 = 3063;

/// Every kind the gateway follows.
pub const KINDS: [i64; 3] = [APPLICATION, RELEASE, ASSET];

pub const DEB_MIME: &str = "application/vnd.debian.binary-package";
pub const RPM_MIME: &str = "application/x-rpm";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Application {
    pub name: Option<String>,
    pub summary: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub channel: String,
    pub created_at: i64,
    pub notes: String,
    /// In the order the release lists them.
    pub assets: Vec<Asset>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub mime: String,
    pub sha256: String,
    pub url: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    /// The `f` tags: `linux-x86_64`, `android-arm64-v8a`, and so on.
    pub platforms: Vec<String>,
}

impl Asset {
    /// What the asset is called in a download URL: its `filename`, or its
    /// sha256 when it has none that fits in one path segment.
    pub fn name(&self) -> &str {
        match &self.filename {
            Some(name) if !name.is_empty() && name != "." && name != ".." && !name.chars().any(|c| c.is_control() || c == '/') => name,
            _ => &self.sha256,
        }
    }
}

/// Everything one application's author has published about it. Two are equal
/// when a repository built from either would be the same.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub application: Option<Application>,
    /// Oldest first.
    pub releases: Vec<Release>,
}

/// Whether `d` can be an application's id here: anything NIP-82 allows, short
/// of what would break a path or a file.
pub fn valid_d(d: &str) -> bool {
    !d.is_empty() && d.len() <= 256 && !d.chars().any(|c| c.is_control() || c == '/')
}

/// The `d` of every application `pubkey` has published, or published a
/// release of.
pub fn applications(events: &[Event], pubkey: &str) -> BTreeSet<String> {
    let prefix = format!("{APPLICATION}:{pubkey}:");
    let mut found = BTreeSet::new();
    for event in events.iter().filter(|event| event.pubkey == pubkey) {
        match event.kind {
            APPLICATION => found.extend(event.tag("d").map(str::to_string)),
            RELEASE => found.extend(
                tag_values(event, "a").filter_map(|a| a.strip_prefix(&prefix)).filter(|d| event.tag("i") == Some(d)).map(str::to_string),
            ),
            _ => {}
        }
    }
    found.retain(|d| valid_d(d));
    found
}

/// The ids of the assets `pubkey`'s releases list that aren't in `events`.
pub fn missing_assets(events: &[Event], pubkey: &str) -> Vec<String> {
    let have: HashSet<&str> = events.iter().filter(|event| event.kind == ASSET).map(|event| event.id.as_str()).collect();
    let mut missing: Vec<String> = events
        .iter()
        .filter(|event| event.kind == RELEASE && event.pubkey == pubkey)
        .flat_map(|event| tag_values(event, "e"))
        .filter(|id| is_hex64(id) && !have.contains(id))
        .map(str::to_string)
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// The application `pubkey:d`, its releases, and their assets, as `events`
/// have them. Only events signed by `pubkey` count: anyone can publish an
/// event that points at someone else's application.
pub fn snapshot(events: &[Event], pubkey: &str, d: &str) -> Snapshot {
    let coordinate = format!("{APPLICATION}:{pubkey}:{d}");
    let events: Vec<&Event> = events.iter().filter(|event| event.pubkey == pubkey).collect();

    let application = events
        .iter()
        .filter(|event| event.kind == APPLICATION && event.tag("d") == Some(d))
        .max_by_key(|event| (event.created_at, std::cmp::Reverse(event.id.clone())))
        .map(|event| Application { name: event.tag("name").map(str::to_string), summary: event.tag("summary").map(str::to_string) });

    // Releases are addressable: of each `d`, the newest stands.
    let mut newest: HashMap<&str, &Event> = HashMap::new();
    for event in events.iter().copied().filter(|event| event.kind == RELEASE) {
        let Some(release_d) = event.tag("d") else { continue };
        if !has_tag(event, "a", &coordinate) || event.tag("i") != Some(d) {
            continue;
        }
        let Some(version) = event.tag("version") else { continue };
        if release_d != format!("{d}@{version}") {
            continue;
        }
        let entry = newest.entry(release_d).or_insert(event);
        if (event.created_at, std::cmp::Reverse(&event.id)) > (entry.created_at, std::cmp::Reverse(&entry.id)) {
            *entry = event;
        }
    }

    // An asset's `i` is its own identifier on its platform, which NIP-82
    // lets differ from the application's: it isn't checked.
    let assets: HashMap<&str, Asset> =
        events.iter().filter(|event| event.kind == ASSET).filter_map(|event| Some((event.id.as_str(), parse_asset(event)?))).collect();

    let mut releases: Vec<Release> = newest
        .into_values()
        .map(|event| Release {
            version: event.tag("version").unwrap_or_default().to_string(),
            channel: event.tag("c").unwrap_or("main").to_string(),
            created_at: event.created_at,
            notes: event.content.clone(),
            assets: tag_values(event, "e").filter_map(|id| assets.get(id).cloned()).collect(),
        })
        .collect();
    releases.sort_by(|a, b| (a.created_at, &a.version).cmp(&(b.created_at, &b.version)));

    Snapshot { application, releases }
}

fn parse_asset(event: &Event) -> Option<Asset> {
    let sha256 = event.tag("x")?.to_ascii_lowercase();
    if !is_hex64(&sha256) {
        return None;
    }
    Some(Asset {
        mime: event.tag("m")?.to_ascii_lowercase(),
        sha256,
        url: event.tag("url").map(str::to_string),
        filename: event.tag("filename").map(str::to_string),
        size: event.tag("size").and_then(|size| size.parse().ok()),
        platforms: tag_values(event, "f").map(str::to_string).collect(),
    })
}

/// How two release versions order, semver's way where they look like
/// semver: an optional `v`, dotted numbers, then an optional `-prerelease`
/// that sorts below the release itself, and a `+build` that's ignored.
/// Missing numbers count as 0, so `1.2` is `1.2.0`. A version that isn't
/// like that sorts below every one that is, and equal to every other one.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    match (parse_version(a), parse_version(b)) {
        (Some(a), Some(b)) => {
            let parts = a.0.len().max(b.0.len());
            let core = (0..parts)
                .map(|i| compare_numbers(a.0.get(i).copied().unwrap_or("0"), b.0.get(i).copied().unwrap_or("0")))
                .find(|ordering| ordering.is_ne())
                .unwrap_or(Ordering::Equal);
            core.then_with(|| match (a.1, b.1) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => compare_prereleases(a, b),
            })
        }
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

/// Whether a version has a `-prerelease` part, like `1.2.0-rc.1`.
pub fn is_prerelease(version: &str) -> bool {
    parse_version(version).is_some_and(|(_, prerelease)| prerelease.is_some())
}

/// A version's dotted numbers and its prerelease part.
fn parse_version(version: &str) -> Option<(Vec<&str>, Option<&str>)> {
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    let version = version.split_once('+').map_or(version, |(version, _)| version);
    let (core, prerelease) = match version.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (version, None),
    };
    let core: Vec<&str> = core.split('.').collect();
    if core.iter().any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some((core, prerelease.filter(|prerelease| !prerelease.is_empty())))
}

/// Two strings of digits, as numbers of any size.
fn compare_numbers(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Semver's precedence for prereleases: numeric identifiers as numbers and
/// below alphanumeric ones, and more identifiers above fewer.
fn compare_prereleases(a: &str, b: &str) -> Ordering {
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        let ordering = match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => match (numeric(a), numeric(b)) {
                (true, true) => compare_numbers(a, b),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => a.cmp(b),
            },
        };
        if ordering.is_ne() {
            return ordering;
        }
    }
}

fn tag_values<'a>(event: &'a Event, name: &'a str) -> impl Iterator<Item = &'a str> {
    event.tags.iter().filter(move |tag| tag.first().map(String::as_str) == Some(name)).filter_map(|tag| tag.get(1).map(String::as_str))
}

fn has_tag(event: &Event, name: &str, value: &str) -> bool {
    tag_values(event, name).any(|v| v == value)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn orders_versions_like_semver() {
        let ordered = [
            "nightly",
            "0.9",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "v1.0.0",
            "1.2",
            "1.9.0",
            "1.10.0",
            "10.0.0",
        ];
        for pair in ordered.windows(2) {
            assert_eq!(compare_versions(pair[0], pair[1]), Ordering::Less, "{} < {}", pair[0], pair[1]);
            assert_eq!(compare_versions(pair[1], pair[0]), Ordering::Greater, "{} > {}", pair[1], pair[0]);
        }
        assert_eq!(compare_versions("1.0", "v1.0.0+build.5"), Ordering::Equal);
        assert_eq!(compare_versions("nightly", "git-3f2a1c"), Ordering::Equal);
        assert_eq!(compare_versions("99999999999999999999999.0", "99999999999999999999998.1"), Ordering::Greater);
    }

    #[test]
    fn tells_prereleases() {
        assert!(is_prerelease("1.2.0-rc.1"));
        assert!(is_prerelease("v2-beta"));
        assert!(!is_prerelease("1.2.0"));
        assert!(!is_prerelease("1.2.0+build-5"));
        assert!(!is_prerelease("nightly-2026"));
    }

    #[test]
    fn names_assets_by_filename_or_hash() {
        let asset = |filename: Option<&str>| Asset {
            mime: "application/zip".into(),
            sha256: "a".repeat(64),
            url: None,
            filename: filename.map(str::to_string),
            size: None,
            platforms: Vec::new(),
        };
        assert_eq!(asset(Some("Armada-v1.zip")).name(), "Armada-v1.zip");
        assert_eq!(asset(None).name(), "a".repeat(64));
        assert_eq!(asset(Some("../x")).name(), "a".repeat(64));
        assert_eq!(asset(Some("")).name(), "a".repeat(64));
    }

    const ALICE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const MALLORY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn tags(tags: &[&[&str]]) -> Vec<Vec<String>> {
        tags.iter().map(|tag| tag.iter().map(|value| value.to_string()).collect()).collect()
    }

    /// An asset, a release listing it and one that isn't stored, and the
    /// application, all by `secret`.
    pub fn published(secret: &str, version: &str, created_at: i64) -> Vec<Event> {
        let asset = Event::sign(secret, created_at, ASSET, tags(&[&["x", &"a".repeat(64)], &["m", DEB_MIME]]), "");
        let pubkey = asset.pubkey.clone();
        let coordinate = format!("{APPLICATION}:{pubkey}:app");
        let release = Event::sign(
            secret,
            created_at,
            RELEASE,
            tags(&[
                &["d", &format!("app@{version}")],
                &["a", &coordinate],
                &["i", "app"],
                &["version", version],
                &["e", &asset.id],
                &["e", &"f".repeat(64)],
            ]),
            "notes",
        );
        let application = Event::sign(secret, created_at, APPLICATION, tags(&[&["d", "app"], &["name", "App"]]), "");
        vec![asset, release, application]
    }

    #[test]
    fn reads_what_an_author_published() {
        let mut events = published(ALICE, "1.0", 100);
        let alice = events[0].pubkey.clone();
        events.extend(published(ALICE, "1.1", 200));
        // Someone else's release can't add to Alice's application.
        let mut forged = published(MALLORY, "9.9", 300);
        for event in &mut forged {
            for tag in &mut event.tags {
                if tag[0] == "a" {
                    tag[1] = format!("{APPLICATION}:{alice}:app");
                }
            }
        }
        events.extend(forged);

        assert_eq!(applications(&events, &alice), BTreeSet::from(["app".to_string()]));
        let snapshot = snapshot(&events, &alice, "app");
        assert_eq!(snapshot.application.unwrap().name.as_deref(), Some("App"));
        let versions: Vec<&str> = snapshot.releases.iter().map(|release| release.version.as_str()).collect();
        assert_eq!(versions, ["1.0", "1.1"]);
        assert_eq!(snapshot.releases[0].assets.len(), 1);
        assert_eq!(snapshot.releases[0].channel, "main");
        assert_eq!(missing_assets(&events, &alice), ["f".repeat(64)]);
    }
}

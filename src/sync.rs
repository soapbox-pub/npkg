//! The sync worker: what keeps every repository current.
//!
//! Three things drive it:
//!
//! 1. At startup, every repository is built from the events already stored,
//!    without the network, so a restart serves what it served before in
//!    milliseconds.
//! 2. A live subscription to the team's NIP-82 events, and their deletions
//!    (NIP-09), which withdraw releases. A new one rebuilds its
//!    author's repositories once things have been quiet for [`SETTLE`]: CI
//!    publishes a release's assets and then the release, and one rebuild for
//!    the lot is enough.
//! 3. A full re-fetch every `resync_interval`, so an event missed on the wire
//!    (a relay down, a restart) is still picked up, and a file that couldn't
//!    be downloaded last time is tried again.
//!
//! A repository is only rebuilt when what it's built from changed, and a
//! failed rebuild leaves the last one up.
//!
//! Once a day, after a resync, the OSTree store is pruned of what no
//! repository's releases need any more. It happens here, between builds,
//! so it never deletes an object a bundle being unpacked is counting on.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::time::Instant;

use crate::db::Db;
use crate::nip82;
use crate::nostr::{Event, relay};
use crate::repo::{Lookup, Repos};

/// How long a full fetch waits on relays, per round of queries.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Asset ids asked for in one filter.
const IDS_PER_FILTER: usize = 200;

/// How long after the last new event its author's repositories are rebuilt.
const SETTLE: Duration = Duration::from_secs(3);

/// How often the OSTree store is pruned, and how old an object has to be to
/// go: younger ones may belong to a bundle not served yet.
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 3600);
const PRUNE_GRACE: Duration = Duration::from_secs(24 * 3600);

/// How far ahead of the gateway's clock an event may be dated. One dated
/// further would stand over every later release of its address, and an
/// index dated in the future is one apt refuses, so a stolen key could
/// otherwise break a repository for good. One refused now is picked up by
/// a later resync, once its time has come.
const MAX_FUTURE: i64 = 600;

/// Whether `event` is dated no later than [`MAX_FUTURE`] from now.
fn not_future(event: &Event) -> bool {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64);
    event.created_at <= now + MAX_FUTURE
}

pub struct Worker {
    pub relays: Vec<String>,
    /// The hex pubkeys whose applications are followed.
    pub authors: HashSet<String>,
    pub resync_interval: Duration,
    pub db: Db,
    pub repos: Arc<Repos>,
}

impl Worker {
    pub fn start(self) {
        tokio::spawn(self.run());
    }

    async fn run(self) {
        match self.db.forget_authors_except(&self.authors).await {
            Ok(0) => {}
            Ok(forgotten) => tracing::info!(forgotten, "forgot the events of authors no longer listed"),
            Err(error) => tracing::warn!(?error, "couldn't forget the events of authors no longer listed"),
        }
        let authors: BTreeSet<String> = self.authors.iter().cloned().collect();
        for author in &authors {
            self.rebuild(author, false, false).await;
        }

        let filter = json!({"kinds": nip82::KINDS, "authors": authors});
        let mut live = relay::subscribe(&self.relays, vec![filter]);
        let mut resync = tokio::time::interval(self.resync_interval);
        resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut dirty = BTreeSet::new();
        let mut settled = Instant::now();
        let mut pruned: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = resync.tick() => {
                    for author in &authors {
                        self.resync(author).await;
                    }
                    self.repos.mark_synced();
                    // A full resync covered whatever was waiting.
                    dirty.clear();
                    if pruned.is_none_or(|at| at.elapsed() >= PRUNE_EVERY) {
                        self.prune().await;
                        pruned = Some(Instant::now());
                    }
                }
                Some(event) = live.recv() => {
                    if let Some(author) = self.store(event).await {
                        dirty.insert(author);
                        settled = Instant::now() + SETTLE;
                    }
                }
                _ = tokio::time::sleep_until(settled), if !dirty.is_empty() => {
                    for author in std::mem::take(&mut dirty) {
                        self.rebuild(&author, true, false).await;
                    }
                }
            }
        }
    }

    /// Delete the objects no repository's bundles need.
    async fn prune(&self) {
        let keep: HashSet<String> =
            self.repos.all().iter().flat_map(|repo| repo.commits().map(str::to_string).collect::<Vec<_>>()).collect();
        let store = self.repos.store().clone();
        match tokio::task::spawn_blocking(move || store.prune(&keep, PRUNE_GRACE)).await {
            Ok(Ok((0, _))) => {}
            Ok(Ok((objects, bytes))) => tracing::info!(objects, bytes, "pruned the OSTree store"),
            Ok(Err(error)) => tracing::warn!(?error, "couldn't prune the OSTree store"),
            Err(error) => tracing::warn!(?error, "couldn't prune the OSTree store"),
        }
    }

    /// Store a live event, and say whose it was if it was new.
    async fn store(&self, event: Event) -> Option<String> {
        if !self.authors.contains(&event.pubkey) || !nip82::KINDS.contains(&event.kind) || !not_future(&event) {
            return None;
        }
        let author = event.pubkey.clone();
        match self.db.store_events(vec![event]).await {
            Ok(0) => None,
            Ok(_) => Some(author),
            Err(error) => {
                tracing::warn!(?error, "couldn't store an event");
                None
            }
        }
    }

    /// Ask relays for everything `author` has published, then rebuild.
    async fn resync(&self, author: &str) {
        let kinds = [nip82::APPLICATION, nip82::RELEASE, nip82::DELETION];
        let filter = json!({"kinds": kinds, "authors": [author]});
        match relay::query(&self.relays, &[filter], QUERY_TIMEOUT).await {
            Ok(events) => {
                // A relay can send what it likes: only what was asked for is kept.
                let events =
                    events.into_iter().filter(|event| event.pubkey == author && kinds.contains(&event.kind) && not_future(event)).collect();
                if let Err(error) = self.db.store_events(events).await {
                    tracing::warn!(author, ?error, "couldn't store events");
                }
            }
            Err(error) => tracing::warn!(author, %error, "resync failed"),
        }
        self.rebuild(author, true, true).await;
    }

    /// Rebuild each of `author`'s repositories whose events changed, and
    /// stop serving any that no longer has any. `online`, assets the
    /// releases list but the database lacks are fetched first, and package
    /// files not seen before are downloaded. `retry`, a repository missing a
    /// file it couldn't download is rebuilt even if nothing changed.
    async fn rebuild(&self, author: &str, online: bool, retry: bool) {
        let mut events = match self.db.events(author).await {
            Ok(events) => events,
            Err(error) => {
                tracing::warn!(author, ?error, "couldn't read stored events");
                return;
            }
        };
        // A deleted asset is stored, so it isn't fetched again.
        if online && self.fetch_assets(author, &events).await {
            match self.db.events(author).await {
                Ok(fresh) => events = fresh,
                Err(error) => tracing::warn!(author, ?error, "couldn't read stored events"),
            }
        }
        let events = nip82::standing(events);

        let applications = nip82::applications(&events, author);
        for d in &applications {
            let snapshot = nip82::snapshot(&events, author, d);
            if let Lookup::Found(repo) = self.repos.get(author, d)
                && repo.snapshot == snapshot
                && !(retry && repo.incomplete)
            {
                continue;
            }
            match self.repos.build(author, d, &snapshot, !online).await {
                Ok(repo) => self.repos.publish(repo),
                Err(error) => tracing::warn!(author, d, ?error, "build failed"),
            }
        }
        self.repos.retain(|pubkey, d| pubkey != author || applications.contains(d));
    }

    /// Fetch the asset events `author`'s releases list that aren't stored,
    /// and say whether any turned up.
    async fn fetch_assets(&self, author: &str, events: &[Event]) -> bool {
        let missing = nip82::missing_assets(events, author);
        let mut found = false;
        for ids in missing.chunks(IDS_PER_FILTER) {
            let filter = json!({"ids": ids, "kinds": [nip82::ASSET], "authors": [author]});
            match relay::query(&self.relays, &[filter], QUERY_TIMEOUT).await {
                Ok(events) => {
                    let events = events
                        .into_iter()
                        .filter(|event| event.pubkey == author && event.kind == nip82::ASSET && not_future(event))
                        .collect();
                    match self.db.store_events(events).await {
                        Ok(stored) => found |= stored > 0,
                        Err(error) => tracing::warn!(author, ?error, "couldn't store events"),
                    }
                }
                Err(error) => {
                    tracing::warn!(author, %error, "couldn't fetch assets");
                    break;
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_events_dated_ahead() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let at = |created_at| Event::sign(secret, created_at, nip82::RELEASE, Vec::new(), "");
        assert!(not_future(&at(0)));
        assert!(not_future(&at(now + 60)));
        assert!(!not_future(&at(now + 3600)));
        assert!(!not_future(&at(i64::MAX)));
    }
}

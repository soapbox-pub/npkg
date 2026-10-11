//! SQLite: what each package file was found to be, which file each package
//! version is pinned to, the key each NIP-05 address last named, and what
//! relays last said about each application. With those, a repository is
//! rebuilt after a restart without the network.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};

use crate::inspect::{Format, Meta};
use crate::nip82::Snapshot;

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

/// A package file, inspected. Keyed by its sha256, so it never goes stale.
#[derive(Clone, Debug)]
pub struct Inspected {
    pub size: u64,
    /// Where the file was found, and where downloads are sent.
    pub url: String,
    /// What it is, or why it isn't a package this gateway can serve.
    pub meta: Result<Meta, String>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        let conn = Connection::open(path).with_context(|| format!("Couldn't open the database at {}.", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS packages (
               sha256 TEXT PRIMARY KEY,
               size INTEGER NOT NULL,
               url TEXT NOT NULL,
               meta TEXT,
               error TEXT
             );
             CREATE TABLE IF NOT EXISTS pins (
               pubkey TEXT NOT NULL,
               d TEXT NOT NULL,
               format TEXT NOT NULL,
               package TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               pinned_at INTEGER NOT NULL DEFAULT (unixepoch()),
               PRIMARY KEY (pubkey, d, format, package)
             );
             CREATE TABLE IF NOT EXISTS nip05 (
               name TEXT NOT NULL,
               domain TEXT NOT NULL,
               pubkey TEXT NOT NULL,
               resolved_at INTEGER NOT NULL,
               PRIMARY KEY (name, domain)
             );
             CREATE TABLE IF NOT EXISTS snapshots (
               pubkey TEXT NOT NULL,
               d TEXT NOT NULL,
               fetched_at INTEGER NOT NULL,
               snapshot TEXT NOT NULL,
               PRIMARY KEY (pubkey, d)
             );",
        )?;
        Ok(Db { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Run `f` on the blocking pool, off the runtime's threads.
    async fn call<T: Send + 'static>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static) -> anyhow::Result<T> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&conn)
        })
        .await?
        .map_err(Into::into)
    }

    pub async fn inspected(&self, sha256: &str) -> anyhow::Result<Option<Inspected>> {
        let sha256 = sha256.to_string();
        let row = self
            .call(move |conn| {
                conn.query_row("SELECT size, url, meta, error FROM packages WHERE sha256 = ?", [sha256], |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .optional()
            })
            .await?;
        Ok(row.map(|(size, url, meta, error)| {
            let meta = match (meta, error) {
                (Some(meta), _) => serde_json::from_str(&meta).map_err(|error| format!("Stored metadata is unreadable: {error}")),
                (None, error) => Err(error.unwrap_or_default()),
            };
            Inspected { size, url, meta }
        }))
    }

    pub async fn store_inspected(&self, sha256: &str, inspected: &Inspected) -> anyhow::Result<()> {
        let (meta, error) = match &inspected.meta {
            Ok(meta) => (Some(serde_json::to_string(meta)?), None),
            Err(error) => (None, Some(error.clone())),
        };
        let (sha256, size, url) = (sha256.to_string(), inspected.size as i64, inspected.url.clone());
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO packages (sha256, size, url, meta, error) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (sha256) DO NOTHING",
                params![sha256, size, url, meta, error],
            )
        })
        .await?;
        Ok(())
    }

    /// Pin `sha256` as the file for `package` (its name, version and
    /// architecture) in this repository, unless one already is. Returns the
    /// file that is.
    pub async fn pin(&self, pubkey: &str, d: &str, format: Format, package: &str, sha256: &str) -> anyhow::Result<String> {
        let args = [pubkey, d, format.as_str(), package, sha256].map(str::to_string);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO pins (pubkey, d, format, package, sha256) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT DO NOTHING",
                params![args[0], args[1], args[2], args[3], args[4]],
            )?;
            conn.query_row(
                "SELECT sha256 FROM pins WHERE pubkey = ? AND d = ? AND format = ? AND package = ?",
                params![args[0], args[1], args[2], args[3]],
                |row| row.get(0),
            )
        })
        .await
    }

    /// The key `name@domain` last resolved to, and how long ago.
    pub async fn nip05(&self, name: &str, domain: &str) -> anyhow::Result<Option<(String, Duration)>> {
        let (name, domain) = (name.to_string(), domain.to_string());
        let row = self
            .call(move |conn| {
                conn.query_row("SELECT pubkey, resolved_at FROM nip05 WHERE name = ? AND domain = ?", [name, domain], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .optional()
            })
            .await?;
        Ok(row.map(|(pubkey, resolved_at)| (pubkey, age(resolved_at))))
    }

    pub async fn store_nip05(&self, name: &str, domain: &str, pubkey: &str) -> anyhow::Result<()> {
        let args = [name, domain, pubkey].map(str::to_string);
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO nip05 (name, domain, pubkey, resolved_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT (name, domain) DO UPDATE SET pubkey = excluded.pubkey, resolved_at = excluded.resolved_at",
                params![args[0], args[1], args[2], unix_now()],
            )
        })
        .await?;
        Ok(())
    }

    pub async fn forget_nip05(&self, name: &str, domain: &str) -> anyhow::Result<()> {
        let (name, domain) = (name.to_string(), domain.to_string());
        self.call(move |conn| conn.execute("DELETE FROM nip05 WHERE name = ? AND domain = ?", [name, domain])).await?;
        Ok(())
    }

    /// What relays last said about `pubkey`'s application `d`, and how long
    /// ago. One stored by an older gateway that no longer reads is an error.
    pub async fn snapshot(&self, pubkey: &str, d: &str) -> anyhow::Result<Option<(Snapshot, Duration)>> {
        let (pubkey, d) = (pubkey.to_string(), d.to_string());
        let row = self
            .call(move |conn| {
                conn.query_row("SELECT snapshot, fetched_at FROM snapshots WHERE pubkey = ? AND d = ?", [pubkey, d], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .optional()
            })
            .await?;
        row.map(|(snapshot, fetched_at)| Ok((serde_json::from_str(&snapshot)?, age(fetched_at)))).transpose()
    }

    pub async fn store_snapshot(&self, pubkey: &str, d: &str, snapshot: &Snapshot) -> anyhow::Result<()> {
        let args = [pubkey.to_string(), d.to_string(), serde_json::to_string(snapshot)?];
        self.call(move |conn| {
            conn.execute(
                "INSERT INTO snapshots (pubkey, d, fetched_at, snapshot) VALUES (?, ?, ?, ?)
                 ON CONFLICT (pubkey, d) DO UPDATE SET fetched_at = excluded.fetched_at, snapshot = excluded.snapshot",
                params![args[0], args[1], unix_now(), args[2]],
            )
        })
        .await?;
        Ok(())
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)
}

/// How long ago a stored Unix time was.
fn age(then: i64) -> Duration {
    Duration::from_secs(unix_now().saturating_sub(then).max(0) as u64)
}

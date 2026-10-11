//! The configuration file: TOML, from the path `--config` names, or else the
//! first of `$XDG_CONFIG_HOME/npkg-gateway/npkg-gateway.toml`
//! (`~/.config/...`) and [`SYSTEM_PATH`] that exists. A file `--config` names
//! has to exist, since naming it meant something.
//!
//! `npkg-gateway.example.toml` lists every key with its default. Only
//! `public_url` and `authors` are required.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::nostr::nip19;

/// Where a packaged gateway's configuration is.
pub const SYSTEM_PATH: &str = "/etc/npkg-gateway/npkg-gateway.toml";
/// `data_dir` when the file doesn't say, for root.
const SYSTEM_DATA_DIR: &str = "/var/lib/npkg-gateway";

const DEFAULT_RELAYS: [&str; 5] =
    ["wss://relay.ditto.pub", "wss://relay.primal.net", "wss://relay.ngit.dev", "wss://relay.damus.io", "wss://nos.lol"];
const DEFAULT_BLOSSOM_SERVERS: [&str; 2] = ["https://blossom.ditto.pub", "https://blossom.primal.net"];

/// The file, resolved and validated.
#[derive(Clone, Debug)]
pub struct Config {
    /// The file it was read from.
    pub source: PathBuf,
    pub bind: SocketAddr,
    /// The URL users reach the gateway at, for the setup files. No trailing
    /// slash.
    pub public_url: String,
    /// Directory holding the database, the signing key, and the OSTree store.
    pub data_dir: PathBuf,
    /// Relays to look for NIP-82 events on.
    pub relays: Vec<String>,
    /// Blossom servers to look for package files on, when the URL an asset
    /// names doesn't serve it.
    pub blossom_servers: Vec<String>,
    /// How often everything is fetched from relays again, in case the live
    /// subscription missed something.
    pub resync_interval: Duration,
    /// What to log, as `tracing_subscriber`'s `EnvFilter` directives.
    pub log: String,
    /// The hex pubkeys whose applications are followed and served.
    pub authors: HashSet<String>,
}

/// The file as written. Every key is optional but `public_url` and
/// `authors`, and a key the gateway doesn't know is refused rather than
/// ignored, since it's a typo.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    bind: Option<String>,
    public_url: Option<String>,
    data_dir: Option<PathBuf>,
    relays: Option<Vec<String>>,
    blossom_servers: Option<Vec<String>>,
    resync_interval: Option<u64>,
    log: Option<String>,
    authors: Option<Vec<String>>,
}

/// What the defaults depend on, read once so that tests can supply their own.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    pub root: bool,
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
}

impl Environment {
    pub fn current() -> Environment {
        // The XDG spec has relative values ignored, and an empty one is unset.
        let absolute = |name: &str| std::env::var_os(name).map(PathBuf::from).filter(|path| path.is_absolute());
        Environment {
            // SAFETY: geteuid has no preconditions and cannot fail.
            root: unsafe { libc::geteuid() } == 0,
            home: absolute("HOME"),
            xdg_config_home: absolute("XDG_CONFIG_HOME"),
            xdg_data_home: absolute("XDG_DATA_HOME"),
        }
    }

    /// The files looked for when `--config` names none, in the order tried.
    pub fn config_candidates(&self) -> Vec<PathBuf> {
        let user = self.xdg_config_home.clone().or_else(|| self.home.as_ref().map(|home| home.join(".config")));
        user.map(|dir| dir.join("npkg-gateway/npkg-gateway.toml")).into_iter().chain([PathBuf::from(SYSTEM_PATH)]).collect()
    }

    fn default_data_dir(&self) -> Result<PathBuf> {
        if self.root {
            return Ok(PathBuf::from(SYSTEM_DATA_DIR));
        }
        match self.xdg_data_home.clone().or_else(|| self.home.as_ref().map(|home| home.join(".local/share"))) {
            Some(dir) => Ok(dir.join("npkg-gateway")),
            None => bail!("Neither HOME nor XDG_DATA_HOME is set, so there is no default place to keep data. Set data_dir."),
        }
    }
}

impl Config {
    /// Read the file `path` names, or else the first of the candidates that
    /// exists.
    pub fn load(path: Option<&Path>, env: &Environment) -> Result<Self> {
        let source = match path {
            Some(path) => path.to_path_buf(),
            // One this user can't look into is there all the same: reading
            // it says so, where skipping it would quietly find another.
            None => env
                .config_candidates()
                .into_iter()
                .find(|candidate| match candidate.metadata() {
                    Ok(metadata) => metadata.is_file(),
                    Err(error) => error.kind() == std::io::ErrorKind::PermissionDenied,
                })
                .ok_or_else(|| not_found(env))?,
        };
        let text =
            std::fs::read_to_string(&source).map_err(|error| anyhow!("Could not read the config file {}: {error}.", source.display()))?;
        let file: File = toml::from_str(&text).with_context(|| format!("{} is not a valid config file", source.display()))?;
        Self::from_file(file, source.clone(), env).with_context(|| format!("In {}", source.display()))
    }

    fn from_file(file: File, source: PathBuf, env: &Environment) -> Result<Self> {
        let bind = match file.bind {
            None => SocketAddr::from(([127, 0, 0, 1], 8080)),
            Some(value) => match value.trim().parse() {
                Ok(bind) => bind,
                Err(_) => bail!("bind must be an IP address and port, eg \"127.0.0.1:8080\"."),
            },
        };

        let public_url = file.public_url.unwrap_or_default().trim().trim_end_matches('/').to_string();
        if public_url.is_empty() {
            bail!("public_url must be set, eg public_url = \"https://pkg.example.com\".");
        }
        if !public_url.starts_with("http://") && !public_url.starts_with("https://") {
            bail!("public_url must be an http or https URL, eg \"https://pkg.example.com\".");
        }

        let relays = file.relays.unwrap_or_else(|| DEFAULT_RELAYS.map(String::from).into());
        if relays.is_empty() {
            bail!("relays must list at least one relay, or be left out for the defaults.");
        }
        if let Some(relay) = relays.iter().find(|relay| !relay.starts_with("ws://") && !relay.starts_with("wss://")) {
            bail!("relays must be ws:// or wss:// URLs, and {relay:?} is not.");
        }

        let blossom_servers = file.blossom_servers.unwrap_or_else(|| DEFAULT_BLOSSOM_SERVERS.map(String::from).into());
        if let Some(server) = blossom_servers.iter().find(|server| !server.starts_with("http://") && !server.starts_with("https://")) {
            bail!("blossom_servers must be http or https URLs, and {server:?} is not.");
        }

        let resync_interval = match file.resync_interval {
            Some(seconds) if seconds < 60 => bail!("resync_interval must be at least 60 seconds."),
            seconds => Duration::from_secs(seconds.unwrap_or(3600)),
        };

        let data_dir = match file.data_dir {
            // Against the file, so the setting means one place however the
            // gateway was started.
            Some(dir) => absolute(&source.parent().unwrap_or(Path::new("")).join(dir)),
            None => env.default_data_dir()?,
        };

        let log = file.log.unwrap_or_else(|| "info".into());

        // Keys only: a NIP-05 address here would hand the list to whoever
        // controls the domain, and its lookup could fail at startup.
        let authors = file.authors.unwrap_or_default();
        if authors.is_empty() {
            bail!("authors must list the npubs whose applications the gateway serves, eg authors = [\"npub1...\"].");
        }
        let authors = authors
            .iter()
            .map(|author| {
                let author = author.trim();
                match nip19::decode(author) {
                    Ok(nip19::Decoded::Npub(pubkey)) => Ok(pubkey),
                    _ if author.len() == 64 && author.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(author.to_ascii_lowercase()),
                    _ => bail!("authors must be npubs or hex public keys, and {author:?} is neither."),
                }
            })
            .collect::<Result<HashSet<_>>>()?;

        Ok(Self { source, bind, public_url, data_dir, relays, blossom_servers, resync_interval, log, authors })
    }

    /// Path of the SQLite database file.
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("npkg-gateway.sqlite")
    }

    /// Directory of the OSTree object store Flatpak remotes are served from.
    pub fn ostree_path(&self) -> PathBuf {
        self.data_dir.join("ostree")
    }

    /// Path of the gateway's OpenPGP signing key.
    pub fn key_path(&self) -> PathBuf {
        self.data_dir.join("signing-key.asc")
    }
}

fn not_found(env: &Environment) -> anyhow::Error {
    let tried: Vec<String> = env.config_candidates().iter().map(|path| path.display().to_string()).collect();
    anyhow!(
        "No config file at {}. Write one with public_url and authors set (npkg-gateway.example.toml lists every setting), or name one with --config.",
        tried.join(" or ")
    )
}

/// `path` made absolute, lexically: it needn't exist yet.
fn absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(path) };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Environment {
        Environment { root: false, home: Some("/home/someone".into()), ..Default::default() }
    }

    const NPUB: &str = "npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj";
    const HEX: &str = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5";

    /// `text`, with an author added unless it names some.
    fn config(text: &str) -> Result<Config> {
        let text = if text.contains("authors") { text.to_string() } else { format!("authors = [\"{NPUB}\"]\n{text}") };
        let file: File = toml::from_str(&text)?;
        Config::from_file(file, SYSTEM_PATH.into(), &env())
    }

    #[test]
    fn defaults() {
        let c = config(r#"public_url = "https://pkg.example.com/""#).unwrap();
        assert_eq!(c.public_url, "https://pkg.example.com");
        assert_eq!(c.bind.to_string(), "127.0.0.1:8080");
        assert_eq!(c.data_dir, Path::new("/home/someone/.local/share/npkg-gateway"));
        assert_eq!(c.relays, DEFAULT_RELAYS);
        assert_eq!(c.blossom_servers, DEFAULT_BLOSSOM_SERVERS);
        assert_eq!(c.resync_interval, Duration::from_secs(3600));
        assert_eq!(c.log, "info");
    }

    #[test]
    fn authors_are_npubs_or_hex() {
        let c = config(&format!("public_url = \"http://x\"\nauthors = [\"{NPUB}\", \"{}\"]", HEX.to_uppercase())).unwrap();
        assert_eq!(c.authors, HashSet::from([HEX.to_string()]));
        assert!(config("public_url = \"http://x\"\nauthors = []").is_err());
        let file: File = toml::from_str("public_url = \"http://x\"").unwrap();
        assert!(Config::from_file(file, SYSTEM_PATH.into(), &env()).is_err());
        assert!(config("public_url = \"http://x\"\nauthors = [\"soapbox.pub\"]").is_err());
        assert!(config("public_url = \"http://x\"\nauthors = [\"npub1\"]").is_err());
    }

    #[test]
    fn data_dir_is_relative_to_the_file() {
        let c = config("public_url = \"http://x\"\ndata_dir = \"data\"").unwrap();
        assert_eq!(c.data_dir, Path::new("/etc/npkg-gateway/data"));
        assert_eq!(c.database_path(), Path::new("/etc/npkg-gateway/data/npkg-gateway.sqlite"));
        let root = Environment { root: true, ..env() };
        let file: File = toml::from_str(&format!("public_url = \"http://x\"\nauthors = [\"{NPUB}\"]")).unwrap();
        assert_eq!(Config::from_file(file, "/x/npkg-gateway.toml".into(), &root).unwrap().data_dir, Path::new(SYSTEM_DATA_DIR));
    }

    #[test]
    fn refuses_mistakes() {
        assert!(config("").is_err());
        assert!(config("public_url = \"\"").is_err());
        assert!(config("public_url = \"pkg.example.com\"").is_err());
        assert!(config("public_url = \"http://x\"\nbind = \"localhost:8080\"").is_err());
        assert!(config("public_url = \"http://x\"\nbind = \"127.0.0.1\"").is_err());
        assert!(config("public_url = \"http://x\"\nrelays = []").is_err());
        assert!(config("public_url = \"http://x\"\nrelays = [\"relay.ditto.pub\"]").is_err());
        assert!(config("public_url = \"http://x\"\nblossom_servers = [\"blossom.ditto.pub\"]").is_err());
        assert!(config("public_url = \"http://x\"\nresync_interval = 10").is_err());
        assert!(config("public_url = \"http://x\"\nresync_interval = \"3600\"").is_err());
        assert!(config("public_url = \"http://x\"\nttl = 300").is_err());
        // Unknown keys, and the old flags' names.
        assert!(config("public_url = \"http://x\"\nblossom = []").is_err());
        assert!(config("public_url = \"http://x\"\nlisten = \"127.0.0.1:8080\"").is_err());
    }

    #[test]
    fn an_empty_blossom_list_is_allowed() {
        assert!(config("public_url = \"http://x\"\nblossom_servers = []").unwrap().blossom_servers.is_empty());
    }

    #[test]
    fn the_example_is_valid() {
        let c = config(include_str!("../npkg-gateway.example.toml")).unwrap();
        assert_eq!(c.public_url, "https://pkg.example.com");
    }

    #[test]
    fn finds_the_user_config_first() {
        let dir = tempfile::tempdir().unwrap();
        let env = Environment { xdg_config_home: Some(dir.path().into()), ..env() };
        assert_eq!(env.config_candidates(), [dir.path().join("npkg-gateway/npkg-gateway.toml"), PathBuf::from(SYSTEM_PATH)]);

        std::fs::create_dir(dir.path().join("npkg-gateway")).unwrap();
        std::fs::write(
            dir.path().join("npkg-gateway/npkg-gateway.toml"),
            format!("public_url = \"http://mine\"\ndata_dir = \"d\"\nauthors = [\"{NPUB}\"]"),
        )
        .unwrap();
        let c = Config::load(None, &env).unwrap();
        assert_eq!(c.public_url, "http://mine");
        assert_eq!(c.data_dir, dir.path().join("npkg-gateway/d"));
    }

    #[test]
    fn a_named_file_has_to_exist() {
        let dir = tempfile::tempdir().unwrap();
        let error = Config::load(Some(&dir.path().join("missing.toml")), &env()).unwrap_err();
        assert!(error.to_string().starts_with("Could not read the config file"), "{error}");
    }
}

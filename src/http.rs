//! The routes. Every repository is addressed by its format first, then its
//! application's author and `d` tag: `/apt/<owner>/<d>`, `/rpm/<owner>/<d>`.
//! The owner is an npub or a NIP-05 address (`alex@gleasonator.com`, or
//! `soapbox.pub` for `_@soapbox.pub`). The URLs a repository hands out keep
//! the form they were asked for by, so a NIP-05 repository follows its name
//! to whatever key the domain gives it.

// Handlers return early with a response from helpers; boxing it would only
// add noise to every call.
#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use crate::inspect::Format;
use crate::nostr::nip05::{self, Address, Resolver};
use crate::nostr::nip19;
use crate::repo::{BuildError, CHANNELS, Repo, Repos, channel_rank};

pub struct AppState {
    pub repos: Arc<Repos>,
    pub names: Resolver,
    /// Where the gateway is reached, for the setup files: no trailing slash.
    pub public_url: String,
    /// The hex pubkeys whose repositories are served, or `None` for anyone's.
    pub authors: Option<HashSet<String>>,
}

type Shared = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/key.asc", get(key))
        .route("/apt/{owner}/{d}", get(status))
        .route("/apt/{owner}/{d}/source", get(apt_source))
        .route("/apt/{owner}/{d}/dists/{suite}/{*path}", get(apt_dists))
        .route("/apt/{owner}/{d}/pool/{sha256}/{file}", get(apt_pool))
        .route("/rpm/{owner}/{d}", get(status))
        .route("/rpm/{owner}/{d}/repo", get(rpm_repo))
        .route("/rpm/{owner}/{d}/{channel}/repodata/{file}", get(rpm_repodata))
        .route("/rpm/{owner}/{d}/{channel}/packages/{sha256}/{file}", get(rpm_package))
        .with_state(state)
}

/// An error a person reads: plain text, a sentence.
fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], message.into() + "\n").into_response()
}

fn text(content_type: &'static str, body: impl Into<Vec<u8>>) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=60")], body.into()).into_response()
}

/// The hex pubkey an npub or a NIP-05 address names, and the owner as the
/// URLs this gateway hands out give it.
async fn owner(state: &AppState, value: &str) -> Result<(String, String), Response> {
    if let Ok(nip19::Decoded::Npub(pubkey)) = nip19::decode(value) {
        let npub = nip19::npub_encode(&pubkey);
        return Ok((pubkey, npub));
    }
    let Some(address) = Address::parse(value) else {
        return Err(error(
            StatusCode::NOT_FOUND,
            format!("{value:?} isn't an npub or a NIP-05 address like alex@gleasonator.com or soapbox.pub."),
        ));
    };
    match state.names.resolve(&address).await {
        Ok(pubkey) => Ok((pubkey, value.to_ascii_lowercase())),
        Err(nip05::LookupError::NotFound(message)) => Err(error(StatusCode::NOT_FOUND, message)),
        Err(nip05::LookupError::Failed(message)) => Err(error(StatusCode::BAD_GATEWAY, message)),
    }
}

/// The repository at `owner`/`d`, built if it has to be, and its owner as
/// [`owner`] gives it.
async fn repo(state: &AppState, owner_value: &str, d: &str) -> Result<(Arc<Repo>, String), Response> {
    // Anything NIP-82 allows, short of what would break a path or a file.
    if d.is_empty() || d.len() > 256 || d.chars().any(|c| c.is_control() || c == '/') {
        return Err(error(StatusCode::NOT_FOUND, format!("{d:?} isn't an application id this gateway can serve.")));
    }
    let (pubkey, owner) = owner(state, owner_value).await?;
    // Checked before building, so an author nobody listed costs no relay
    // queries or downloads.
    if state.authors.as_ref().is_some_and(|authors| !authors.contains(&pubkey)) {
        return Err(error(
            StatusCode::FORBIDDEN,
            format!("This gateway only serves repositories for the authors its operator lists, and {owner} isn't one of them."),
        ));
    }
    let repo = state.repos.get(&pubkey, d).await.map_err(|failure| match failure {
        BuildError::NotFound(message) => error(StatusCode::NOT_FOUND, message),
        BuildError::Failed(message) => error(StatusCode::BAD_GATEWAY, message),
    })?;
    Ok((repo, owner))
}

async fn index(State(state): Shared) -> Response {
    text(
        "text/plain; charset=utf-8",
        format!(
            "npkg-gateway: apt and dnf repositories for software released on Nostr (NIP-82).\n\n\
             apt:  {0}/apt/<owner>/<app-id>\n\
             dnf:  {0}/rpm/<owner>/<app-id>\n\
             The owner is an npub, or a NIP-05 address: alex@gleasonator.com, or soapbox.pub for _@soapbox.pub.\n\n\
             key:  {0}/key.asc ({1})\n",
            state.public_url,
            state.repos.signer().fingerprint()
        ),
    )
}

async fn key(State(state): Shared) -> Response {
    text("application/pgp-keys", state.repos.signer().public_key().to_string())
}

/// What a repository holds, what it left out and why, and how to add it.
async fn status(State(state): Shared, Path((owner, d)): Path<(String, String)>) -> Response {
    let (repo, owner) = match repo(&state, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let base = &state.public_url;
    let file = file_stem(&repo.d);
    let mut out = format!("{} ({})\n", repo.name, repo.d);
    if let Some(summary) = &repo.summary {
        let _ = writeln!(out, "{summary}");
    }
    out.push('\n');

    let names = |format: Format| {
        let mut names: Vec<&str> =
            repo.packages.iter().filter(|package| package.meta.format() == format).map(|package| package.meta.name()).collect();
        names.sort();
        names.dedup();
        names.join(" ")
    };
    let (debs, rpms) = (names(Format::Deb), names(Format::Rpm));
    if !debs.is_empty() {
        let _ = writeln!(
            out,
            "Debian, Ubuntu:\n  sudo curl -fsSL -o /etc/apt/sources.list.d/{file}.sources {base}/apt/{owner}/{d}/source\n  sudo apt update && sudo apt install {debs}\n",
            d = segment(&repo.d)
        );
    }
    if !rpms.is_empty() {
        let _ = writeln!(
            out,
            "Fedora, RHEL:\n  sudo curl -fsSL -o /etc/yum.repos.d/{file}.repo {base}/rpm/{owner}/{d}/repo\n  sudo dnf install {rpms}\n",
            d = segment(&repo.d)
        );
    }
    let _ = writeln!(out, "Channels: {} (add ?channel=beta to either setup URL)", CHANNELS.join(", "));
    let _ = writeln!(out, "This repository serves whatever packages its author publishes, under any name.\n");

    let _ = writeln!(out, "Packages:");
    if repo.packages.is_empty() {
        let _ = writeln!(out, "  none");
    }
    let mut packages: Vec<_> = repo.packages.iter().collect();
    packages.sort_by_key(|package| (package.meta.name(), package.meta.format(), std::cmp::Reverse(package.created_at)));
    let mut previous = None;
    for package in packages {
        let name = package.meta.name();
        if previous != Some(name) {
            let _ = writeln!(out, "  {name}");
            previous = Some(name);
        }
        let _ = writeln!(
            out,
            "    {} {} {} [{}] {}",
            package.meta.version(),
            package.meta.format().as_str(),
            package.meta.arch(),
            CHANNELS[package.channel],
            package.sha256
        );
    }
    if !repo.rejections.is_empty() {
        let _ = writeln!(out, "\nLeft out:");
        for rejection in &repo.rejections {
            let _ = writeln!(out, "  {} {}: {}", rejection.release, rejection.sha256, rejection.reason);
        }
    }
    text("text/plain; charset=utf-8", out)
}

/// `d`, as one segment of a URL path.
fn segment(d: &str) -> String {
    d.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// `d`, as a file name apt and dnf read: they skip files with other
/// characters in their names.
fn file_stem(d: &str) -> String {
    d.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect()
}

/// The channel a setup file is for: `?channel=`, or the stable one.
fn setup_channel(query: &HashMap<String, String>) -> Result<&str, Response> {
    let channel = query.get("channel").map_or(CHANNELS[0], String::as_str);
    if channel_rank(channel).is_none() {
        return Err(error(StatusCode::BAD_REQUEST, format!("There's no channel {channel:?}. The channels are {}.", CHANNELS.join(", "))));
    }
    Ok(channel)
}

/// A deb822 `.sources` file, with the gateway's key in it, so that adding the
/// repository is one download.
async fn apt_source(
    State(state): Shared,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let (repo, owner) = match repo(&state, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let channel = match setup_channel(&query) {
        Ok(channel) => channel,
        Err(response) => return response,
    };
    let key: String = state
        .repos
        .signer()
        .public_key()
        .lines()
        .map(|line| if line.trim().is_empty() { " .\n".to_string() } else { format!(" {line}\n") })
        .collect();
    text(
        "text/plain; charset=utf-8",
        format!(
            "# {}, from npkg-gateway\nTypes: deb\nURIs: {}/apt/{}/{}\nSuites: {channel}\nComponents: main\nSigned-By:\n{key}",
            repo.name,
            state.public_url,
            owner,
            segment(&repo.d)
        ),
    )
}

async fn apt_dists(State(state): Shared, Path((owner, d, suite, path)): Path<(String, String, String, String)>) -> Response {
    let (repo, _) = match repo(&state, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Some(body) = repo.apt_file(&suite, &path) else {
        return error(StatusCode::NOT_FOUND, "There's no such file.");
    };
    let content_type = if path.ends_with(".gz") { "application/gzip" } else { "text/plain; charset=utf-8" };
    text(content_type, body.to_vec())
}

async fn apt_pool(State(state): Shared, Path((owner, d, sha256, _file)): Path<(String, String, String, String)>) -> Response {
    download(&state, &owner, &d, Format::Deb, &sha256).await
}

/// A `.repo` file for `/etc/yum.repos.d/`. Packages themselves aren't
/// signed by anyone dnf knows; the repodata that names their hashes is.
async fn rpm_repo(
    State(state): Shared,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let (repo, owner) = match repo(&state, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let channel = match setup_channel(&query) {
        Ok(channel) => channel,
        Err(response) => return response,
    };
    // The same ID on every channel, and the same as the file it's saved as:
    // switching channel replaces the repository rather than adding one.
    text(
        "text/plain; charset=utf-8",
        format!(
            "[{id}]\nname={name} ({channel}, from npkg-gateway)\nbaseurl={base}/rpm/{owner}/{d}/{channel}\nenabled=1\nrepo_gpgcheck=1\ngpgcheck=0\ngpgkey={base}/key.asc\n",
            id = file_stem(&repo.d),
            d = segment(&repo.d),
            name = repo.name.replace('\n', " "),
            base = state.public_url,
        ),
    )
}

async fn rpm_repodata(State(state): Shared, Path((owner, d, channel, file)): Path<(String, String, String, String)>) -> Response {
    let Some(rank) = channel_rank(&channel) else {
        return error(StatusCode::NOT_FOUND, format!("There's no channel {channel:?}."));
    };
    let (repo, _) = match repo(&state, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Some(body) = repo.rpm_file(rank, &format!("repodata/{file}")) else {
        return error(StatusCode::NOT_FOUND, "There's no such file.");
    };
    let content_type = match file.rsplit('.').next() {
        Some("gz") => "application/gzip",
        Some("asc") => "application/pgp-signature",
        _ => "application/xml",
    };
    text(content_type, body.to_vec())
}

async fn rpm_package(
    State(state): Shared,
    Path((owner, d, channel, sha256, _file)): Path<(String, String, String, String, String)>,
) -> Response {
    if channel_rank(&channel).is_none() {
        return error(StatusCode::NOT_FOUND, format!("There's no channel {channel:?}."));
    }
    download(&state, &owner, &d, Format::Rpm, &sha256).await
}

/// A redirect to the package file on Blossom. apt and dnf check the file
/// against the hash in the signed index, so where it's served from needn't
/// be trusted.
async fn download(state: &AppState, owner: &str, d: &str, format: Format, sha256: &str) -> Response {
    let (repo, _) = match repo(state, owner, d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    match repo.download_url(format, sha256) {
        Some(url) => Redirect::to(url).into_response(),
        None => error(StatusCode::NOT_FOUND, "This repository has no such package."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_ids_safe() {
        assert_eq!(segment("buzz.armada.app"), "buzz.armada.app");
        assert_eq!(segment("My App/x"), "My%20App%2Fx");
        assert_eq!(file_stem("My App"), "My_App");
    }
}

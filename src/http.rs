//! The routes. Every repository is addressed by its format first, then its
//! application's author and `d` tag: `/apt/<owner>/<d>`, `/rpm/<owner>/<d>`,
//! `/flatpak/<owner>/<d>`, `/fdroid/<owner>/<d>`.
//! The owner is an npub or a NIP-05 address (`alex@gleasonator.com`, or
//! `soapbox.pub` for `_@soapbox.pub`). The URLs a repository hands out keep
//! the form they were asked for by, so a NIP-05 repository follows its name
//! to whatever key the domain gives it.

// Handlers return early with a response from helpers; boxing it would only
// add noise to every call.
#![allow(clippy::result_large_err)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use base64::Engine;
use serde_json::{Value, json};

use crate::inspect::Format;
use crate::nostr::nip05::{self, Address, Resolver};
use crate::nostr::nip19;
use crate::ostree;
use crate::pages::{self, Kind};
use crate::repo::{CHANNELS, FlatpakChannel, Lookup, Release, Repo, Repos, channel_rank};
use crate::{apt, nip82};

pub struct AppState {
    pub repos: Arc<Repos>,
    pub names: Arc<Resolver>,
    /// Where the gateway is reached, for the setup files: no trailing slash.
    pub public_url: String,
    /// The hex pubkeys whose repositories are served.
    pub authors: HashSet<String>,
}

type Shared = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/key.asc", get(key))
        .route("/assets/{file}", get(asset))
        .route("/icon/{owner}/{d}/{file}", get(icon))
        .route("/og/{file}", get(site_card))
        .route("/og/{owner}/{d}/{file}", get(repo_card))
        .route("/apt/{owner}/{d}", get(apt_page))
        .route("/apt/{owner}/{d}/source", get(apt_source))
        .route("/apt/{owner}/{d}/dists/{suite}/{*path}", get(apt_dists))
        .route("/apt/{owner}/{d}/pool/{sha256}/{file}", get(apt_pool))
        .route("/rpm/{owner}/{d}", get(rpm_page))
        .route("/rpm/{owner}/{d}/repo", get(rpm_repo))
        .route("/rpm/{owner}/{d}/{channel}/repodata/{file}", get(rpm_repodata))
        .route("/rpm/{owner}/{d}/{channel}/packages/{sha256}/{file}", get(rpm_package))
        .route("/flatpak/{owner}/{d}", get(flatpak_page))
        .route("/flatpak/{owner}/{d}/{file}", get(flatpak_setup))
        .route("/flatpak/{owner}/{d}/{channel}/{file}", get(flatpak_top))
        .route("/flatpak/{owner}/{d}/{channel}/objects/{prefix}/{file}", get(flatpak_object))
        .route("/fdroid/{owner}/{d}", get(fdroid_page))
        .route("/fdroid/{owner}/{d}/repo", get(fdroid_page))
        .route("/fdroid/{owner}/{d}/repo/{file}", get(fdroid_file))
        .route("/fdroid/{owner}/{d}/repo/{sha256}/{file}", get(fdroid_apk))
        .route("/releases/{owner}/{d}", get(releases))
        .route("/releases/{owner}/{d}/latest", get(latest_release))
        .route("/releases/{owner}/{d}/latest/download/{name}", get(latest_download))
        .route("/releases/{owner}/{d}/tags/{version}", get(tagged_release))
        .route("/releases/{owner}/{d}/download/{version}/{name}", get(tagged_download))
        .layer(axum::middleware::map_response(nosniff))
        .with_state(state)
}

/// Every response is what its content type says: a browser shouldn't guess
/// that an author's text, say, is HTML.
async fn nosniff(mut response: Response) -> Response {
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    response
}

/// An error a person reads: plain text, a sentence.
fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], message.into() + "\n").into_response()
}

fn text(content_type: &'static str, body: impl Into<Vec<u8>>) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=60")], body.into()).into_response()
}

fn json(value: &Value) -> Response {
    text("application/json", serde_json::to_string_pretty(value).unwrap_or_default() + "\n")
}

/// The address of whoever made a request, for the limits on what a request
/// can make the gateway do. The socket's peer, unless that's a reverse proxy
/// on this machine: then the address the proxy added to `X-Forwarded-For`,
/// last, since a client can write the ones before it. `X-Real-IP` isn't
/// read: behind a proxy that only sets that, a client could write its own
/// `X-Forwarded-For`.
///
/// An IPv6 client is its /64, which is what one host is usually given:
/// counted address by address, it could make itself billions of clients.
pub struct Client(IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for Client {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Client, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map_or(IpAddr::from([0, 0, 0, 0]), |info| info.0.ip());
        if !peer.is_loopback() {
            return Ok(Client(network(peer)));
        }
        let forwarded = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
            .and_then(|ip| ip.trim().parse().ok());
        Ok(Client(network(forwarded.unwrap_or(peer))))
    }
}

/// The network a client is counted by: an IPv4 address, or an IPv6 /64.
fn network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        },
        v4 => v4,
    }
}

/// The hex pubkey an npub or a NIP-05 address names, and the owner as the
/// URLs this gateway hands out give it.
async fn owner(state: &AppState, client: IpAddr, value: &str) -> Result<(String, String), Response> {
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
    match state.names.resolve(&address, client).await {
        Ok(pubkey) => Ok((pubkey, value.to_ascii_lowercase())),
        Err(nip05::LookupError::NotFound(message)) => Err(error(StatusCode::NOT_FOUND, message)),
        Err(nip05::LookupError::Failed(message)) => Err(error(StatusCode::BAD_GATEWAY, message)),
        Err(nip05::LookupError::Limited(message)) => Err(error(StatusCode::TOO_MANY_REQUESTS, message)),
    }
}

/// The repository at `owner`/`d`, and its owner as [`owner`] gives it.
async fn repo(state: &AppState, client: IpAddr, owner_value: &str, d: &str) -> Result<(Arc<Repo>, String), Response> {
    if !nip82::valid_d(d) {
        return Err(error(StatusCode::NOT_FOUND, format!("{d:?} isn't an application id this gateway can serve.")));
    }
    let (pubkey, owner) = owner(state, client, owner_value).await?;
    if !state.authors.contains(&pubkey) {
        return Err(error(
            StatusCode::NOT_FOUND,
            format!(
                "This gateway only serves its team's repositories, and {owner} isn't on the team. They're listed at {}/.",
                state.public_url
            ),
        ));
    }
    match state.repos.get(&pubkey, d) {
        Lookup::Found(repo) => Ok((repo, owner)),
        Lookup::Syncing => {
            let mut response = error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The gateway has just started and is still syncing with relays. Try again in a minute.",
            );
            response.headers_mut().insert(header::RETRY_AFTER, header::HeaderValue::from_static("30"));
            Err(response)
        }
        Lookup::Missing => {
            Err(error(StatusCode::NOT_FOUND, format!("{owner} has published no NIP-82 application {d:?} that the gateway has seen.")))
        }
    }
}

async fn index(State(state): Shared) -> Response {
    let fingerprint = state.repos.signer().fingerprint();
    let site = pages::Site { base: &state.public_url, fingerprint: &fingerprint };
    html(StatusCode::OK, pages::index(&site, &state.repos.all()))
}

async fn key(State(state): Shared) -> Response {
    text("application/pgp-keys", state.repos.signer().public_key().to_string())
}

/// A page, with nothing in it the gateway didn't serve itself.
fn html(status: StatusCode, body: String) -> Response {
    let mut response =
        (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=60")], body).into_response();
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static(pages::CSP));
    response
}

/// An error made for apt or dnf, as a page: the same status and headers,
/// its sentence on a crate.
async fn html_error(state: &AppState, response: Response) -> Response {
    let (parts, body) = response.into_parts();
    let message = axum::body::to_bytes(body, 64 << 10).await.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default();
    let fingerprint = state.repos.signer().fingerprint();
    let site = pages::Site { base: &state.public_url, fingerprint: &fingerprint };
    let reason = parts.status.canonical_reason().unwrap_or("Error");
    let mut page = html(parts.status, pages::error(&site, parts.status.as_u16(), reason, &message));
    if let Some(retry) = parts.headers.get(header::RETRY_AFTER) {
        page.headers_mut().insert(header::RETRY_AFTER, retry.clone());
    }
    page.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    page
}

/// The stylesheet, script and icon the pages use.
async fn asset(Path(file): Path<String>) -> Response {
    let (content_type, body) = match file.as_str() {
        "style.css" => ("text/css; charset=utf-8", pages::STYLE),
        "app.js" => ("text/javascript; charset=utf-8", pages::SCRIPT),
        "favicon.svg" => ("image/svg+xml", pages::FAVICON),
        _ => return error(StatusCode::NOT_FOUND, "There's no such file."),
    };
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=300")], body).into_response()
}

fn jpeg(body: Vec<u8>, cache: &'static str) -> Response {
    ([(header::CONTENT_TYPE, "image/jpeg"), (header::CACHE_CONTROL, cache)], body).into_response()
}

/// The gateway's own link-preview card, drawn once.
async fn site_card(State(state): Shared, Path(file): Path<String>) -> Response {
    static CARD: tokio::sync::OnceCell<Vec<u8>> = tokio::sync::OnceCell::const_new();
    if format!("/og/{file}") != pages::SITE_CARD {
        return error(StatusCode::NOT_FOUND, "There's no such image.");
    }
    let card = CARD
        .get_or_try_init(|| {
            let base = state.public_url.clone();
            async move { tokio::task::spawn_blocking(move || pages::site_card(&base)).await? }
        })
        .await;
    match card {
        // Named by the gateway's version, which is all it changes with.
        Ok(card) => jpeg(card.clone(), "public, max-age=31536000, immutable"),
        Err(error) => self::error(StatusCode::INTERNAL_SERVER_ERROR, format!("The card couldn't be drawn: {error:#}.")),
    }
}

/// An application's link-preview card. One named by an old hash gets the
/// current card, briefly cached, so a preview made before still shows.
async fn repo_card(State(state): Shared, Client(client): Client, Path((owner, d, file)): Path<(String, String, String)>) -> Response {
    let (repo, _) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Some((hash, card)) = &repo.card else {
        return error(StatusCode::NOT_FOUND, "There's no card for this application.");
    };
    if file.strip_suffix(".jpg") == Some(hash.as_str()) {
        jpeg(card.clone(), "public, max-age=31536000, immutable")
    } else {
        jpeg(card.clone(), "public, max-age=300")
    }
}

/// An application's icon, named by its hash, as its pages show it.
async fn icon(State(state): Shared, Client(client): Client, Path((owner, d, file)): Path<(String, String, String)>) -> Response {
    match repo(&state, client, &owner, &d).await {
        Ok((repo, _)) => icon_file(&repo, &file).unwrap_or_else(|| error(StatusCode::NOT_FOUND, "There's no such icon.")),
        Err(response) => response,
    }
}

/// The application's icon, if it's called `file`.
fn icon_file(repo: &Repo, file: &str) -> Option<Response> {
    let (_, icon) = repo.icon.as_ref().filter(|(name, _)| name == file)?;
    let content_type = match icon.as_slice() {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xff, 0xd8, 0xff, ..] => "image/jpeg",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        // Not one a page shows: an SVG could carry script.
        _ => "application/octet-stream",
    };
    // Named by its hash, so it never changes.
    Some(
        ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=31536000, immutable")], icon.clone())
            .into_response(),
    )
}

async fn apt_page(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    repo_page(&state, client, &owner, &d, &query, Kind::Apt).await
}

async fn rpm_page(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    repo_page(&state, client, &owner, &d, &query, Kind::Rpm).await
}

async fn flatpak_page(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    repo_page(&state, client, &owner, &d, &query, Kind::Flatpak).await
}

async fn fdroid_page(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    repo_page(&state, client, &owner, &d, &query, Kind::Fdroid).await
}

/// What one kind of repository holds, how to add it, and what it left out.
async fn repo_page(state: &AppState, client: IpAddr, owner: &str, d: &str, query: &HashMap<String, String>, kind: Kind) -> Response {
    let (repo, owner) = match repo(state, client, owner, d).await {
        Ok(found) => found,
        Err(response) => return html_error(state, response).await,
    };
    let rank = match setup_channel(query) {
        Ok(channel) => channel_rank(channel).unwrap_or(0),
        Err(response) => return html_error(state, response).await,
    };
    let fingerprint = state.repos.signer().fingerprint();
    let site = pages::Site { base: &state.public_url, fingerprint: &fingerprint };
    html(StatusCode::OK, pages::repo(&site, &repo, &owner, kind, rank))
}

/// `d`, as one segment of a URL path.
pub fn segment(d: &str) -> String {
    d.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// `d`, as a file name apt and dnf read: they skip files with other
/// characters in their names.
pub fn file_stem(d: &str) -> String {
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
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let (repo, owner) = match repo(&state, client, &owner, &d).await {
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
            "# {}, from npkg\nTypes: deb\nURIs: {}/apt/{}/{}\nSuites: {channel}\nComponents: main\nSigned-By:\n{key}",
            repo.name,
            state.public_url,
            owner,
            segment(&repo.d)
        ),
    )
}

async fn apt_dists(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, suite, path)): Path<(String, String, String, String)>,
) -> Response {
    let (repo, _) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Some(body) = repo.apt_file(&suite, &path) else {
        return error(StatusCode::NOT_FOUND, "There's no such file.");
    };
    let content_type = if path.ends_with(".gz") { "application/gzip" } else { "text/plain; charset=utf-8" };
    text(content_type, body.to_vec())
}

async fn apt_pool(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, sha256, _file)): Path<(String, String, String, String)>,
) -> Response {
    download(&state, client, &owner, &d, Format::Deb, &sha256).await
}

/// A `.repo` file for `/etc/yum.repos.d/`. Packages themselves aren't
/// signed by anyone dnf knows; the repodata that names their hashes is.
async fn rpm_repo(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let (repo, owner) = match repo(&state, client, &owner, &d).await {
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
            "[{id}]\nname={name} ({channel}, from npkg)\nbaseurl={base}/rpm/{owner}/{d}/{channel}\nenabled=1\nrepo_gpgcheck=1\ngpgcheck=0\ngpgkey={base}/key.asc\n",
            id = file_stem(&repo.d),
            d = segment(&repo.d),
            name = repo.name,
            base = state.public_url,
        ),
    )
}

async fn rpm_repodata(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, channel, file)): Path<(String, String, String, String)>,
) -> Response {
    let Some(rank) = channel_rank(&channel) else {
        return error(StatusCode::NOT_FOUND, format!("There's no channel {channel:?}."));
    };
    let (repo, _) = match repo(&state, client, &owner, &d).await {
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
    Client(client): Client,
    Path((owner, d, channel, sha256, _file)): Path<(String, String, String, String, String)>,
) -> Response {
    if channel_rank(&channel).is_none() {
        return error(StatusCode::NOT_FOUND, format!("There's no channel {channel:?}."));
    }
    download(&state, client, &owner, &d, Format::Rpm, &sha256).await
}

/// A redirect to the package file on Blossom. apt and dnf check the file
/// against the hash in the signed index, so where it's served from needn't
/// be trusted.
async fn download(state: &AppState, client: IpAddr, owner: &str, d: &str, format: Format, sha256: &str) -> Response {
    let (repo, _) = match repo(state, client, owner, d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    match repo.package(format, sha256) {
        Some(package) => Redirect::to(&package.url).into_response(),
        None => error(StatusCode::NOT_FOUND, "This repository has no such package."),
    }
}

/// The F-Droid repository's index files, and the app's icon.
async fn fdroid_file(State(state): Shared, Client(client): Client, Path((owner, d, file)): Path<(String, String, String)>) -> Response {
    let (repo, _) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Some(fdroid) = &repo.fdroid else {
        return error(StatusCode::NOT_FOUND, format!("{} has no APK in any release.", repo.name));
    };
    if let Some(icon) = icon_file(&repo, &file) {
        return icon;
    }
    let content_type = match file.as_str() {
        "entry.jar" => "application/java-archive",
        "entry.json" | "index-v2.json" => "application/json",
        _ => return error(StatusCode::NOT_FOUND, "There's no such file."),
    };
    match fdroid.file(&file) {
        Some(body) => text(content_type, body.to_vec()),
        None => error(StatusCode::NOT_FOUND, "There's no such file."),
    }
}

/// An APK, passed on from where it's kept: F-Droid doesn't follow
/// redirects. F-Droid checks it against the hash in the signed index.
async fn fdroid_apk(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, sha256, _file)): Path<(String, String, String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
    let (repo, _) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Some(package) = repo.package(Format::Apk, &sha256) else {
        return error(StatusCode::NOT_FOUND, "This repository has no such APK.");
    };
    let range = headers.get(header::RANGE).and_then(|range| range.to_str().ok());
    match state.repos.fetch(package, range).await {
        Ok(response) => passed_on(response),
        Err(error) => self::error(StatusCode::BAD_GATEWAY, format!("Couldn't fetch the APK from any server: {error:#}. Try again later.")),
    }
}

/// An APK from upstream, streamed on.
fn passed_on(upstream: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::OK);
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/vnd.android.package-archive")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable");
    for name in [header::CONTENT_LENGTH, header::CONTENT_RANGE, header::ACCEPT_RANGES] {
        if let Some(value) = upstream.headers().get(name.as_str()).and_then(|value| header::HeaderValue::from_bytes(value.as_bytes()).ok())
        {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY, "The upstream response couldn't be passed on."))
}

/// The app a channel's `.flatpakref` installs: the one named like the
/// repository if there is one, or else the first. Its id, and its branch.
pub fn flatpak_app<'a>(repo: &Repo, channel: &'a FlatpakChannel) -> Option<&'a str> {
    let app_id = |head: &'a crate::repo::FlatpakBundle| head.bundle.ref_name.split('/').nth(1);
    channel.refs.iter().find(|head| app_id(head) == Some(repo.d.as_str())).or(channel.refs.first()).and_then(app_id)
}

/// A `.flatpakref`, which installs the app and adds its remote in one go,
/// or a `.flatpakrepo`, which only adds the remote. Both carry the gateway's
/// key, which Flatpak checks every summary and commit against.
async fn flatpak_setup(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, file)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let (repo, owner) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let channel = match setup_channel(&query) {
        Ok(channel) => channel,
        Err(response) => return response,
    };
    let rank = channel_rank(channel).unwrap_or(0);
    let Some(remote) = repo.flatpak(rank) else {
        return error(StatusCode::NOT_FOUND, format!("{} has no Flatpak bundle on the {channel} channel.", repo.name));
    };
    let url = format!("{}/flatpak/{owner}/{}/{channel}/", state.public_url, segment(&repo.d));
    let key = base64::engine::general_purpose::STANDARD.encode(state.repos.signer().public_key_binary());
    let title = &repo.name;
    // Remote names are what `flatpak remotes` lists: one per channel.
    let remote_name = if rank == 0 { file_stem(&repo.d) } else { format!("{}-{channel}", file_stem(&repo.d)) };
    if file.ends_with(".flatpakrepo") {
        return text(
            "application/vnd.flatpak.repo",
            format!("[Flatpak Repo]\nTitle={title} ({channel}, from npkg)\nUrl={url}\nGPGKey={key}\n"),
        );
    }
    if !file.ends_with(".flatpakref") {
        return error(StatusCode::NOT_FOUND, "There's no such file. Try one ending in .flatpakref or .flatpakrepo.");
    }
    let Some(head) =
        flatpak_app(&repo, remote).and_then(|app| remote.refs.iter().find(|head| head.bundle.ref_name.split('/').nth(1) == Some(app)))
    else {
        return error(StatusCode::NOT_FOUND, format!("{} has no Flatpak app on the {channel} channel.", repo.name));
    };
    let parts: Vec<&str> = head.bundle.ref_name.split('/').collect();
    let runtime_repo = head.bundle.runtime_repo.as_deref().unwrap_or(FLATHUB);
    text(
        "application/vnd.flatpak.ref",
        format!(
            "[Flatpak Ref]\nTitle={title}\nName={}\nBranch={}\nUrl={url}\nSuggestRemoteName={remote_name}\nIsRuntime=false\nGPGKey={key}\nRuntimeRepo={runtime_repo}\n",
            parts[1], parts[3]
        ),
    )
}

/// Where the runtimes apps depend on come from, unless the bundle says:
/// Flatpak adds it, if it isn't already, when it installs a `.flatpakref`
/// naming it.
const FLATHUB: &str = "https://dl.flathub.org/repo/flathub.flatpakrepo";

/// A channel's remote's `config`, `summary` and `summary.sig`.
async fn flatpak_top(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, channel, file)): Path<(String, String, String, String)>,
) -> Response {
    let Some(rank) = channel_rank(&channel) else {
        return error(StatusCode::NOT_FOUND, format!("There's no channel {channel:?}."));
    };
    let (repo, _) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    if repo.flatpak(rank).is_none() {
        return error(StatusCode::NOT_FOUND, format!("{} has no Flatpak bundle on the {channel} channel.", repo.name));
    }
    if file == "config" {
        return text("text/plain; charset=utf-8", "[core]\nrepo_version=1\nmode=archive-z2\n");
    }
    // No summary.idx: Flatpak falls back to the summary itself.
    match repo.flatpak_file(rank, &file) {
        Some(body) => text("application/octet-stream", body.to_vec()),
        None => error(StatusCode::NOT_FOUND, "There's no such file."),
    }
}

/// An object from the store, or a commit's signature. Objects are named by
/// their checksums and never change, so they're cached forever.
async fn flatpak_object(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, channel, prefix, file)): Path<(String, String, String, String, String)>,
) -> Response {
    let Some(rank) = channel_rank(&channel) else {
        return error(StatusCode::NOT_FOUND, format!("There's no channel {channel:?}."));
    };
    let (repo, _) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let not_found = || error(StatusCode::NOT_FOUND, "There's no such object.");
    let Some((rest, extension)) = file.split_once('.') else { return not_found() };
    let checksum = format!("{prefix}{rest}");
    if repo.flatpak(rank).is_none() || !ostree::is_checksum(&checksum) || prefix.len() != 2 {
        return not_found();
    }
    let immutable = |content_type: &'static str, body: Body| {
        ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=31536000, immutable")], body).into_response()
    };
    if extension == "commitmeta" {
        return match repo.commitmeta(&checksum) {
            // Signed afresh by each build, so not cached for long.
            Some(body) => text("application/octet-stream", body.to_vec()),
            None => not_found(),
        };
    }
    let Some(kind) = ostree::Kind::from_extension(extension).filter(|&kind| repo.has_object(kind, &checksum)) else {
        return not_found();
    };
    let file = match tokio::fs::File::open(state.repos.store().path(kind, &checksum)).await {
        Ok(file) => file,
        Err(_) => return not_found(),
    };
    let length = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(_) => return not_found(),
    };
    let mut response = immutable("application/octet-stream", Body::from_stream(tokio_util::io::ReaderStream::new(file)));
    response.headers_mut().insert(header::CONTENT_LENGTH, header::HeaderValue::from(length));
    response
}

/// Where a repository's releases are listed: no trailing slash.
fn releases_url(state: &AppState, owner: &str, repo: &Repo) -> String {
    format!("{}/releases/{owner}/{}", state.public_url, segment(&repo.d))
}

/// A release, shaped after GitHub's release JSON but with less in it.
fn release_json(base: &str, release: &Release) -> Value {
    let assets: Vec<Value> = release
        .assets
        .iter()
        .map(|asset| {
            json!({
                "name": asset.name(),
                "size": asset.size,
                "content_type": asset.mime,
                "sha256": asset.sha256,
                "platforms": asset.platforms,
                "download_url": format!("{base}/download/{}/{}", segment(&release.version), segment(asset.name())),
            })
        })
        .collect();
    json!({
        "version": release.version,
        "channel": CHANNELS[release.channel],
        "prerelease": release.channel > 0 || nip82::is_prerelease(&release.version),
        "published_at": apt::rfc3339(release.created_at),
        "notes": release.notes,
        "assets": assets,
    })
}

/// Every release, highest version first.
async fn releases(State(state): Shared, Client(client): Client, Path((owner, d)): Path<(String, String)>) -> Response {
    let (repo, owner) = match repo(&state, client, &owner, &d).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let base = releases_url(&state, &owner, &repo);
    json(&Value::Array(repo.releases.iter().map(|release| release_json(&base, release)).collect()))
}

/// The latest release on `?channel=`, or the stable one.
async fn latest_release(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match latest(&state, client, &owner, &d, &query).await {
        Ok((repo, owner, release)) => json(&release_json(&releases_url(&state, &owner, &repo), &release)),
        Err(response) => response,
    }
}

async fn latest_download(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, name)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    match latest(&state, client, &owner, &d, &query).await {
        Ok((repo, owner, release)) => asset_redirect(&releases_url(&state, &owner, &repo), &release, &name),
        Err(response) => response,
    }
}

async fn tagged_release(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, version)): Path<(String, String, String)>,
) -> Response {
    match tagged(&state, client, &owner, &d, &version).await {
        Ok((repo, owner, release)) => json(&release_json(&releases_url(&state, &owner, &repo), &release)),
        Err(response) => response,
    }
}

async fn tagged_download(
    State(state): Shared,
    Client(client): Client,
    Path((owner, d, version, name)): Path<(String, String, String, String)>,
) -> Response {
    match tagged(&state, client, &owner, &d, &version).await {
        Ok((repo, owner, release)) => asset_redirect(&releases_url(&state, &owner, &repo), &release, &name),
        Err(response) => response,
    }
}

/// The repository, its owner, and its latest release on `?channel=`.
async fn latest(
    state: &AppState,
    client: IpAddr,
    owner: &str,
    d: &str,
    query: &HashMap<String, String>,
) -> Result<(Arc<Repo>, String, Release), Response> {
    let channel = setup_channel(query)?;
    let (repo, owner) = repo(state, client, owner, d).await?;
    let rank = channel_rank(channel).unwrap_or(0);
    let Some(release) = repo.latest(rank) else {
        let wider = if rank + 1 < CHANNELS.len() {
            format!(" Add ?channel={} to look at less stable ones.", CHANNELS[rank + 1])
        } else {
            String::new()
        };
        return Err(error(StatusCode::NOT_FOUND, format!("{} has no release on the {channel} channel.{wider}", repo.name)));
    };
    let release = release.clone();
    Ok((repo, owner, release))
}

/// The repository, its owner, and its release `version`.
async fn tagged(state: &AppState, client: IpAddr, owner: &str, d: &str, version: &str) -> Result<(Arc<Repo>, String, Release), Response> {
    let (repo, owner) = repo(state, client, owner, d).await?;
    let Some(release) = repo.release(version).cloned() else {
        return Err(error(
            StatusCode::NOT_FOUND,
            format!("{} has no release {version:?}. Its releases are listed at {}.", repo.name, releases_url(state, &owner, &repo)),
        ));
    };
    Ok((repo, owner, release))
}

/// A redirect to the release's file called `name`, or with that sha256.
/// The gateway doesn't download these files, so it hasn't checked them:
/// whoever downloads one should check it against the sha256 in the JSON.
fn asset_redirect(base: &str, release: &Release, name: &str) -> Response {
    let matching: Vec<&nip82::Asset> = release.assets.iter().filter(|asset| asset.name() == name || asset.sha256 == name).collect();
    let mut hashes: Vec<&str> = matching.iter().map(|asset| asset.sha256.as_str()).collect();
    hashes.sort();
    hashes.dedup();
    let listing = format!("{base}/tags/{}", segment(&release.version));
    match (matching.first(), hashes.len()) {
        (None, _) => error(
            StatusCode::NOT_FOUND,
            format!("Release {} has no file named {name:?}. Its files are listed at {listing}.", release.version),
        ),
        (Some(_), 2..) => error(
            StatusCode::CONFLICT,
            format!(
                "Release {} has more than one file named {name:?}: {}. Download one by its sha256 instead, from {base}/download/{}/<sha256>.",
                release.version,
                hashes.join(", "),
                segment(&release.version)
            ),
        ),
        (Some(asset), _) => match &asset.url {
            Some(url) => Redirect::to(url).into_response(),
            None => error(
                StatusCode::NOT_FOUND,
                format!("{name:?} has no https URL, and the gateway has no Blossom server configured to look for it on."),
            ),
        },
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

    #[test]
    fn counts_ipv6_clients_by_their_64() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(network(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(network(ip("2001:db8:1:2:bbbb::9")), ip("2001:db8:1:2::"));
        assert_eq!(network(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(network(ip("192.0.2.1")), ip("192.0.2.1"));
    }
}

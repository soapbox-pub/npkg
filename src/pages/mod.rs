//! The pages people read, as opposed to the files apt, dnf, Flatpak and
//! F-Droid read: the front page, which lists every application, and each
//! repository's page, which says only what its own tool needs.
//!
//! Everything an author wrote is escaped. The pages work without their
//! script, which only adds copy buttons and a tilt. The stylesheet, script
//! and icon are compiled in and served from /assets/, so the pages can be
//! served with a policy that loads nothing else.

use std::fmt::Write;

use crate::fdroid;
use crate::http::{file_stem, flatpak_app, segment};
use crate::inspect::{Format, Meta};
use crate::nip82::{self, one_line};
use crate::nostr::nip19;
use crate::repo::{CHANNELS, Package, Repo};

pub const STYLE: &str = concat!(include_str!("wood.css"), include_str!("style.css"));
pub const SCRIPT: &str = include_str!("app.js");
pub const FAVICON: &str = include_str!("favicon.svg");

/// Nothing runs or loads that the gateway didn't serve itself. `data:`
/// images are the wood grain the stylesheet draws.
pub const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// What every page shows of the gateway itself.
pub struct Site<'a> {
    /// No trailing slash.
    pub base: &'a str,
    pub fingerprint: &'a str,
}

/// A kind of repository, each with a page of its own.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Apt,
    Rpm,
    Flatpak,
    Fdroid,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Apt, Kind::Rpm, Kind::Flatpak, Kind::Fdroid];

    fn path(self) -> &'static str {
        match self {
            Kind::Apt => "apt",
            Kind::Rpm => "rpm",
            Kind::Flatpak => "flatpak",
            Kind::Fdroid => "fdroid",
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Kind::Apt => "apt",
            Kind::Rpm => "dnf",
            Kind::Flatpak => "Flatpak",
            Kind::Fdroid => "F-Droid",
        }
    }

    fn systems(self) -> &'static str {
        match self {
            Kind::Apt => "Debian · Ubuntu · Mint",
            Kind::Rpm => "Fedora · RHEL · Rocky",
            Kind::Flatpak => "Any Linux desktop",
            Kind::Fdroid => "Android",
        }
    }

    fn mime(self) -> &'static str {
        match self {
            Kind::Apt => nip82::DEB_MIME,
            Kind::Rpm => nip82::RPM_MIME,
            Kind::Flatpak => nip82::FLATPAK_MIME,
            Kind::Fdroid => nip82::APK_MIME,
        }
    }

    fn format(self) -> Option<Format> {
        match self {
            Kind::Apt => Some(Format::Deb),
            Kind::Rpm => Some(Format::Rpm),
            Kind::Flatpak => None,
            Kind::Fdroid => Some(Format::Apk),
        }
    }

    fn has(self, repo: &Repo) -> bool {
        match self {
            Kind::Flatpak => !repo.bundles.is_empty(),
            Kind::Fdroid => repo.fdroid.is_some(),
            _ => repo.packages.iter().any(|package| Some(package.meta.format()) == self.format()),
        }
    }
}

/// `text`, safe in HTML text and in a quoted attribute.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn layout(site: &Site, title: &str, main: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/style.css">
<script src="/assets/app.js" defer></script>
</head>
<body>
<header class="beam wood">
  <a class="brand" href="/"><span class="brand-crate" aria-hidden="true"></span><span>npkg</span></a>
  <nav><a href="/#apps">Apps</a><a href="/#how">How it works</a><a href="/key.asc">Signing key</a></nav>
</header>
<main>
{main}
</main>
<footer>
  <p>Every index here is signed with key <code class="copyable">{fingerprint}</code> (<a href="/key.asc">key.asc</a>).</p>
  <p>Served by <strong>npkg</strong> from releases published on Nostr (NIP-82), at {base}.</p>
</footer>
</body>
</html>
"##,
        title = esc(title),
        fingerprint = esc(site.fingerprint),
        base = esc(site.base),
    )
}

/// A wooden crate turning in 3D, with `label` stencilled on it.
fn cube(class: &str, label: &str) -> String {
    format!(
        r#"<div class="scene {class}" aria-hidden="true"><div class="cube">
<div class="f front"><span>{label}</span></div><div class="f back"><span>{label}</span></div>
<div class="f right"><span class="small">this side up ⇧</span></div><div class="f left"><span class="small">fragile</span></div>
<div class="f top"></div><div class="f bottom"></div></div></div>"#
    )
}

/// A block of commands, one per line, each copied without its prompt.
fn commands(lines: &[String]) -> String {
    let mut out = String::from(r#"<div class="terminal"><pre class="cmd"><code>"#);
    for line in lines {
        let _ = write!(out, r#"<span class="ln">{}</span>"#, esc(line));
    }
    out.push_str("</code></pre></div>");
    out
}

/// Something to paste rather than run, such as an address.
fn address(text: &str) -> String {
    format!(r#"<div class="terminal"><pre class="cmd plain"><code><span class="ln">{}</span></code></pre></div>"#, esc(text))
}

fn step(n: usize, title: &str, body: &str) -> String {
    format!(r#"<li class="step"><span class="num">{n}</span><div><h3>{}</h3>{body}</div></li>"#, esc(title))
}

fn short(npub: &str) -> String {
    if npub.starts_with("npub1") && npub.len() > 20 { format!("{}…{}", &npub[..10], &npub[npub.len() - 6..]) } else { npub.to_string() }
}

fn date(time: i64) -> String {
    crate::apt::rfc3339(time)[..10].to_string()
}

fn size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.0} kB", bytes as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", bytes as f64 / 1e6),
        _ => format!("{:.2} GB", bytes as f64 / 1e9),
    }
}

fn android(sdk: u32) -> String {
    let version = match sdk {
        21 => "5.0",
        22 => "5.1",
        23 => "6",
        24 => "7.0",
        25 => "7.1",
        26 => "8.0",
        27 => "8.1",
        28 => "9",
        29 => "10",
        30 => "11",
        31 => "12",
        32 => "12L",
        33 => "13",
        34 => "14",
        35 => "15",
        36 => "16",
        _ => return format!("API {sdk}+"),
    };
    format!("{version}+")
}

/// `?channel=` for the channel ranked `rank`, or nothing for the stable one.
fn query(rank: usize) -> String {
    if rank == 0 { String::new() } else { format!("?channel={}", CHANNELS[rank]) }
}

/// The app's icon, or a stencilled initial on a crate.
fn icon(repo: &Repo, owner: &str, class: &str) -> String {
    match &repo.icon {
        Some((name, _)) => format!(
            r#"<img class="icon {class}" src="/icon/{}/{}/{}" alt="" width="96" height="96">"#,
            esc(owner),
            esc(&segment(&repo.d)),
            esc(name)
        ),
        None => {
            let initial = repo.name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default();
            format!(r#"<span class="icon {class} blank wood" aria-hidden="true">{}</span>"#, esc(&initial))
        }
    }
}

/// A QR code of `data`, as SVG.
fn qr(data: &str) -> String {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M) else { return String::new() };
    let width = code.width();
    let mut path = String::new();
    for (i, color) in code.to_colors().into_iter().enumerate() {
        if color == qrcode::Color::Dark {
            let _ = write!(path, "M{} {}h1v1h-1z", i % width + 4, i / width + 4);
        }
    }
    let side = width + 8;
    format!(
        r##"<svg class="qr" viewBox="0 0 {side} {side}" xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges" role="img" aria-label="QR code of the repository's address"><rect width="{side}" height="{side}" fill="#fffdf6"/><path d="{path}" fill="#1e140b"/></svg>"##
    )
}

mod render;
pub use render::{error, index, repo};

#[cfg(test)]
mod tests;

/// Each package of `format`, by name, newest first.
fn packages(repo: &Repo, format: Format) -> Vec<&Package> {
    let mut packages: Vec<&Package> = repo.packages.iter().filter(|package| package.meta.format() == format).collect();
    packages.sort_by(|a, b| a.meta.name().cmp(b.meta.name()).then(b.created_at.cmp(&a.created_at)));
    packages
}

/// The names `apt install` or `dnf install` needs.
fn names(repo: &Repo, format: Format) -> String {
    let mut names: Vec<&str> = packages(repo, format).into_iter().map(|package| package.meta.name()).collect();
    names.dedup();
    names.join(" ")
}

fn apk(meta: &Meta) -> Option<&crate::inspect::apk::ApkMeta> {
    match meta {
        Meta::Apk(apk) => Some(apk),
        _ => None,
    }
}

fn npub(repo: &Repo) -> String {
    nip19::npub_encode(&repo.pubkey)
}

fn label(text: &str) -> String {
    esc(&one_line(text))
}

fn fdroid_setup(address: &str, fingerprint: &str) -> String {
    fdroid::setup_url(address, fingerprint)
}

fn remote_name(d: &str, rank: usize) -> String {
    if rank == 0 { file_stem(d) } else { format!("{}-{}", file_stem(d), CHANNELS[rank]) }
}

fn app_id(repo: &Repo, rank: usize) -> Option<String> {
    repo.flatpak(rank).and_then(|channel| flatpak_app(repo, channel)).map(str::to_string)
}

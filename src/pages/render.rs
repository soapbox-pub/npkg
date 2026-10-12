//! The front page, repository pages, and error pages.

use std::fmt::Write;
use std::sync::Arc;

use super::*;

/// The front page: what the gateway is, and every application it serves.
pub fn index(site: &Site, repos: &[Arc<Repo>]) -> String {
    let mut main = String::new();
    let _ = write!(
        main,
        r##"<section class="hero">
  <div class="hero-text">
    <p class="eyebrow">apt · dnf · Flatpak · F-Droid</p>
    <h1>Software, <em>crated</em>.</h1>
    <p class="lede">npkg packs the releases its team publishes on Nostr into repositories your package manager already speaks. Add one once, and updates arrive with the rest of your system.</p>
    <p class="actions"><a class="button brass" href="#apps">Browse the apps</a><a class="button" href="#how">How it works</a></p>
  </div>
  <div class="hero-stage">{}{}{}<div class="floor"></div></div>
</section>
<section id="apps" class="shelf">
  <h2 class="stencil">In the warehouse <span class="tape">{} {}</span></h2>
  <div class="grid">"##,
        cube("big", "npkg"),
        cube("small one", "deb"),
        cube("small two", "apk"),
        repos.len(),
        if repos.len() == 1 { "app" } else { "apps" },
    );
    if repos.is_empty() {
        main.push_str(r#"<p class="empty paper">The warehouse is empty: the gateway hasn't seen a release from its team yet.</p>"#);
    }
    // What can be installed first; an application with nothing to install
    // here yet last.
    let mut sorted: Vec<&Arc<Repo>> = repos.iter().collect();
    sorted.sort_by_key(|repo| !Kind::ALL.into_iter().any(|kind| kind.has(repo)));
    for repo in sorted {
        let owner = npub(repo);
        let kinds: Vec<Kind> = Kind::ALL.into_iter().filter(|kind| kind.has(repo)).collect();
        let first = kinds.first().copied().unwrap_or(Kind::Apt);
        let href = format!("/{}/{}/{}", first.path(), esc(&owner), esc(&segment(&repo.d)));
        let latest = repo.latest(0).map(|release| format!(r#"<span class="tape">v{}</span>"#, label(&release.version))).unwrap_or_default();
        let _ = write!(
            main,
            r#"<article class="crate tilt{bare}"><div class="label">
  <a class="cover" href="{href}" aria-label="{name}"></a>
  {icon}
  <h3><a href="{href}">{name}</a> {latest}</h3>
  <p class="summary">{summary}</p>
  <p class="stamps">"#,
            bare = if kinds.is_empty() { " bare" } else { "" },
            icon = icon(repo, &owner, ""),
            name = label(&repo.name),
            summary = repo.summary.as_deref().map(label).unwrap_or_default(),
        );
        for kind in &kinds {
            let _ = write!(
                main,
                r#"<a class="stamp {}" href="/{}/{}/{}">{}</a>"#,
                kind.path(),
                kind.path(),
                esc(&owner),
                esc(&segment(&repo.d)),
                kind.tool()
            );
        }
        if kinds.is_empty() {
            main.push_str(r#"<span class="tape">nothing to install here yet</span>"#);
        }
        main.push_str("</p></div></article>");
    }
    main.push_str("</div></section>");

    let _ = write!(
        main,
        r#"<section id="how" class="how">
  <h2 class="stencil">How a crate gets here</h2>
  <ol class="steps three">
    {}{}{}
  </ol>
</section>
<section class="paper scripts">
  <h2>For scripts</h2>
  <p>Every release's files can be downloaded directly, the way GitHub's release URLs work. The owner is an npub, or a NIP-05 address like <code>soapbox.pub</code>.</p>
  <table class="ledger"><tbody>
    <tr><td><code>{base}/releases/&lt;owner&gt;/&lt;app&gt;</code></td><td>every release, as JSON</td></tr>
    <tr><td><code>{base}/releases/&lt;owner&gt;/&lt;app&gt;/latest</code></td><td>the latest stable release</td></tr>
    <tr><td><code>{base}/releases/&lt;owner&gt;/&lt;app&gt;/latest/download/&lt;file&gt;</code></td><td>its file, by name</td></tr>
  </tbody></table>
</section>"#,
        step(
            1,
            "Published on Nostr",
            "<p>The team signs NIP-82 release events naming each file and its SHA-256. The files themselves live on Blossom servers.</p>"
        ),
        step(
            2,
            "Crated here",
            "<p>npkg checks every file against its hash, reads what it is, and builds apt, dnf, Flatpak and F-Droid repositories, signed with its own key.</p>"
        ),
        step(
            3,
            "Installed by your tools",
            "<p>Add a repository once. Your package manager checks the signature on every update, like it does for any other repository.</p>"
        ),
        base = esc(site.base),
    );
    let names: Vec<String> = repos.iter().map(|repo| one_line(&repo.name)).collect();
    let description = if names.is_empty() {
        "apt, dnf, Flatpak and F-Droid repositories for software released on Nostr.".to_string()
    } else {
        format!("apt, dnf, Flatpak and F-Droid repositories for software released on Nostr: {}.", names.join(", "))
    };
    let head = Head {
        title: "npkg: software, crated",
        description: &description,
        path: Some("/"),
        image: SITE_CARD,
        image_alt: "Wooden crates in a warehouse, and a label: Software, crated.",
    };
    layout(site, &head, &main)
}

/// The page's head: its title, a description that says what's on it, and
/// the application's card.
fn repo_head(repo: &Repo, owner: &str, kind: Kind) -> (String, String, String, String) {
    let name = one_line(&repo.name);
    let title = format!("{name} for {}", kind.tool());
    let summary = repo.summary.as_deref().map(one_line).map(|summary| format!(" {summary}")).unwrap_or_default();
    let description = if kind.has(repo) {
        format!("Install {name} with {} ({}).{summary}", kind.tool(), kind.systems())
    } else {
        format!("{name} isn't released for {}.{summary}", kind.tool())
    };
    let image = match &repo.card {
        Some((hash, _)) => format!("/og/{}/{}/{hash}.jpg", npub(repo), segment(&repo.d)),
        None => SITE_CARD.to_string(),
    };
    let path = format!("/{}/{owner}/{}", kind.path(), segment(&repo.d));
    (title, description, image, path)
}

/// A repository's page for one kind of repository, on the channel ranked
/// `rank`. `owner` is as the URL gave it.
pub fn repo(site: &Site, repo: &Repo, owner: &str, kind: Kind, rank: usize) -> String {
    let (title, description, image, path) = repo_head(repo, owner, kind);
    let alt = format!("{}, on a label in a warehouse of wooden crates", one_line(&repo.name));
    let head = Head { title: &title, description: &description, path: Some(&path), image: &image, image_alt: &alt };
    let mut main = plaque(repo, owner, kind);
    if !kind.has(repo) {
        let _ = write!(
            main,
            r#"<section class="crate"><div class="label"><h2>No {} packages</h2><p>{} isn't released for {} ({}).</p>{}</div></section>"#,
            kind.tool(),
            label(&repo.name),
            kind.tool(),
            kind.systems(),
            elsewhere(repo, owner)
        );
        return layout(site, &head, &main);
    }
    let d = segment(&repo.d);
    let at = format!("{}/{}/{owner}/{d}", site.base, kind.path());
    match kind {
        Kind::Apt => main.push_str(&apt(site, repo, owner, &d, rank)),
        Kind::Rpm => main.push_str(&rpm(site, repo, owner, &d, rank)),
        Kind::Flatpak => main.push_str(&flatpak(site, repo, owner, &d, rank)),
        Kind::Fdroid => main.push_str(&fdroid(repo, owner, &d)),
    }
    main.push_str(&left_out(repo, kind));
    let releases = format!("{}/releases/{owner}/{d}", site.base);
    let _ = write!(
        main,
        r#"<section class="paper scripts"><h2>For scripts</h2>
<p>Every release, as JSON: <a href="{r}"><code>{r}</code></a>. A file of the latest one: <code>{r}/latest/download/&lt;file&gt;</code>.</p>
<p class="fine">This page: <code>{at}</code></p></section>"#,
        r = esc(&releases),
        at = esc(&at),
    );
    layout(site, &head, &main)
}

/// The application's nameplate, and a tab for each kind of repository.
fn plaque(repo: &Repo, owner: &str, kind: Kind) -> String {
    let application = repo.snapshot.application.as_ref();
    let mut links = String::new();
    for (text, url) in
        [("Website", application.and_then(|app| app.website.as_deref())), ("Source", application.and_then(|app| app.repository.as_deref()))]
    {
        if let Some(url) = url.filter(|url| url.starts_with("https://")) {
            let _ = write!(links, r#"<a href="{}" rel="nofollow noopener">{text}</a>"#, esc(url));
        }
    }
    if let Some(license) = application.and_then(|app| app.license.as_deref()) {
        let _ = write!(links, r#"<span class="tape">{}</span>"#, label(license));
    }
    let description = application.map(|app| app.description.trim()).filter(|text| !text.is_empty()).map(|text| {
        let paragraphs: String = text.split("\n\n").map(|p| format!("<p>{}</p>", esc(p.trim()))).collect();
        format!(r#"<details class="about"><summary>About {}</summary>{paragraphs}</details>"#, label(&repo.name))
    });
    let mut out = format!(
        r#"<section class="crate plaque"><div class="label">
{icon}
<div class="plate">
  <p class="eyebrow"><a href="/">npkg</a> / <span title="{owner}">{short}</span></p>
  <h1>{name}</h1>
  <p class="summary">{summary}</p>
  <p class="links">{links}</p>
  {description}
</div></div></section>
<nav class="tabs" aria-label="Kinds of repository">"#,
        icon = icon(repo, owner, "large"),
        owner = esc(owner),
        short = esc(&short(owner)),
        name = label(&repo.name),
        summary = repo.summary.as_deref().map(label).unwrap_or_default(),
        description = description.unwrap_or_default(),
    );
    for other in Kind::ALL {
        let current = if other == kind { r#" aria-current="page""# } else { "" };
        let off = if other.has(repo) { "" } else { " off" };
        let _ = write!(
            out,
            r#"<a class="tab{off}" href="/{}/{}/{}"{current}><strong>{}</strong><small>{}</small></a>"#,
            other.path(),
            esc(owner),
            esc(&segment(&repo.d)),
            other.tool(),
            other.systems()
        );
    }
    out.push_str("</nav>");
    out
}

/// Links to the kinds of repository the application does have.
fn elsewhere(repo: &Repo, owner: &str) -> String {
    let mut out = String::from(r#"<p class="stamps">"#);
    for kind in Kind::ALL.into_iter().filter(|kind| kind.has(repo)) {
        let _ = write!(
            out,
            r#"<a class="stamp {}" href="/{}/{}/{}">{}</a>"#,
            kind.path(),
            kind.path(),
            esc(owner),
            esc(&segment(&repo.d)),
            kind.tool()
        );
    }
    out.push_str("</p>");
    out
}

/// Links to each channel's version of this page.
fn channels(rank: usize) -> String {
    let mut out = String::from(r#"<div class="channels"><span>Channel</span>"#);
    for (i, channel) in CHANNELS.iter().enumerate() {
        let href = if i == 0 { "?".to_string() } else { format!("?channel={channel}") };
        let current = if i == rank { r#" aria-current="true""# } else { "" };
        let _ = write!(out, r#"<a class="chip" href="{href}"{current}>{channel}</a>"#);
    }
    out.push_str(r#"<small>Each channel has every more stable one's releases too.</small></div>"#);
    out
}

fn apt(site: &Site, repo: &Repo, owner: &str, d: &str, rank: usize) -> String {
    let file = file_stem(&repo.d);
    let source = format!("/etc/apt/sources.list.d/{file}.sources");
    let mut out = format!(r#"<section class="paper install"><h2>Install with apt</h2>{}<ol class="steps">"#, channels(rank));
    out.push_str(&step(
        1,
        "Add the repository",
        &format!(
            "<p>One file holds its address and the key its indexes are signed with.</p>{}",
            commands(&[format!("sudo curl -fsSL -o {source} {}/apt/{owner}/{d}/source{}", site.base, query(rank))])
        ),
    ));
    out.push_str(&step(2, "Install", &commands(&["sudo apt update".into(), format!("sudo apt install {}", names(repo, Format::Deb))])));
    out.push_str(&step(
        3,
        "Stay up to date",
        &format!(
            "<p>Updates come with the rest of the system's.</p>{}<p>To stop using the repository, delete its file.</p>{}",
            commands(&["sudo apt update && sudo apt upgrade".into()]),
            commands(&[format!("sudo rm {source}")])
        ),
    ));
    out.push_str(r#"</ol><p class="fine">No curl? <code>sudo apt install curl</code> first.</p></section>"#);
    out.push_str(&package_table(repo, owner, d, Format::Deb));
    out
}

fn rpm(site: &Site, repo: &Repo, owner: &str, d: &str, rank: usize) -> String {
    let file = format!("/etc/yum.repos.d/{}.repo", file_stem(&repo.d));
    let mut out = format!(r#"<section class="paper install"><h2>Install with dnf</h2>{}<ol class="steps">"#, channels(rank));
    out.push_str(&step(
        1,
        "Add the repository",
        &commands(&[format!("sudo curl -fsSL -o {file} {}/rpm/{owner}/{d}/repo{}", site.base, query(rank))]),
    ));
    out.push_str(&step(
        2,
        "Install",
        &format!(
            "{}<p>dnf asks once whether to trust the gateway's key. Its fingerprint should be <code>{}</code>.</p>",
            commands(&[format!("sudo dnf install {}", names(repo, Format::Rpm))]),
            esc(site.fingerprint)
        ),
    ));
    out.push_str(&step(
        3,
        "Stay up to date",
        &format!(
            "{}<p>To stop using the repository, delete its file.</p>{}",
            commands(&["sudo dnf upgrade".into()]),
            commands(&[format!("sudo rm {file}")])
        ),
    ));
    out.push_str("</ol></section>");
    out.push_str(&package_table(repo, owner, d, Format::Rpm));
    out
}

fn package_table(repo: &Repo, owner: &str, d: &str, format: Format) -> String {
    let mut out = String::from(
        r#"<section class="paper"><h2>Packages</h2><div class="scroll"><table class="ledger"><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Channel</th><th>Released</th><th>Size</th><th></th></tr></thead><tbody>"#,
    );
    for package in packages(repo, format) {
        let (name, version, arch) = (package.meta.name(), package.meta.version(), package.meta.arch());
        let href = match format {
            Format::Deb => format!("/apt/{owner}/{d}/pool/{}/{}", package.sha256, segment(&format!("{name}_{version}_{arch}.deb"))),
            _ => format!(
                "/rpm/{owner}/{d}/{}/packages/{}/{}",
                CHANNELS[package.channel],
                package.sha256,
                segment(&format!("{name}-{version}.{arch}.rpm"))
            ),
        };
        let _ = write!(
            out,
            r#"<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td><span class="chip small">{}</span></td><td>{}</td><td>{}</td><td><a href="{}" title="SHA-256 {}">Download</a></td></tr>"#,
            label(name),
            label(&version),
            label(&arch),
            CHANNELS[package.channel],
            date(package.created_at),
            size(package.size),
            esc(&href),
            package.sha256
        );
    }
    out.push_str("</tbody></table></div></section>");
    out
}

fn flatpak(site: &Site, repo: &Repo, owner: &str, d: &str, rank: usize) -> String {
    let mut out = format!(r#"<section class="paper install"><h2>Install with Flatpak</h2>{}"#, channels(rank));
    let (Some(remote), Some(app)) = (repo.flatpak(rank), app_id(repo, rank)) else {
        out.push_str(&format!("<p>There's no Flatpak of {} on the {} channel yet.</p></section>", label(&repo.name), CHANNELS[rank]));
        return out;
    };
    let file = file_stem(&repo.d);
    out.push_str(r#"<ol class="steps">"#);
    out.push_str(&step(
        1,
        "Install",
        &format!(
            "<p>Adds the remote <code>{}</code> and installs the app, with the runtime it needs from Flathub.</p>{}",
            esc(&remote_name(&repo.d, rank)),
            commands(&[format!("flatpak install --user {}/flatpak/{owner}/{d}/{file}.flatpakref{}", site.base, query(rank))])
        ),
    ));
    out.push_str(&step(2, "Run it", &format!("<p>Or find it among your apps.</p>{}", commands(&[format!("flatpak run {app}")]))));
    out.push_str(&step(
        3,
        "Stay up to date",
        &format!("<p>GNOME Software and Discover update it too.</p>{}", commands(&["flatpak update".into()])),
    ));
    out.push_str("</ol></section>");

    let current =
        remote.refs.iter().find(|head| head.bundle.ref_name.split('/').nth(1) == Some(app.as_str())).map(|head| head.bundle.commit.clone());
    let _ = write!(
        out,
        r#"<section class="paper"><h2>Every version</h2><p>Each one is a commit on top of the last, so Flatpak can go back to any of them. Click a commit to copy it.</p><div class="rollback"><div><h3>Go back to one</h3>{}</div><div><h3>Stay there</h3>{}</div><div><h3>Back to the newest</h3>{}</div></div><div class="scroll"><table class="ledger"><thead><tr><th>Version</th><th>Arch</th><th>Published</th><th>Commit</th></tr></thead><tbody>"#,
        commands(&[format!("flatpak update --user --commit=<commit> {app}")]),
        commands(&[format!("flatpak mask --user {app}")]),
        commands(&[format!("flatpak mask --user --remove {app} && flatpak update --user")]),
    );
    for published in remote.history.iter().rev() {
        let arch = published.ref_name.split('/').nth(2).unwrap_or_default();
        let tag = if Some(&published.commit) == current.as_ref() { r#" <span class="tape">current</span>"# } else { "" };
        let _ = write!(
            out,
            r#"<tr><td><strong>{}</strong>{tag}</td><td>{}</td><td>{}</td><td><code class="copyable commit" title="{c}">{c}</code></td></tr>"#,
            label(&published.version),
            label(arch),
            date(published.timestamp as i64),
            c = esc(&published.commit),
        );
    }
    out.push_str(r#"</tbody></table></div><p class="fine">Also listed by <code>flatpak remote-info --log</code>.</p></section>"#);
    out
}

fn fdroid(repo: &Repo, owner: &str, d: &str) -> String {
    let Some(fdroid) = &repo.fdroid else { return String::new() };
    let url = fdroid_setup(&fdroid.address, &fdroid.fingerprint);
    let open = url
        .strip_prefix("https://")
        .map(|rest| format!(r#"<a class="button brass" href="fdroidrepos://{}">Open in F-Droid</a>"#, esc(rest)))
        .unwrap_or_default();
    let grouped: Vec<String> = fdroid.fingerprint.as_bytes().chunks(4).map(|chunk| String::from_utf8_lossy(chunk).to_uppercase()).collect();
    let mut out = format!(
        r#"<section class="paper install fdroid"><h2>Install with F-Droid</h2>
<div class="split">
<figure class="pinned">{qr}<figcaption>Scan with F-Droid</figcaption></figure>
<ol class="steps">{one}{two}{three}</ol>
</div>
<p class="fingerprint">Repository fingerprint<br><code>{grouped}</code></p>
</section>"#,
        qr = qr(&url),
        one = step(1, "Get F-Droid", r#"<p>From <a href="https://f-droid.org/" rel="noopener">f-droid.org</a>, if you haven't.</p>"#),
        two = step(
            2,
            "Add this repository",
            &format!(
                "<p>On the phone, tap {open_text}. Or in F-Droid, open Settings, Repositories, tap +, and scan this code or paste the address.</p>{open}{cmd}",
                open_text = if open.is_empty() { "the address" } else { "Open in F-Droid" },
                cmd = address(&url)
            )
        ),
        three = step(
            3,
            "Install",
            &format!(
                "<p>Search for {} and install it. Releases off the stable channel show up as betas, if you've turned those on.</p>",
                label(&repo.name)
            )
        ),
        grouped = esc(&grouped.join(" ")),
    );
    out.push_str(
        r#"<section class="paper"><h2>Versions</h2><div class="scroll"><table class="ledger"><thead><tr><th>Version</th><th>Code</th><th>ABIs</th><th>Android</th><th>Channel</th><th>Released</th><th>Size</th></tr></thead><tbody>"#,
    );
    for package in packages(repo, Format::Apk) {
        let Some(apk) = apk(&package.meta) else { continue };
        let abis = if apk.nativecode.is_empty() { "any".to_string() } else { apk.nativecode.join(", ") };
        let _ = write!(
            out,
            r#"<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td>{}</td><td><span class="chip small">{}</span></td><td>{}</td><td><a href="/fdroid/{}/{}/repo/{}/{}.apk">{}</a></td></tr>"#,
            label(&apk.version_name),
            apk.version_code,
            label(&abis),
            android(apk.min_sdk),
            CHANNELS[package.channel],
            date(package.created_at),
            esc(owner),
            esc(d),
            package.sha256,
            esc(&segment(&format!("{}_{}", apk.package, apk.version_code))),
            size(package.size),
        );
    }
    out.push_str("</tbody></table></div></section>");
    out
}

/// What the application's releases listed of this kind that isn't served,
/// and why.
fn left_out(repo: &Repo, kind: Kind) -> String {
    let rejections: Vec<_> =
        repo.rejections.iter().filter(|rejection| rejection.mime == kind.mime() || rejection.mime.is_empty()).collect();
    if rejections.is_empty() {
        return String::new();
    }
    let mut out = format!(
        r#"<section class="paper"><details><summary>Left out <span class="tape">{}</span></summary><table class="ledger"><thead><tr><th>Release</th><th>File</th><th>Why</th></tr></thead><tbody>"#,
        rejections.len()
    );
    for rejection in rejections {
        let file = rejection.sha256.get(..12).unwrap_or(&rejection.sha256);
        let _ = write!(
            out,
            r#"<tr><td>{}</td><td><code title="{}">{}</code></td><td>{}</td></tr>"#,
            label(&rejection.release),
            esc(&rejection.sha256),
            esc(file),
            label(&rejection.reason)
        );
    }
    out.push_str("</tbody></table></details></section>");
    out
}

/// An error, for a person: the status stamped on a crate, and what to do.
pub fn error(site: &Site, status: u16, reason: &str, message: &str) -> String {
    let main = format!(
        r#"<section class="error">{}<div class="crate"><div class="label"><span class="stamp big">{status} {}</span><p class="message">{}</p><p><a class="button brass" href="/">Back to the warehouse</a></p></div></div></section>"#,
        cube("small lost", "?"),
        esc(reason),
        esc(message.trim())
    );
    let title = format!("{status} {reason}");
    let head = Head {
        title: &title,
        description: message.trim(),
        path: None,
        image: SITE_CARD,
        image_alt: "Wooden crates in a warehouse, and a label: Software, crated.",
    };
    layout(site, &head, &main)
}

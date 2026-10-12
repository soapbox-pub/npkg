use super::*;
use crate::db::Db;
use crate::repo::tests::{hello, repos};

const SITE: Site = Site { base: "https://pkg.example.com", fingerprint: "1775DF3E" };

#[test]
fn escapes_what_authors_write() {
    assert_eq!(esc(r#"<script>"x" & 'y'</script>"#), "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;");
}

#[test]
fn draws_a_qr_code() {
    let svg = qr("https://pkg.example.com/fdroid/x/y/repo?fingerprint=ab");
    assert!(svg.starts_with("<svg") && svg.contains("M4 4h1v1h-1z"), "{svg}");
}

#[tokio::test]
async fn puts_each_kind_of_repository_on_its_own_page() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("db.sqlite")).unwrap();
    let mut snapshot = hello(&db).await;
    if let Some(app) = &mut snapshot.application {
        app.name = Some("Hello <b>".into());
        app.summary = Some("Says \"hi\"".into());
    }
    let repo = repos(dir.path(), &db).build("pk", "hello", &snapshot, true).await.unwrap();
    let team = Author {
        pubkey: "pk".into(),
        address: Some("soapbox.pub".into()),
        name: Some("Team <Soapbox>".into()),
        picture: Some(("avatar-ab".into(), Vec::new())),
    };

    let deb = super::repo(&SITE, &repo, &team, Kind::Deb, 0);
    assert!(deb.contains("sudo curl -fsSL -o /etc/apt/sources.list.d/hello.sources https://pkg.example.com/deb/soapbox.pub/hello/source"));
    assert!(deb.contains("sudo apt install hello"));
    assert!(deb.contains("Hello &lt;b&gt;") && !deb.contains("<b>"));
    // The deb page says nothing of dnf, and the never-downloaded file it left
    // out is a .deb, so it's listed here.
    assert!(!deb.contains("dnf install") && !deb.contains("yum.repos.d") && !deb.contains("/rpm/soapbox.pub/hello/repo"));
    assert!(deb.contains("Left out"));
    assert!(super::repo(&SITE, &repo, &team, Kind::Deb, 1).contains("/source?channel=beta"));

    // No rpm, Flatpak or APK: those pages say so, and point to deb.
    for kind in [Kind::Rpm, Kind::Flatpak, Kind::Fdroid] {
        let page = super::repo(&SITE, &repo, &team, kind, 0);
        assert!(page.contains("isn't released for") && page.contains(r#"class="stamp deb""#));
        assert!(!page.contains("Left out"));
    }

    // Its card, and tags for search engines and link previews.
    let (hash, _) = repo.card.as_ref().unwrap();
    let card = format!(r#"<meta property="og:image" content="https://pkg.example.com/og/{}/hello/{hash}.jpg">"#, nip19::npub_encode("pk"));
    assert!(deb.contains(&card), "{deb}");
    assert!(deb.contains(r#"<meta property="og:title" content="Hello &lt;b&gt; for deb">"#));
    assert!(deb.contains(r#"<link rel="canonical" href="https://pkg.example.com/deb/soapbox.pub/hello">"#));
    assert!(
        deb.contains(
            r#"<meta name="description" content="Install Hello &lt;b&gt; from its deb repository (Debian · Ubuntu · Mint). Says &quot;hi&quot;">"#
        )
    );
    assert!(deb.contains(r#"<meta name="twitter:card" content="summary_large_image">"#));

    let repos = [std::sync::Arc::new(repo)];
    let unknown = |pubkey: &str| std::sync::Arc::new(Author { pubkey: pubkey.into(), ..Default::default() });
    let index = index(&SITE, &repos, unknown);
    assert!(index.contains(&format!(r#"content="https://pkg.example.com{SITE_CARD}""#)));
    assert!(index.contains("for software released on Nostr: Hello &lt;b&gt;."));
    assert!(index.contains("Hello &lt;b&gt;") && index.contains("Says &quot;hi&quot;"));
    assert!(index.contains(&format!("/deb/{}/hello", nip19::npub_encode("pk"))));
    // An author with no profile is shown by their npub.
    let npub = nip19::npub_encode("pk");
    assert!(index.contains(&format!(r#"<span>{}</span>"#, short(&npub))) && index.contains("avatar blank"));
    // One with a NIP-05 address is linked by it, and shown with their
    // picture and name.
    let index = super::index(&SITE, &repos, |_| std::sync::Arc::new(team.clone()));
    assert!(index.contains(r#"href="/deb/soapbox.pub/hello""#) && !index.contains("/deb/npub1"));
    let byline =
        r#"<img class="avatar" src="/avatar/soapbox.pub/avatar-ab" alt="" width="24" height="24"><span>Team &lt;Soapbox&gt;</span>"#;
    assert!(index.contains(byline), "{index}");
    assert!(deb.contains(byline));
}

#[test]
fn says_what_went_wrong() {
    let page = error(&SITE, 404, "Not Found", "There's no <such> thing.\n");
    assert!(page.contains("404 Not Found") && page.contains("There&#39;s no &lt;such&gt; thing."));
    assert!(page.contains(r#"<meta name="robots" content="noindex">"#) && !page.contains("canonical"));
}

#[test]
fn draws_the_sites_card() {
    let jpeg = site_card(SITE.base).unwrap();
    assert_eq!(&jpeg[..3], [0xff, 0xd8, 0xff]);
}

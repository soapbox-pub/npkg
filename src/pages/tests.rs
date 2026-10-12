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

    let apt = super::repo(&SITE, &repo, "soapbox.pub", Kind::Apt, 0);
    assert!(apt.contains("sudo curl -fsSL -o /etc/apt/sources.list.d/hello.sources https://pkg.example.com/apt/soapbox.pub/hello/source"));
    assert!(apt.contains("sudo apt install hello"));
    assert!(apt.contains("Hello &lt;b&gt;") && !apt.contains("<b>"));
    // apt's page says nothing of dnf, and the never-downloaded file it left
    // out is a .deb, so it's listed here.
    assert!(!apt.contains("dnf install") && !apt.contains("yum.repos.d") && !apt.contains("/rpm/soapbox.pub/hello/repo"));
    assert!(apt.contains("Left out"));
    assert!(super::repo(&SITE, &repo, "soapbox.pub", Kind::Apt, 1).contains("/source?channel=beta"));

    // No rpm, Flatpak or APK: those pages say so, and point to apt.
    for kind in [Kind::Rpm, Kind::Flatpak, Kind::Fdroid] {
        let page = super::repo(&SITE, &repo, "soapbox.pub", kind, 0);
        assert!(page.contains("isn't released for") && page.contains(r#"class="stamp apt""#));
        assert!(!page.contains("Left out"));
    }

    let index = index(&SITE, &[std::sync::Arc::new(repo)]);
    assert!(index.contains("Hello &lt;b&gt;") && index.contains("Says &quot;hi&quot;"));
    assert!(index.contains(&format!("/apt/{}/hello", nip19::npub_encode("pk"))));
}

#[test]
fn says_what_went_wrong() {
    let page = error(&SITE, 404, "Not Found", "There's no <such> thing.\n");
    assert!(page.contains("404 Not Found") && page.contains("There&#39;s no &lt;such&gt; thing."));
}

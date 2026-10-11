//! A remote's AppStream branches, which GNOME Software, Discover and
//! `flatpak search` read to show apps before they're installed.
//!
//! Made as `flatpak build-update-repo` makes them: for each architecture,
//! every app's own AppStream data (`files/share/app-info/xmls/<id>.xml.gz`,
//! which `flatpak-builder` composes) merged into one `<components>`, each
//! component given a `<bundle>` naming the ref it installs, and the icons
//! beside it. `appstream/<arch>` holds it gzipped, for old clients;
//! `appstream2/<arch>` holds it plain, which compresses better in an
//! `archive-z2` repository. The XML is written byte for byte as Flatpak
//! writes it, so a branch made from the same apps has the same tree.
//!
//! An app whose data is missing or unreadable is left out of the listing,
//! as Flatpak leaves it out; it still installs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail, ensure};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use quick_xml::events::Event;
use sha2::{Digest, Sha256};

use super::delta::Bundle;
use super::{DirTree, FileMeta, Kind, Store, plain_dirmeta};
use crate::gvariant::{Type, Value};

/// The most an app's AppStream file or an icon may be, compressed or not.
const MAX_FILE: u64 = 16 << 20;

/// How deeply an app's AppStream elements may nest. Real ones go five or
/// six deep; the tree is written, copied and dropped recursively, so a file
/// made to nest millions deep would overflow the stack.
const MAX_DEPTH: usize = 64;

const ICON_SIZES: [&str; 2] = ["64x64", "128x128"];

/// Make the AppStream branches for `apps`, writing their objects to
/// `store`, and describe their commits. Commits are dated `timestamp`, so
/// the same apps give the same commits.
pub fn build(store: &Store, apps: &[&Bundle], timestamp: u64) -> Result<Vec<Bundle>> {
    let arches: BTreeSet<&str> = apps.iter().filter_map(|app| app.ref_name.split('/').nth(2)).collect();
    let mut branches = Vec::new();
    for arch in arches {
        let mut refs: Vec<&Bundle> = apps.iter().copied().filter(|app| app.ref_name.split('/').nth(2) == Some(arch)).collect();
        refs.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));

        let mut components = Vec::new();
        let mut icons: [BTreeMap<String, String>; 2] = Default::default();
        for app in refs {
            if let Err(error) = extract(store, app, &mut components, &mut icons) {
                tracing::info!(r#ref = app.ref_name, error = format!("{error:#}"), "no AppStream data");
            }
        }
        let xml = serialize(components);
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(xml.as_bytes())?;
        let gz = gz.finish()?;

        branches.push(write_branch(store, &format!("appstream/{arch}"), ("appstream.xml.gz", &gz), &icons, timestamp)?);
        branches.push(write_branch(store, &format!("appstream2/{arch}"), ("appstream.xml", xml.as_bytes()), &icons, timestamp)?);
    }
    Ok(branches)
}

/// Add `app`'s components to `components`, and the icons of every component
/// named after it to `icons`, by size.
fn extract(store: &Store, app: &Bundle, components: &mut Vec<Element>, icons: &mut [BTreeMap<String, String>; 2]) -> Result<()> {
    let id = app.ref_name.split('/').nth(1).ok_or_else(|| anyhow!("The ref names no app."))?;
    let path = format!("files/share/app-info/xmls/{id}.xml.gz");
    let checksum = store.lookup(&app.commit, &path)?.ok_or_else(|| anyhow!("The app has no {path}."))?;
    let mut xml = String::new();
    GzDecoder::new(&store.file_content(&checksum, MAX_FILE)?[..])
        .take(MAX_FILE)
        .read_to_string(&mut xml)
        .with_context(|| format!("{path} isn't gzipped UTF-8"))?;
    let roots = parse(&xml).with_context(|| format!("{path} isn't XML"))?;
    let [source] = &roots[..] else { bail!("{path} has more than one root element.") };
    ensure!(source.name == "components", "{path}'s root element isn't <components>.");

    let keys = Metadata::parse(&app.metadata);
    let tags: Vec<&str> = keys.get("tags").map(|tags| tags.split(';').filter(|tag| !tag.is_empty()).collect()).unwrap_or_default();
    let mut migrated = false;
    for child in &source.children {
        if let Node::Element(component) = child
            && let Some(component) = validate(component.clone(), &app.ref_name, id, &tags, keys.get("runtime"), keys.get("sdk"))
        {
            components.push(component);
            migrated = true;
        }
    }
    ensure!(migrated, "{path} has no component for {id}.");

    // Flatpak looks again at every component so far, this app's or not,
    // whose id starts with this app's.
    for component in components.iter() {
        let Some(component_id) = component_id(component) else { continue };
        let component_id = component_id.trim_ascii();
        match component_id.strip_prefix(id) {
            Some(rest) if rest.is_empty() || rest.starts_with('.') => {}
            _ => continue,
        }
        for (size, icons) in ICON_SIZES.iter().zip(icons.iter_mut()) {
            let name = format!("{component_id}.png");
            if let Some(icon) = store.lookup(&app.commit, &format!("files/share/app-info/icons/flatpak/{size}/{name}"))? {
                icons.insert(name, icon);
            }
        }
    }
    Ok(())
}

/// `component` fit for the merged listing, if it belongs to `id`: its own
/// `<bundle>` replaced by one naming `ref_name`, and the app's tags added.
fn validate(mut component: Element, ref_name: &str, id: &str, tags: &[&str], runtime: Option<&str>, sdk: Option<&str>) -> Option<Element> {
    let mut id_text = component_id(&component)?.trim_ascii();
    if !id.ends_with(".desktop") {
        id_text = id_text.strip_suffix(".desktop").unwrap_or(id_text);
    }
    if !id_text.starts_with(id) {
        return None;
    }

    component.children.retain(|child| !matches!(child, Node::Element(element) if element.name == "bundle"));
    let mut attrs = vec![("type".to_string(), "flatpak".to_string())];
    if let Some(runtime) = runtime.filter(|runtime| !runtime.starts_with("runtime/")) {
        attrs.push(("runtime".into(), runtime.into()));
    }
    if let Some(sdk) = sdk {
        attrs.push(("sdk".into(), sdk.into()));
    }
    let bundle = Element { name: "bundle".into(), attrs, children: vec![Node::Text(ref_name.into())] };
    component.children.extend([Node::Text("  ".into()), Node::Element(bundle), Node::Text("\n  ".into())]);

    if !tags.is_empty() {
        let at = match component.children.iter().position(|child| matches!(child, Node::Element(element) if element.name == "metadata")) {
            Some(at) => at,
            None => {
                let metadata = Element { name: "metadata".into(), attrs: Vec::new(), children: Vec::new() };
                component.children.extend([Node::Text("  ".into()), Node::Element(metadata), Node::Text("\n  ".into())]);
                component.children.len() - 2
            }
        };
        if let Node::Element(metadata) = &mut component.children[at] {
            let value = Element {
                name: "value".into(),
                attrs: vec![("key".into(), "X-Flatpak-Tags".into())],
                children: vec![Node::Text(tags.join(","))],
            };
            metadata.children.extend([Node::Text("\n       ".into()), Node::Element(value), Node::Text("\n    ".into())]);
        }
    }
    Some(component)
}

/// The text of a component's `<id>`, as Flatpak finds it: the first piece
/// of text in the first `<id>`.
fn component_id(component: &Element) -> Option<&str> {
    let id = component.children.iter().find_map(|child| match child {
        Node::Element(element) if element.name == "id" => Some(element),
        _ => None,
    })?;
    id.children.iter().find_map(|child| match child {
        Node::Text(text) => Some(text.as_str()),
        _ => None,
    })
}

/// Write one branch's files, directories and commit, and describe it.
fn write_branch(
    store: &Store,
    branch: &str,
    (name, content): (&str, &[u8]),
    icons: &[BTreeMap<String, String>; 2],
    timestamp: u64,
) -> Result<Bundle> {
    let (dirmeta, dirmeta_bytes) = plain_dirmeta();
    store.write(Kind::DirMeta, &dirmeta, &dirmeta_bytes)?;
    let write_dir = |tree: DirTree| -> Result<(String, String, String)> {
        let (checksum, bytes) = tree.to_object()?;
        store.write(Kind::DirTree, &checksum, &bytes)?;
        Ok((String::new(), checksum, dirmeta.clone()))
    };

    let mut regular = Vec::new();
    let xml = store.write_file(&FileMeta::plain_file(), content)?;
    regular.push((xml.clone(), content.len() as u64));

    let mut icon_dirs = Vec::new();
    for (size, icons) in ICON_SIZES.iter().zip(icons) {
        for icon in icons.values() {
            regular.push((icon.clone(), store.file_content(icon, MAX_FILE)?.len() as u64));
        }
        let files = icons.iter().map(|(name, checksum)| (name.clone(), checksum.clone())).collect();
        let (_, tree, meta) = write_dir(DirTree { files, dirs: Vec::new() })?;
        icon_dirs.push((size.to_string(), tree, meta));
    }
    // So the layout matches libappstream's, which expects an origin
    // directory, `flatpak`, as flatpak-builder names it.
    let links = ICON_SIZES
        .iter()
        .map(|size| Ok((size.to_string(), store.write_file(&FileMeta::plain_symlink(), format!("../{size}").as_bytes())?)))
        .collect::<Result<_>>()?;
    let (_, tree, meta) = write_dir(DirTree { files: links, dirs: Vec::new() })?;
    icon_dirs.push(("flatpak".into(), tree, meta));
    let (_, icons_tree, _) = write_dir(DirTree { files: Vec::new(), dirs: icon_dirs })?;
    let (_, root, _) = write_dir(DirTree { files: vec![(name.into(), xml)], dirs: vec![("icons".into(), icons_tree, dirmeta.clone())] })?;

    let commit = Value::Tuple(vec![
        Value::vardict(vec![
            ("ostree.collection-binding", Value::str("")),
            ("ostree.ref-binding", Value::Array(Type::Str, vec![Value::str(branch)])),
        ]),
        Value::bytes(Vec::new()),
        Value::Array(Type::parse("(say)")?, Vec::new()),
        Value::str("Update"),
        Value::str(""),
        Value::U64(timestamp.swap_bytes()),
        Value::bytes(hex::decode(&root)?),
        Value::bytes(hex::decode(&dirmeta)?),
    ])
    .to_bytes();
    let checksum = hex::encode(Sha256::digest(&commit));
    store.write(Kind::Commit, &checksum, &commit)?;

    // As Flatpak counts them for a commit that doesn't say: whole 512-byte
    // blocks installed, and the objects as stored downloaded.
    let installed_size = regular.iter().map(|(_, size)| size.div_ceil(512) * 512).sum();
    let download_size = regular.iter().map(|(checksum, _)| store.size(Kind::File, checksum)).sum();
    Ok(Bundle {
        commit: checksum,
        ref_name: branch.into(),
        commit_size: commit.len() as u64,
        timestamp,
        installed_size,
        download_size,
        metadata: String::new(),
    })
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Element(Element),
    Text(String),
}

#[derive(Clone, Debug, PartialEq)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

/// The top-level elements of `xml`, with all the text between elements kept,
/// and comments and processing instructions dropped, as GLib's parser
/// gives them to Flatpak.
fn parse(xml: &str) -> Result<Vec<Element>> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut roots = Vec::new();
    let mut open: Vec<Element> = Vec::new();
    let element = |start: &quick_xml::events::BytesStart| -> Result<Element> {
        let name = start.name().as_ref().to_string();
        let attrs = start
            .attributes()
            .map(|attr| {
                let attr = attr?;
                Ok((attr.key.as_ref().to_string(), attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)?.into_owned()))
            })
            .collect::<Result<_>>()?;
        Ok(Element { name, attrs, children: Vec::new() })
    };
    let close = |element: Element, open: &mut Vec<Element>, roots: &mut Vec<Element>| match open.last_mut() {
        Some(parent) => parent.children.push(Node::Element(element)),
        None => roots.push(element),
    };
    let text = |text: &str, open: &mut Vec<Element>| {
        // Text outside the root element is only whitespace, which GLib skips.
        let Some(parent) = open.last_mut() else { return };
        match parent.children.last_mut() {
            Some(Node::Text(last)) => last.push_str(text),
            _ => parent.children.push(Node::Text(text.to_string())),
        }
    };
    loop {
        match reader.read_event()? {
            Event::Start(start) => {
                ensure!(open.len() < MAX_DEPTH, "Its elements nest more than {MAX_DEPTH} deep.");
                open.push(element(&start)?);
            }
            Event::Empty(start) => close(element(&start)?, &mut open, &mut roots),
            Event::End(_) => {
                let element = open.pop().ok_or_else(|| anyhow!("An element closes that never opened."))?;
                close(element, &mut open, &mut roots);
            }
            Event::Text(t) => text(&t.xml10_content(), &mut open),
            Event::CData(t) => text(&t.into_inner(), &mut open),
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref()? {
                    Some(c) => c.to_string(),
                    None => match &*r {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "apos" => "'",
                        "quot" => "\"",
                        other => bail!("&{other}; isn't an entity XML defines."),
                    }
                    .to_string(),
                };
                text(&resolved, &mut open);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(open.is_empty(), "<{}> never closes.", open.last().map_or("", |element| element.name.as_str()));
    Ok(roots)
}

/// The merged listing, as `flatpak_xml_to_string` writes it.
fn serialize(components: Vec<Element>) -> String {
    let mut children = vec![Node::Text("\n  ".into())];
    children.extend(components.into_iter().map(Node::Element));
    children.push(Node::Text("\n".into()));
    let root =
        Element { name: "components".into(), attrs: vec![("version".into(), "0.8".into()), ("origin".into(), "flatpak".into())], children };
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write_element(&root, &mut out);
    out
}

fn write_element(element: &Element, out: &mut String) {
    out.push('<');
    out.push_str(&element.name);
    for (name, value) in &element.attrs {
        out.push(' ');
        out.push_str(name);
        out.push_str("=\"");
        escape(value, out);
        out.push('"');
    }
    if element.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    for child in &element.children {
        match child {
            Node::Element(element) => write_element(element, out),
            Node::Text(text) => escape(text, out),
        }
    }
    out.push_str("</");
    out.push_str(&element.name);
    out.push('>');
}

/// As `g_markup_escape_text` escapes.
fn escape(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            '\u{1}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}' | '\u{80}'..='\u{84}' | '\u{86}'..='\u{9f}' => {
                out.push_str(&format!("&#x{:x};", c as u32))
            }
            c => out.push(c),
        }
    }
}

/// The `[Application]` group of an app's `metadata`, which is all Flatpak
/// reads from it here.
struct Metadata(BTreeMap<String, String>);

impl Metadata {
    fn parse(text: &str) -> Metadata {
        let mut keys = BTreeMap::new();
        let mut in_group = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_group = line == "[Application]";
            } else if in_group && let Some((key, value)) = line.split_once('=') {
                keys.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        Metadata(keys)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ostree::delta;

    /// What `flatpak build-update-repo` 1.18 made of the fixture: see
    /// tests/fixtures/README.md.
    const APPSTREAM2_ROOT: &str = "01e4b410b785776c7a680c32a6c88649ce3d9b4a3936e54ce325892014298bf5";
    const ICONS: &str = "2ae73c79d3f1f859f18a5e6d5fc232add76cebb0642950dbdbbf98d0838975f9";

    fn hello(store: &Store, dir: &std::path::Path) -> Bundle {
        let path = dir.join("hello.flatpak");
        std::fs::write(&path, include_bytes!("../../tests/fixtures/hello.flatpak")).unwrap();
        delta::unpack(&path, store).unwrap()
    }

    #[test]
    fn makes_what_flatpak_makes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        let app = hello(&store, dir.path());
        let branches = build(&store, &[&app], 1_767_225_600).unwrap();
        let names: Vec<&str> = branches.iter().map(|branch| branch.ref_name.as_str()).collect();
        assert_eq!(names, ["appstream/x86_64", "appstream2/x86_64"]);

        let appstream2 = &branches[1];
        let (root, _) = super::super::commit_root(&store.read(Kind::Commit, &appstream2.commit).unwrap()).unwrap();
        assert_eq!(root, APPSTREAM2_ROOT);
        assert_eq!(appstream2.commit_size, 182);
        let xml = store.file_content(&store.lookup(&appstream2.commit, "appstream.xml").unwrap().unwrap(), MAX_FILE).unwrap();
        assert_eq!(String::from_utf8(xml).unwrap(), include_str!("../../tests/fixtures/hello.appstream.xml"));

        // The other branch has the same listing, gzipped, and the same icons.
        let appstream = &branches[0];
        let gz = store.file_content(&store.lookup(&appstream.commit, "appstream.xml.gz").unwrap().unwrap(), MAX_FILE).unwrap();
        let mut xml = String::new();
        GzDecoder::new(&gz[..]).read_to_string(&mut xml).unwrap();
        assert_eq!(xml, include_str!("../../tests/fixtures/hello.appstream.xml"));
        let (root, _) = super::super::commit_root(&store.read(Kind::Commit, &appstream.commit).unwrap()).unwrap();
        let tree = super::super::read_dirtree(&store.read(Kind::DirTree, &root).unwrap()).unwrap();
        assert_eq!(tree.dirs[0].1, ICONS);
        assert!(store.reachable(&appstream.commit).is_ok());

        // The same apps, the same commits.
        assert_eq!(build(&store, &[&app], 1_767_225_600).unwrap(), branches);
    }

    #[test]
    fn lists_no_app_it_cant_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("ostree")).unwrap();
        let app = hello(&store, dir.path());
        let renamed = Bundle { ref_name: "app/org.example.Other/x86_64/stable".into(), ..app };
        let branches = build(&store, &[&renamed], 1).unwrap();
        let xml = store.file_content(&store.lookup(&branches[1].commit, "appstream.xml").unwrap().unwrap(), MAX_FILE).unwrap();
        assert_eq!(
            String::from_utf8(xml).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<components version=\"0.8\" origin=\"flatpak\">\n  \n</components>"
        );
    }

    #[test]
    fn reads_and_writes_xml_as_glib_does() {
        let roots =
            parse("<?xml version=\"1.0\"?>\n<!-- c -->\n<a x=\"1 &amp; 2\"><b/>t&#x41;&lt;<![CDATA[<raw>]]><c>'\"</c></a>\n").unwrap();
        let mut out = String::new();
        write_element(&roots[0], &mut out);
        assert_eq!(out, "<a x=\"1 &amp; 2\"><b/>tA&lt;&lt;raw&gt;<c>&apos;&quot;</c></a>");
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a>&nbsp;</a>").is_err());
        assert!(parse(&format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH))).is_ok());
        assert!(parse(&"<a>".repeat(1_000_000)).is_err());
        let mut out = String::new();
        escape("\u{1}\u{85}\u{9f}é", &mut out);
        assert_eq!(out, "&#x1;\u{85}&#x9f;é");
    }
}

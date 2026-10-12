# npkg

apt, dnf, Flatpak and F-Droid repositories for software a team releases on
Nostr (NIP-82).
The gateway follows the NIP-82 events of the authors its config lists, and
each application they publish gets a repository, at `/apt/<owner>/<d>` and
`/rpm/<owner>/<d>`, that serves every package its releases list, under any
name, and an OSTree remote per channel at `/flatpak/<owner>/<d>/<channel>/`
for the Flatpak bundles they list, and an F-Droid repository at
`/fdroid/<owner>/<d>/repo` for the APKs. The owner is an npub or a NIP-05 address
(`alex@gleasonator.com`, or `soapbox.pub` for `_@soapbox.pub`). See
README.md for what's left out.

This is a spike: kept simple on purpose, and revised as we go. Nothing is
deployed yet, so there's no backwards compatibility to keep.

## Layout

```
src/
  main.rs        the CLI: keygen, serve
  config.rs      the TOML config file (npkg.example.toml)
  sync.rs        the sync worker: builds at startup from stored events,
                 follows the team live, resyncs every resync_interval
  http.rs        the routes, setup files, the status page, and release JSON
                 and downloads (/releases/<owner>/<d>); the client's address
  repo.rs        building a repository: inspect, select, pin, render; the
                 built ones, which requests read
  nip82.rs       reading applications, releases and assets from events
  nostr/         events, NIP-19 (both from npanel), NIP-05 lookups (stored,
                 refreshed daily, limited per client), relay queries and
                 subscriptions
  net.rs         keeping requests others point the gateway at (NIP-05
                 lookups, downloads) to public addresses
  rate_limit.rs  token buckets, after npanel's
  inspect/       reading a .deb's control file, an .rpm's header, and an
                 APK's manifest, ABIs and signers
  apt.rs         dists/<suite>/: Release, InRelease, Packages; the arches
  rpmmd.rs       repodata/: primary, filelists, other, repomd.xml
  fdroid.rs      F-Droid's index v2 and signed entry.jar, and each
                 application's P-256 key, derived from the gateway's
  der.rs         the DER of X.509 certificates and PKCS#7 signatures
  ostree/        Flatpak: unpacking bundles (delta.rs) into an archive-z2
                 object store, pruning it, publishing their commits as
                 a history (publish.rs), AppStream branches
                 (appstream.rs), and summaries (summary.rs)
  gvariant.rs    GLib's serialization, which OSTree's formats are made of
  signing.rs     the gateway's Ed25519 OpenPGP key, and secrets derived
                 from it
  db.rs          SQLite: the team's events, inspected package files,
                 unpacked bundles, published Flatpak commits, pins,
                 F-Droid index dates, icons, NIP-05 keys
tests/fixtures/  tiny real packages nfpm, flatpak and aapt2 built (see its
                 README)
```

## How a build goes

No request ever builds anything or waits on relays: the sync worker builds
repositories and swaps them in, and requests read what's there. Until the
first resync after startup finishes, a repository that isn't built yet is a
503, since it may yet turn up; after that, a 404.

- At startup, every repository is built from the stored events, without the
  network, in milliseconds.
- A live subscription stores each new event from the team and, once things
  have been quiet for a few seconds, rebuilds its author's repositories.
- Every `resync_interval`, everything is fetched from the relays again.

A rebuild of an author goes through each of their applications, and only
builds one whose snapshot (what its events say) changed, or, on a resync,
one that couldn't download a file last time. A failed build leaves the last
one up.

1. Read the application, its releases, and their assets from the stored
   events, which only ever hold events signed by a team member, and only the
   newest of each address. Asset events a release lists but the database
   lacks are fetched first.
2. Download each .deb, .rpm and .apk asset not seen before, check its sha256, read
   its metadata, and store that in SQLite by hash. A file's hash never
   changes, so this happens once per file. The file itself isn't kept:
   downloads are redirects.
   A .flatpak is downloaded to a temporary file and unpacked into the
   OSTree store instead, every object checked against its checksum; the
   commit it carried is stored in SQLite by the bundle's hash, and the
   bundle deleted.
3. Select the files an index can hold, each once, then pin: the first file
   for a package version (name, version, architecture, as the file says) is
   the one served from then on. An APK's version is its versionCode, and
   its architecture its ABIs.
4. Render and sign every channel. Indexes are dated by their newest release,
   not by the build, so rebuilding the same packages gives the same files
   and a client between two requests never sees hashes change underneath it.
   A channel's Flatpak remote publishes each ref's head as `flatpak
   build-commit-from` does: a commit of the bundle's tree on top of the last
   one published, dated after it, made only when the head's bundle changes
   (a ref seen first starts with every release, oldest first). The database
   keeps that history and never rewrites it, since clients hold its ids.
   The summary names each ref's last commit, and is dated by it, and its
   AppStream branches, made from those commits' AppStream data (with the
   remote's releases added for an app that lists none) and dated by the
   repository's newest commit, so the same apps give the same branches.
   F-Droid only reads an index dated later than the last it read, so an
   F-Droid index is dated by its newest event, or, if it changed with no
   newer one (say a file that failed to download, downloaded), a
   millisecond after the last one served, which the database keeps. Its
   icon is downloaded once and kept, since the index names its hash.

Once a day, after a resync, the sync worker prunes the OSTree store of
objects no current release's commit reaches, if they're over a day old.
Published commits themselves are kept, so a history lists withdrawn
releases too.

## Conventions

- Comments explain *why*, not *what*.
- No `unwrap()` on anything a relay, an author, or a request can influence.
- Nothing blocking on a runtime thread: SQLite through `Db::call`, parsing
  and signing through `spawn_blocking`.
- User-facing error strings are full sentences that say what to do next.
  They show up on the status page and in HTTP error bodies.

## Verifying changes

```sh
cargo clippy --all-targets    # no warnings
cargo fmt --check
cargo test
```

What the unit tests can't show is whether apt and dnf accept the result. To
check that, run the gateway and install a real package in containers:

```sh
cat > npkg.toml <<'EOF'   # once; gitignored
public_url = "http://127.0.0.1:8099"
bind = "127.0.0.1:8099"
data_dir = "data"
authors = ["npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj"]
EOF
cargo run -- -c npkg.toml keygen   # once
cargo run -- -c npkg.toml serve
N=npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj
podman run --rm --network host docker.io/library/debian:trixie bash -c "
  apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null &&
  curl -fsSL -o /etc/apt/sources.list.d/npanel.sources http://127.0.0.1:8099/apt/$N/npanel/source &&
  apt-get update && apt-get install -y npanel"
podman run --rm --network host docker.io/library/rockylinux:8 bash -c "
  curl -fsSL -o /etc/yum.repos.d/npanel.repo http://127.0.0.1:8099/rpm/$N/npanel/repo &&
  dnf -y install npanel"
```

This was last done against npanel 0.6.0 on debian:trixie, ubuntu:24.04,
fedora:latest and rockylinux:8, and against npanel 0.6.1 on debian:trixie
and rockylinux:8 from a gateway restarted with its relays unreachable.

For Flatpak, `flatpak install --user --no-deps --from <.flatpakref>` in a
fedora:latest container (with `--network host`, and `flatpak` installed) was
checked against Armada 0.64.7-0.64.11: install, `update --commit=` to an
older commit and back, `repair` after deleting an object, and an install
from a gateway restarted with its relays unreachable. An `ostree pull` from
0.64.7 to 0.64.11 fetched 9 objects (6 MB) of 599. `flatpak update
--appstream` then `flatpak search armada` found it, with its icons.

For F-Droid, the gateway with `public_url = "http://10.0.2.2:<port>"` was
added to F-Droid 2.0.1 on the Android emulator (the Pixel 3a API 34 AVD,
which runs arm64 APKs), by typing the repository URL with its
`?fingerprint=` into Add repository: F-Droid only opens `fdroidrepos://`
(https) links. It verified `entry.jar`, listed Armada with its icon and
description, and installed 0.64.11 from Blossom through the gateway.

## Committing

**Always commit after making changes.** Once a change passes the checks
above, commit it; don't leave work uncommitted at the end of a task. One
commit per coherent change, with a message in the style of `git log`: a
short subject saying what it does, and a body saying why when it isn't
obvious. If the tree already had unrelated uncommitted work, commit that
separately rather than folding it into yours.

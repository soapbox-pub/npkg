# npkg-gateway

apt and dnf repositories for software released on Nostr (NIP-82). Each
application's repository, at `/apt/<owner>/<d>` and `/rpm/<owner>/<d>`, serves
every package its releases list, under any name. The owner is an npub or a
NIP-05 address (`alex@gleasonator.com`, or `soapbox.pub` for `_@soapbox.pub`).
See README.md for what's left out.

This is a spike: kept simple on purpose, and revised as we go.

## Layout

```
src/
  main.rs        the CLI: keygen, serve
  config.rs      the TOML config file (npkg-gateway.example.toml)
  http.rs        the routes, setup files, the status page, and release JSON
                 and downloads (/releases/<owner>/<d>)
  repo.rs        building a repository: fetch, inspect, select, pin, render;
                 cached in memory and rebuilt in the background
  nip82.rs       application, release and asset events, fetched from relays
  nostr/         events, NIP-19 (both from npanel), NIP-05 lookups (stored,
                 and refreshed in the background), one-shot relay queries
  inspect/       reading a .deb's control file and an .rpm's header
  apt.rs         dists/<suite>/: Release, InRelease, Packages; the arches
  rpmmd.rs       repodata/: primary, filelists, other, repomd.xml
  signing.rs     the gateway's Ed25519 OpenPGP key
  db.rs          SQLite: inspected package files, pins, NIP-05 keys
tests/fixtures/  tiny real packages nfpm built (see its README)
```

## How a build goes

A request for a repository nobody has asked for yet waits while it's built.
After that it's served from memory and rebuilt in the background once it's
older than `ttl`; a failed rebuild keeps the last good one up.

1. Fetch the application, its releases, and their assets from the relays,
   keeping only events signed by the application's author.
2. Download each .deb and .rpm asset not seen before, check its sha256, read
   its metadata, and store that in SQLite by hash. A file's hash never
   changes, so this happens once per file.
3. Select the files an index can hold, each once, then pin: the first file
   for a package version (name, version, architecture, as the file says) is
   the one served from then on.
4. Render and sign every channel. Indexes are dated by their newest release,
   not by the build, so rebuilding the same packages gives the same files
   and a client between two requests never sees hashes change underneath it.

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
cat > npkg-gateway.toml <<'EOF'   # once; gitignored
public_url = "http://127.0.0.1:8099"
bind = "127.0.0.1:8099"
data_dir = "data"
EOF
cargo run -- -c npkg-gateway.toml keygen   # once
cargo run -- -c npkg-gateway.toml serve
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
fedora:latest and rockylinux:8.

## Committing

**Always commit after making changes.** Once a change passes the checks
above, commit it; don't leave work uncommitted at the end of a task. One
commit per coherent change, with a message in the style of `git log`: a
short subject saying what it does, and a body saying why when it isn't
obvious. If the tree already had unrelated uncommitted work, commit that
separately rather than folding it into yours.

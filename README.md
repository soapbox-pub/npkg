# npkg-gateway

apt and dnf repositories for software released on Nostr.

Every NIP-82 application
that publishes `.deb` or `.rpm` assets gets its own repository, addressed by
its author and its `d` tag:

```
/apt/<owner>/<d>     # Debian, Ubuntu
/rpm/<owner>/<d>     # Fedora, RHEL, Rocky
```

The owner is the author's npub, or a NIP-05 address that names them:
`alex@gleasonator.com`, or a bare domain like `soapbox.pub` for
`_@soapbox.pub`. Setup files keep whichever form they were asked for by.

Opening either path shows the repository's packages, the files it left out
and why, and how to add it:

```sh
# Debian, Ubuntu
sudo curl -fsSL -o /etc/apt/sources.list.d/npanel.sources \
  https://<host>/apt/npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/npanel/source
sudo apt update && sudo apt install npanel

# Fedora, RHEL
sudo curl -fsSL -o /etc/yum.repos.d/npanel.repo \
  https://<host>/rpm/npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/npanel/repo
sudo dnf install npanel
```

Add `?channel=beta` (or `nightly`, `dev`) to a setup URL to follow a
less stable channel.

## Release files

Every file an application's releases list, of any type, can also be
downloaded directly, the way GitHub's release URLs work, so a script can
fetch the latest build:

```sh
B=https://<host>/releases/<owner>/<d>
curl -fsSLO $B/latest/download/myapp-linux-x86_64.tar.gz   # latest stable
curl -fsSLO $B/download/1.2.0/myapp-linux-x86_64.tar.gz    # one release

# When file names have the version in them, pick one from the JSON:
B=https://<host>/releases/soapbox.pub/buzz.armada.app
curl -fsSL $B/latest | jq -r '.assets[] | select(.platforms | index("linux-x86_64"))
  | select(.content_type == "application/vnd.appimage") | .download_url'
```

| Path | |
|---|---|
| `/releases/<owner>/<d>` | every release as JSON, highest version first |
| `/releases/<owner>/<d>/latest` | the latest release |
| `/releases/<owner>/<d>/tags/<version>` | one release |
| `/releases/<owner>/<d>/latest/download/<name>` | a redirect to the latest release's file |
| `/releases/<owner>/<d>/download/<version>/<name>` | a redirect to a release's file |

A file's name is its asset's `filename` tag, or its sha256 if it has none;
either one works in a download URL. A release looks like this:

```json
{
  "version": "0.64.11",
  "channel": "stable",
  "prerelease": false,
  "published_at": "2026-10-10T03:27:34Z",
  "notes": "…",
  "assets": [{
    "name": "Armada-v0.64.11.apk",
    "size": 10327052,
    "content_type": "application/vnd.android.package-archive",
    "sha256": "bb745014…",
    "platforms": ["android-arm64-v8a", "android-armeabi-v7a"],
    "download_url": "https://<host>/releases/…/download/0.64.11/Armada-v0.64.11.apk"
  }]
}
```

The latest release is the highest version, compared the way semver does,
on the stable channel. A prerelease version like `1.2.0-rc.1` isn't the
latest there even if its author tagged it `main`. Add `?channel=beta` (or
`nightly`, `dev`) to `latest` to include less stable releases and
prereleases.

## What a repository serves

Every `.deb` and `.rpm` its application's releases list, under whatever
names the files give themselves, the way a PPA serves whatever its owner
uploads. An application can ship several packages, and its packages needn't
be named after it: `buzz.armada.app`'s repository serves `armada-desktop`.
What a package is comes from the file itself, not from the release or the
asset's tags.

- A file is left out if an index can't hold it: a `.deb` for an
  architecture other than `amd64`, `arm64`, `armhf`, `riscv64` or `all`, or
  a name dpkg or rpm wouldn't accept.
- The first file served for a package version (name, version and
  architecture) stays. A later file claiming the same version, whether from
  a republished release or another release, is left out: apt and dnf refuse
  a version whose file changed under them.
- A file listed by more than one release is served once, in the most stable
  of their channels.

The channels are `stable`, `beta`, `nightly` and `dev`: an apt suite or a
dnf repository each. Each one includes every more stable channel, so `beta`
has the stable releases too. `stable` holds the releases NIP-82 tags `main`.

## Trust

apt and dnf can't check Nostr signatures. The gateway checks each event's
signature and each file's sha256, and then signs the repository metadata
(`InRelease`, `repomd.xml`) with its own Ed25519 OpenPGP key. Users who add a
repository are trusting the gateway to have done that, and the author as
much as any third-party repository: the author can publish any package,
under any name. Package downloads are redirects to Blossom: apt and dnf
check each file against the hash in the signed index, so the server a file
comes from doesn't need to be trusted.

Release files are different. The gateway doesn't download them, and
nothing checks them on the way down: a download is a redirect to the URL
the author's asset gives, or to a Blossom server by its hash. Check the
file against the `sha256` in the release's JSON, which comes from the
author's signed event.

A repository added by NIP-05 address follows the address: the gateway looks
it up again every few minutes, so whoever controls the domain decides whose
packages its users get. Add it by npub to pin the author instead. The lookup
only goes to public-looking domain names (no IP addresses, ports, or
single-label hosts), but the gateway doesn't check where those resolve to:
run it where it can't reach anything private.

## Running it

```sh
cargo build --release
sudo install -D -m 644 npkg-gateway.example.toml /etc/npkg-gateway/npkg-gateway.toml
sudoedit /etc/npkg-gateway/npkg-gateway.toml   # set public_url
sudo ./target/release/npkg-gateway keygen
sudo ./target/release/npkg-gateway serve
```

The config file is the one `--config` names, or else the first of
`~/.config/npkg-gateway/npkg-gateway.toml` and
`/etc/npkg-gateway/npkg-gateway.toml`. Only `public_url` is required;
`npkg-gateway.example.toml` lists every setting (the listen address, relays,
Blossom servers, rebuild interval) with its default. Set `authors` to a list
of npubs to serve only their repositories; anyone else's gets a 403.

`keygen` writes `signing-key.asc` into `data_dir` (`/var/lib/npkg-gateway`
as root) once. Back it up: every user's setup trusts that key.

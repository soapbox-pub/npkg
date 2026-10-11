# npkg-gateway

apt, dnf and Flatpak repositories for software a team releases on Nostr.

The gateway follows the NIP-82 events of the authors its operator lists, and
every application they publish gets its own repository, addressed by its
author and its `d` tag:

```
/apt/<owner>/<d>       # Debian, Ubuntu
/rpm/<owner>/<d>       # Fedora, RHEL, Rocky
/flatpak/<owner>/<d>   # any Linux, through Flatpak
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

```sh
# Flatpak
flatpak install --user \
  https://<host>/flatpak/soapbox.pub/buzz.armada.app/buzz.armada.app.flatpakref
```

Add `?channel=beta` (or `nightly`, `dev`) to a setup URL to follow a
less stable channel. The gateway's front page lists every repository.

## How it stays current

The gateway subscribes to the team's NIP-82 events on its relays, so a
release shows up in its repositories seconds after it's published. It also
fetches everything again every hour (`resync_interval`), in case it missed
an event while a relay was down, and tries again any file it couldn't
download. Requests are served from memory and never wait on relays.

The events are stored, so a restart serves exactly what was served before,
without the network, and then catches up.

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

## Flatpak

A release's `.flatpak` bundles (`application/vnd.flatpak` assets) are
unpacked into an OSTree repository, so the app can be installed and updated
with `flatpak` like any other remote's: an update fetches only the files
that changed, `flatpak repair` and `flatpak update --commit=` work, and the
bundle is checked, object by object, before anyone installs it.

Each channel is a remote of its own, at `/flatpak/<owner>/<d>/<channel>/`,
holding the newest commit of each app on it: the one from the release
`/releases/…/latest` would pick, for each architecture. A `.flatpakref`
(`/flatpak/<owner>/<d>/<anything>.flatpakref`, with `?channel=`) installs
the app and adds the remote; a `.flatpakrepo` only adds the remote. The
runtime an app needs comes from Flathub, which the `.flatpakref` names.

Every commit any release lists is kept, so downgrades work; objects nothing
needs any more are pruned once a day.

Each remote also has AppStream branches (`appstream/<arch>` and
`appstream2/<arch>`), made the way `flatpak build-update-repo` makes them,
so GNOME Software, Discover and `flatpak search` show its apps with their
names, descriptions and icons. They're made from the AppStream data
`flatpak-builder` puts in each app, `files/share/app-info/`; an app built
without it installs, but isn't listed.

The channels are `stable`, `beta`, `nightly` and `dev`: an apt suite or a
dnf repository each. Each one includes every more stable channel, so `beta`
has the stable releases too. `stable` holds the releases NIP-82 tags `main`.

## Trust

apt, dnf and Flatpak can't check Nostr signatures. The gateway checks each
event's signature and each file's sha256, and then signs the repository
metadata (`InRelease`, `repomd.xml`, a Flatpak remote's summary and
commits) with its own Ed25519 OpenPGP key. Users who add a
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

Events dated more than ten minutes ahead of the gateway's clock are left
until their time comes. One dated far ahead would stand over every later
release of its address, and date the indexes in the future, which apt
refuses.

If an author's key is stolen, take it off `authors` and restart: the
gateway forgets their events, and their repositories go. Deletion events
(NIP-09) aren't followed, so there's no withdrawing a release while the key
is on the team, short of publishing it again, later, with no assets; and a
package version the thief published first stays pinned to their file (see
above), so a fix has to be a new version. Under a new key, the author's
repositories start afresh, pins included.

A repository added by NIP-05 address follows the address: the gateway looks
it up again once a day, so whoever controls the domain decides whose
packages its users get, as long as it's someone on the team. Add it by npub
to pin the author instead. A key is kept until the domain's `nostr.json`
stops listing the name or names someone off the team; a domain that's down
or broken leaves it as it was, through restarts too.

Looking up an address the gateway doesn't know yet is the one thing a
request can make it do upstream, so those lookups are limited, per client
and overall. A client is its IPv4 address, or its IPv6 /64. Behind a
reverse proxy on the same machine, the client is the address the proxy adds
last to `X-Forwarded-For`, which the proxy has to set: `X-Real-IP` isn't
read. The lookup only goes to
domain names (no IP addresses, ports, or single-label hosts) that resolve
to public addresses.

Package files and bundles are downloaded from the URL the author gives, if
it's https at a public address, and then from the configured Blossom
servers. Redirects are followed, up to five, only to public https URLs. The
Blossom servers themselves may be anywhere: they're the operator's.

## Running it

```sh
cargo build --release
sudo install -D -m 644 npkg-gateway.example.toml /etc/npkg-gateway/npkg-gateway.toml
sudoedit /etc/npkg-gateway/npkg-gateway.toml   # set public_url and authors
sudo ./target/release/npkg-gateway keygen
sudo ./target/release/npkg-gateway serve
```

The config file is the one `--config` names, or else the first of
`~/.config/npkg-gateway/npkg-gateway.toml` and
`/etc/npkg-gateway/npkg-gateway.toml`. `public_url` and `authors`, the npubs
on the team, are required; `npkg-gateway.example.toml` lists every setting
(the listen address, relays, Blossom servers, resync interval) with its
default. An author taken off the list has their events forgotten at the next
start.

The first start downloads every `.deb`, `.rpm` and `.flatpak` the team has
released, once. Of a `.deb` or `.rpm`, only what it is is kept: package
downloads are redirects to Blossom. A `.flatpak` is unpacked into
`data_dir/ostree`, which Flatpak remotes are served from, and that takes
disk: about one copy of each app, plus what changed in each release.

`keygen` writes `signing-key.asc` into `data_dir` (`/var/lib/npkg-gateway`
as root) once. Back it up: every user's setup trusts that key.

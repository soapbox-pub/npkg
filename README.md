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

A repository added by NIP-05 address follows the address: the gateway looks
it up again every few minutes, so whoever controls the domain decides whose
packages its users get. Add it by npub to pin the author instead. The lookup
only goes to public-looking domain names (no IP addresses, ports, or
single-label hosts), but the gateway doesn't check where those resolve to:
run it where it can't reach anything private.

## Running it

```sh
cargo build --release
./target/release/npkg-gateway --data data keygen
./target/release/npkg-gateway --data data serve --listen 127.0.0.1:8080 \
  --public-url https://pkg.example.com
```

`keygen` writes `data/signing-key.asc` once. Back it up: every user's setup
trusts that key. `serve --help` lists the relays and Blossom servers it uses
by default.

# npkg-gateway

apt and dnf repositories for software released on Nostr.

Every NIP-82 application
that publishes `.deb` or `.rpm` assets gets its own repository, addressed by
its author and its `d` tag:

```
/apt/<npub>/<d>     # Debian, Ubuntu
/rpm/<npub>/<d>     # Fedora, RHEL, Rocky
```

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

An application is one package. Its repository serves the package named
after its `d` tag, and nothing else:

- The package's own name (`Package:` / `Name:`) must be the `d` tag.
- Its version must be the release's version, with a pre-release written
  `~pre`, the way nfpm writes it: release `0.3.0-rc.1` means package
  `0.3.0~rc.1`.
- Its architecture must match its asset's `f` tag (`linux-x86_64` is
  `amd64` / `x86_64`), unless the package is `all` / `noarch`.
- It may not reach other packages: no `Replaces` and no `Obsoletes`, and
  `Provides` only its own name.
- A release has one file per format and architecture. If there's more than
  one, none of them is served.
- The first file served for a version and architecture stays. If a release
  is republished with a different file, the new file is ignored.

Each NIP-82 channel is a suite (apt) or a repository (dnf), and each one
includes every more stable channel: `beta` has `main`'s releases too. apt's
`stable` is NIP-82's `main`.

## Trust

apt and dnf can't check Nostr signatures. The gateway checks each event's
signature and each file's sha256, and then signs the repository metadata
(`InRelease`, `repomd.xml`) with its own Ed25519 OpenPGP key. Users who add a
repository are trusting the gateway to have done that, as well as the
package's author. Package downloads are redirects to Blossom: apt and dnf
check each file against the hash in the signed index, so the server a file
comes from doesn't need to be trusted.

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

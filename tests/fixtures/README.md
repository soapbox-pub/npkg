# Test fixtures

`hello-1.2.0-rc.1.x86_64.rpm` and `hello_1.2.0-rc.1_amd64.deb` are tiny real
packages, built by nfpm from `src/`, the way the release workflows of npanel,
ditto-relay and armada-stack build theirs. To rebuild them:

```sh
cd tests/fixtures
for format in rpm deb; do
  podman run --rm -v "$PWD:/w:Z" -w /w/src -e VERSION=1.2.0-rc.1 \
    docker.io/goreleaser/nfpm:latest pkg -p "$format" -t /w/
done
mv 'hello-1.2.0~rc.1-1.x86_64.rpm' hello-1.2.0-rc.1.x86_64.rpm
mv 'hello_1.2.0~rc.1_amd64.deb' hello_1.2.0-rc.1_amd64.deb
```

`hello.flatpak` is a tiny real Flatpak bundle, made by `flatpak build-export`
and `flatpak build-bundle` 1.18 from an app with a script, a text file, a
symlink and an empty file. It needs no runtime installed to build.
`hello.objects` lists the objects `build-export` wrote to its repository,
which unpacking the bundle has to reproduce exactly. To rebuild them, on
Fedora with `flatpak` and `ostree` installed:

```sh
mkdir -p app/files/bin app/files/share/hello
printf '[Application]\nname=org.example.Hello\nruntime=org.freedesktop.Platform/x86_64/25.08\nsdk=org.freedesktop.Sdk/x86_64/25.08\n' > app/metadata
printf '#!/bin/sh\necho hello\n' > app/files/bin/hello && chmod 755 app/files/bin/hello
echo "some data" > app/files/share/hello/data.txt
ln -s data.txt app/files/share/hello/link.txt
: > app/files/share/hello/empty
flatpak build-finish app --command=hello --share=network
ostree init --repo=repo --mode=archive-z2
flatpak build-export -s "Hello fixture" --timestamp=2026-01-01T00:00:00Z repo app stable
flatpak build-bundle repo hello.flatpak org.example.Hello stable
(cd repo/objects && find . -type f | sed 's|^\./||; s|/||' | sort) > hello.objects
```

A rebuild gives a different commit (it records the build's Flatpak version),
so the tests' expected commit changes with it.

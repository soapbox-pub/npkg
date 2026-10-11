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
symlink, an empty file, tags, and AppStream data with icons: one component
to keep, with a `<bundle>` to replace, a comment and entities, and one
belonging to another app. It needs no runtime installed to build.
`hello.objects` lists the objects `build-export` wrote to its repository,
which unpacking the bundle has to reproduce exactly. `hello.appstream.xml`
is the `appstream.xml` `flatpak build-update-repo` then made, and
`src/ostree/appstream.rs` holds the checksums of the tree it made it in.
To rebuild them, on Fedora with `flatpak` and `ostree` installed:

```sh
mkdir -p app/files/bin app/files/share/hello app/files/share/app-info/xmls \
  app/files/share/app-info/icons/flatpak/64x64 app/files/share/app-info/icons/flatpak/128x128
printf '[Application]\nname=org.example.Hello\nruntime=org.freedesktop.Platform/x86_64/25.08\nsdk=org.freedesktop.Sdk/x86_64/25.08\ntags=beta;test;\n' > app/metadata
printf '#!/bin/sh\necho hello\n' > app/files/bin/hello && chmod 755 app/files/bin/hello
echo "some data" > app/files/share/hello/data.txt
ln -s data.txt app/files/share/hello/link.txt
: > app/files/share/hello/empty
cat > hello.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!-- made by hand -->
<components version="0.16" origin="flatpak">
  <component type="desktop-application">
    <id>org.example.Hello.desktop</id>
    <name>Hello &amp; "friends"</name>
    <summary xml:lang="de">Grüß dich</summary>
    <summary>Says hello</summary>
    <bundle type="flatpak">app/wrong/x86_64/stable</bundle>
    <icon type="cached" height="64" width="64">org.example.Hello.desktop.png</icon>
    <description><p>A <em>tiny</em> app.</p></description>
    <launchable type="desktop-id">org.example.Hello.desktop</launchable>
  </component>
  <component type="addon">
    <id>org.other.Thing</id>
  </component>
</components>
XML
gzip -9n -c hello.xml > app/files/share/app-info/xmls/org.example.Hello.xml.gz
printf '\x89PNG\r\n\x1a\nsixty-four' > app/files/share/app-info/icons/flatpak/64x64/org.example.Hello.desktop.png
printf '\x89PNG\r\n\x1a\none-twenty-eight' > app/files/share/app-info/icons/flatpak/128x128/org.example.Hello.desktop.png
flatpak build-finish app --command=hello --share=network
ostree init --repo=repo --mode=archive-z2
flatpak build-export -s "Hello fixture" --timestamp=2026-01-01T00:00:00Z repo app stable
flatpak build-bundle repo hello.flatpak org.example.Hello stable
(cd repo/objects && find . -type f | sed 's|^\./||; s|/||' | sort) > hello.objects
flatpak build-update-repo repo
ostree --repo=repo cat appstream2/x86_64 /appstream.xml > hello.appstream.xml
ostree --repo=repo ls -RC appstream2/x86_64   # the checksums of / and /icons
```

A rebuild gives a different commit (it records the build's Flatpak version),
so the tests' expected commit changes with it.

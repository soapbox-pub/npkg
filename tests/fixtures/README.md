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

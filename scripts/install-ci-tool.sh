#!/bin/sh
# Install checksum-pinned upstream binaries without compiling CI tooling from source.
set -eu

tool=${1:?usage: install-ci-tool.sh cargo-deny|cargo-zigbuild}
case "$tool" in
    cargo-deny)
        version=0.22.1
        requested=${CARGO_DENY_VERSION:-$version}
        checksum=13f7e825e9cb811c2f8de63f29b0f45851dfb53004029f0f2501af524728364d
        url="https://github.com/EmbarkStudios/cargo-deny/releases/download/$version/cargo-deny-$version-x86_64-unknown-linux-musl.tar.gz"
        ;;
    cargo-zigbuild)
        version=0.24.1
        requested=${CARGO_ZIGBUILD_VERSION:-$version}
        checksum=f09b180a517af0e4dd4bffc921bb88e5ab705452a9dd948c61e489b3020c68c2
        url="https://github.com/rust-cross/cargo-zigbuild/releases/download/v$version/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz"
        ;;
    *) echo "unsupported CI tool: $tool" >&2; exit 1 ;;
esac
[ "$requested" = "$version" ] || { echo "update the pinned checksum for $tool $requested" >&2; exit 1; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo 'CI tool binaries require Linux x86_64' >&2; exit 1; }
root="${CI_TOOLS_ROOT:-$HOME/.local}/$tool-$version"
if [ ! -x "$root/bin/$tool" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM
    curl -fsSL --connect-timeout 20 --max-time 180 --retry 2 "$url" -o "$tmp/archive"
    echo "$checksum  $tmp/archive" | sha256sum --check --strict
    tar -xf "$tmp/archive" -C "$tmp"
    binary=$(find "$tmp" -type f -name "$tool" -print -quit)
    [ -n "$binary" ] || { echo "archive has no $tool binary" >&2; exit 1; }
    mkdir -p "$root/bin"
    install -m 755 "$binary" "$root/bin/$tool"
fi
"$root/bin/$tool" --version
if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$root/bin" >> "$GITHUB_PATH"
fi

#!/bin/sh
# Install checksum-pinned upstream binaries without compiling CI tooling from source.
set -eu

tool=${1:?usage: install-ci-tool.sh cargo-deny|cargo-zigbuild|cargo-nextest|typos|zizmor}
platform="$(uname -s)-$(uname -m)"
case "$tool:$platform" in
    cargo-deny:Linux-x86_64)
        version=0.22.1
        requested=${CARGO_DENY_VERSION:-$version}
        checksum=13f7e825e9cb811c2f8de63f29b0f45851dfb53004029f0f2501af524728364d
        url="https://github.com/EmbarkStudios/cargo-deny/releases/download/$version/cargo-deny-$version-x86_64-unknown-linux-musl.tar.gz"
        ;;
    cargo-zigbuild:Linux-x86_64)
        version=0.24.1
        requested=${CARGO_ZIGBUILD_VERSION:-$version}
        checksum=f09b180a517af0e4dd4bffc921bb88e5ab705452a9dd948c61e489b3020c68c2
        url="https://github.com/rust-cross/cargo-zigbuild/releases/download/v$version/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz"
        ;;
    cargo-nextest:Linux-x86_64)
        version=0.9.152
        requested=${CARGO_NEXTEST_VERSION:-$version}
        checksum=521c5f790ed07ee69d0a88403d9d86a8c8ab27977f12fc73f22aa4e7e14a0f71
        url="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$version/cargo-nextest-$version-x86_64-unknown-linux-musl.tar.gz"
        ;;
    cargo-nextest:Linux-aarch64)
        version=0.9.152
        requested=${CARGO_NEXTEST_VERSION:-$version}
        checksum=f168dbfe9c9c3a4b247cf10d9c260f3dac90a1373f5c4b1bfd3b0b8ac8d77095
        url="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$version/cargo-nextest-$version-aarch64-unknown-linux-musl.tar.gz"
        ;;
    typos:Linux-x86_64)
        version=1.52.2
        requested=${TYPOS_VERSION:-$version}
        checksum=3b13d1291281d39d01822e54035636487a7a0f228e70097899b1e33aeb0e7e93
        url="https://github.com/crate-ci/typos/releases/download/v$version/typos-v$version-x86_64-unknown-linux-musl.tar.gz"
        ;;
    zizmor:Linux-x86_64)
        version=1.32.0
        requested=${ZIZMOR_VERSION:-$version}
        checksum=bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b
        url="https://github.com/zizmorcore/zizmor/releases/download/v$version/zizmor-x86_64-unknown-linux-gnu.tar.gz"
        ;;
    cargo-deny:* | cargo-zigbuild:* | cargo-nextest:* | typos:* | zizmor:*)
        echo "no pinned $tool binary for $platform" >&2
        exit 1
        ;;
    *) echo "unsupported CI tool: $tool" >&2; exit 1 ;;
esac
[ "$requested" = "$version" ] || { echo "update the pinned checksum for $tool $requested" >&2; exit 1; }
root="${CI_TOOLS_ROOT:-$HOME/.local}/$tool-$version"
if [ ! -x "$root/bin/$tool" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM
    curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 20 --max-time 180 --retry 2 "$url" -o "$tmp/archive"
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

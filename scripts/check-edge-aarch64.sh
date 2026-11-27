#!/bin/sh
# CI check (build-and-test.md §3–§4, edge-unifi.md §1): build the edge binaries for the gateway,
# aarch64-unknown-linux-gnu against glibc 2.41 (the oldest supported UniFi OS, Debian 13), and
# check each one:
#   - it is a 64-bit little-endian aarch64 ELF;
#   - its highest GLIBC_x.y symbol version (`objdump -T`) is at most 2.41;
#   - every NEEDED library is in the allowlist below: glibc is the only shared library, TLS is
#     compiled in (libgcc_s is allowed for Rust's unwinder, though zig links its own statically).
#
# Usage: scripts/check-edge-aarch64.sh
# Builds picket-edge, picket-edge-helper and picket-edge-update with
# `cargo zigbuild --release --locked --target aarch64-unknown-linux-gnu.2.41` into the usual
# target directory (CARGO_TARGET_DIR is respected), then checks
# <target-dir>/aarch64-unknown-linux-gnu/release/<binary>. Safe to re-run: it writes nothing outside
# the target directory.
#
# Needs: zig and cargo-zigbuild (CI pins ZIG_VERSION and CARGO_ZIGBUILD_VERSION in
# .github/workflows/ci.yml), the toolchain's aarch64-unknown-linux-gnu target, and an objdump that
# reads aarch64 ELF: $OBJDUMP if set, else aarch64-linux-gnu-objdump, llvm-objdump on PATH, the
# toolchain's llvm-objdump (`rustup component add llvm-tools`), or a multiarch objdump.
set -eu

cd "$(dirname "$0")/.."

rust_target=aarch64-unknown-linux-gnu
glibc_max=2.41
zig_target="$rust_target.$glibc_max"
binaries="picket-edge picket-edge-helper picket-edge-update"
needed_allowed="libc.so.6 libm.so.6 libgcc_s.so.1 ld-linux-aarch64.so.1"

fail() {
    echo "check-edge-aarch64: $*" >&2
    exit 1
}

# Tools.
zig="${CARGO_ZIGBUILD_ZIG_PATH:-zig}"
if ! "$zig" version >/dev/null 2>&1; then
    fail "zig is missing (looked for '$zig'); install the pinned version from https://ziglang.org/download/ and put it on PATH"
fi
if ! cargo zigbuild --help >/dev/null 2>&1; then
    fail "cargo-zigbuild is missing; install it with: cargo install cargo-zigbuild --version 0.24.1 --locked"
fi
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$rust_target"; then
    fail "the toolchain lacks $rust_target; add it with: rustup target add $rust_target"
fi

reads_aarch64() {
    case "$1" in
        *llvm-objdump | *aarch64-linux-gnu-objdump) "$1" --version >/dev/null 2>&1 ;;
        *) "$1" -i 2>/dev/null | grep -q aarch64 ;;
    esac
}
objdump=""
if [ -n "${OBJDUMP:-}" ]; then
    objdump="$OBJDUMP"
else
    sysroot_objdump="$(rustc --print sysroot 2>/dev/null)/lib/rustlib/$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')/bin/llvm-objdump"
    for candidate in aarch64-linux-gnu-objdump llvm-objdump "$sysroot_objdump" objdump; do
        if command -v "$candidate" >/dev/null 2>&1 && reads_aarch64 "$candidate"; then
            objdump="$candidate"
            break
        fi
    done
fi
[ -n "$objdump" ] || fail "no objdump that reads aarch64 ELF; install binutils-aarch64-linux-gnu or run: rustup component add llvm-tools"

# Build.
zigbuild_version=$(cargo-zigbuild --version 2>/dev/null || echo "cargo-zigbuild (version unknown)")
echo "check-edge-aarch64: zig $("$zig" version), $zigbuild_version, objdump: $objdump"
set --
for bin in $binaries; do
    set -- "$@" -p "$bin"
done
cargo zigbuild --release --locked --target "$zig_target" "$@"

target_dir=$(cargo metadata --format-version 1 --no-deps --locked | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
[ -n "$target_dir" ] || fail "cargo metadata gave no target directory"
out="$target_dir/$rust_target/release"

# Checks.
errors=0
for bin in $binaries; do
    path="$out/$bin"
    if [ ! -f "$path" ]; then
        echo "check-edge-aarch64: $bin: not built at $path" >&2
        errors=$((errors + 1))
        continue
    fi

    # ELF magic, ELFCLASS64, ELFDATA2LSB, e_machine EM_AARCH64 (183 = 0xb7, little-endian).
    header=$(od -An -tx1 -N20 "$path" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')
    case "$header" in
        "7f 45 4c 46 02 01 "*" b7 00") arch=aarch64 ;;
        *)
            echo "check-edge-aarch64: $bin: not a 64-bit little-endian aarch64 ELF (header: $header)" >&2
            errors=$((errors + 1))
            continue
            ;;
    esac

    glibc=$("$objdump" -T "$path" | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/^GLIBC_//' | sort -u -V | tail -n 1)
    if [ -z "$glibc" ]; then
        echo "check-edge-aarch64: $bin: no GLIBC symbol versions found by $objdump -T" >&2
        errors=$((errors + 1))
    elif [ "$(printf '%s\n%s\n' "$glibc" "$glibc_max" | sort -V | tail -n 1)" != "$glibc_max" ]; then
        echo "check-edge-aarch64: $bin: needs GLIBC_$glibc, above the $glibc_max floor; symbols:" >&2
        "$objdump" -T "$path" | grep -F "GLIBC_$glibc" | sed 's/^/    /' >&2
        errors=$((errors + 1))
    fi

    needed=$("$objdump" -p "$path" | sed -n 's/^ *NEEDED *//p')
    bad=""
    for lib in $needed; do
        case " $needed_allowed " in
            *" $lib "*) ;;
            *) bad="$bad $lib" ;;
        esac
    done
    if [ -n "$bad" ]; then
        echo "check-edge-aarch64: $bin: NEEDED libraries outside the allowlist ($needed_allowed):$bad" >&2
        errors=$((errors + 1))
    fi

    size=$(wc -c <"$path" | tr -d ' ')
    echo "check-edge-aarch64: $bin: $arch, $size bytes, highest GLIBC_${glibc:-?}, NEEDED:" $needed
done

if [ "$errors" -ne 0 ]; then
    fail "$errors problem(s) found"
fi
echo "check-edge-aarch64: all edge binaries are aarch64, need at most GLIBC_$glibc_max and link only allowlisted libraries"

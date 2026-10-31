#!/bin/sh
# AddressSanitizer test run (nightly). Rust code is instrumented; C/C++ deps
# (BoringSSL via boring-sys) are built uninstrumented because zig ships no
# sanitizer runtime (ci/zigcc strips -fsanitize and passes rustc's runtime
# archive through). Requires the zig toolchain env used for normal builds.
#
#   ci/asan.sh [cargo test args...]    e.g. ci/asan.sh -p honk-outbound --lib
set -eu
: "${CARGO_TARGET_DIR:=target/asan}"
export CARGO_TARGET_DIR
export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=address"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -Zsanitizer=address"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}"
[ "$#" -gt 0 ] || set -- --workspace
exec cargo +nightly test --target x86_64-unknown-linux-gnu "$@"

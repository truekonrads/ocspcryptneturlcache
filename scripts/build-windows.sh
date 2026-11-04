#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
case "$target" in
  x86_64-pc-windows-msvc|aarch64-pc-windows-msvc) ;;
  *) echo "Usage: bash scripts/build-windows.sh <x86_64-pc-windows-msvc|aarch64-pc-windows-msvc>" >&2; exit 2 ;;
esac

cd "$(git rev-parse --show-toplevel)"
# SDK/CRT versions validated with cargo-xwin 0.23.1 and clang/LLD 14.
export XWIN_SDK_VERSION=10.0.26100
export XWIN_CRT_VERSION=14.44.17.14
# cargo-xwin's cache marker does not check SDK/CRT versions on reuse.
export XWIN_CACHE_DIR="${XWIN_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/cargo-xwin/0.23.1-sdk-$XWIN_SDK_VERSION-crt-$XWIN_CRT_VERSION}"
rustup target add "$target"
cargo xwin cache xwin

config=()
if [[ "$target" == aarch64-pc-windows-msvc ]]; then
  # ring 0.17 uses clang on ARM64, which rejects clang-cl's /imsvc flags.
  # Force the cc-rs target flags instead of concatenating with xwin's flags.
  # Shell quoting plus TOML encoding preserves cache paths containing spaces.
  export CC_SHELL_ESCAPED_FLAGS=1
  cflags=$(python3 - <<'PY'
import json
import os
import shlex

flags = ["--target=aarch64-pc-windows-msvc", "-Wno-unused-command-line-argument"]
for directory in ["crt/include", "sdk/include/ucrt", "sdk/include/um", "sdk/include/shared", "sdk/include/winrt"]:
    flags.extend(["-isystem", os.path.join(os.environ["XWIN_CACHE_DIR"], "xwin", directory)])
print("env.CFLAGS_aarch64_pc_windows_msvc.value=" + json.dumps(shlex.join(flags)))
PY
  )
  config=(--config "$cflags" --config 'env.CFLAGS_aarch64_pc_windows_msvc.force=true')
fi

cargo xwin build --release --locked --target "$target" "${config[@]}"

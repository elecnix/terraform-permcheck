#!/usr/bin/env bash
# Installs terraform-permcheck for action.yml into $RUNNER_TEMP and writes
# its path to $GITHUB_OUTPUT as `path`. It never changes PATH or GITHUB_PATH,
# so later steps in the caller's job see the tools they had before.
#
# When the action runs from a release tag (uses: owner/repo@vX.Y.Z), it
# downloads that release's archive and checks it against checksums.txt from
# the same release. Otherwise, or when the release has no archive for this
# runner, it builds from the action's source: with the `go` already on PATH
# when there is one, else with a Go toolchain it downloads into $RUNNER_TEMP
# and checks against the published SHA-256.
#
# Inputs, from the environment: ACTION_REF, ACTION_REPOSITORY, ACTION_PATH,
# RUNNER_TEMP, RUNNER_OS, RUNNER_ARCH, GITHUB_OUTPUT. RELEASE_BASE_URL
# replaces https://github.com/$ACTION_REPOSITORY/releases/download, for tests.
set -euo pipefail

dest="$RUNNER_TEMP/terraform-permcheck-action"
mkdir -p "$dest"

case "$RUNNER_OS" in
  Linux) os=linux ;;
  macOS) os=darwin ;;
  Windows) os=windows ;;
  *) echo "::error::unsupported runner OS $RUNNER_OS"; exit 1 ;;
esac
case "$RUNNER_ARCH" in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *) echo "::error::unsupported runner architecture $RUNNER_ARCH"; exit 1 ;;
esac
exe=""
ext=tar.gz
if [ "$os" = windows ]; then
  exe=.exe
  ext=zip
fi
bin="$dest/terraform-permcheck$exe"

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

unpack() { # archive dir
  if [ "$ext" = zip ]; then
    unzip -q -o "$1" -d "$2"
  else
    tar -xzf "$1" -C "$2"
  fi
}

# download_release prints nothing and returns 1 when the release has no
# archive for this runner, so the caller can build instead. A checksum
# mismatch is fatal: the archive is not the one the release published.
download_release() {
  local tag="$1" version="${1#v}" base archive tmp want got
  base="${RELEASE_BASE_URL:-https://github.com/$ACTION_REPOSITORY/releases/download}/$tag"
  archive="terraform-permcheck_${version}_${os}_${arch}.$ext"
  tmp="$(mktemp -d "$RUNNER_TEMP/terraform-permcheck-dl.XXXXXX")"
  if ! curl -fsSL --retry 3 -o "$tmp/$archive" "$base/$archive" ||
     ! curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt"; then
    echo "No release archive $archive for $tag; building from source."
    rm -rf "$tmp"
    return 1
  fi
  want="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
  got="$(sha256 "$tmp/$archive")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "::error::$archive does not match checksums.txt of $tag (want '${want}', got '$got')"
    exit 1
  fi
  # errexit is off inside a function called from an if, so check each step.
  unpack "$tmp/$archive" "$tmp" || { echo "::error::cannot unpack $archive"; exit 1; }
  mv "$tmp/terraform-permcheck$exe" "$bin" || { echo "::error::$archive holds no terraform-permcheck$exe"; exit 1; }
  rm -rf "$tmp"
  echo "Installed terraform-permcheck $tag from the release archive."
}

# go_toolchain prints the Go version that go.mod asks for: the toolchain
# line, else the go line.
go_toolchain() {
  local v
  v="$(sed -n 's/^toolchain go\([0-9.]*\).*/\1/p' "$ACTION_PATH/go.mod")"
  [ -n "$v" ] || v="$(sed -n 's/^go \([0-9.]*\).*/\1/p' "$ACTION_PATH/go.mod")"
  echo "$v"
}

build_from_source() {
  local go_bin=go v url tmp want got
  if ! command -v go >/dev/null; then
    v="$(go_toolchain)"
    url="https://dl.google.com/go/go$v.$os-$arch.$ext"
    tmp="$(mktemp -d "$RUNNER_TEMP/terraform-permcheck-go.XXXXXX")"
    echo "Downloading Go $v into $tmp to build terraform-permcheck."
    curl -fsSL --retry 3 -o "$tmp/go.$ext" "$url"
    want="$(curl -fsSL --retry 3 "$url.sha256")"
    got="$(sha256 "$tmp/go.$ext")"
    if [ "$want" != "$got" ]; then
      echo "::error::Go $v archive does not match its published SHA-256"
      exit 1
    fi
    unpack "$tmp/go.$ext" "$tmp"
    go_bin="$tmp/go/bin/go$exe"
    export GOTOOLCHAIN=local GOROOT="$tmp/go"
    export GOPATH="$tmp/gopath" GOCACHE="$tmp/gocache"
  fi
  (cd "$ACTION_PATH" && CGO_ENABLED=0 "$go_bin" build -trimpath -o "$bin" .)
  echo "Built terraform-permcheck from $ACTION_PATH."
}

if [[ "${ACTION_REF:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ -n "${ACTION_REPOSITORY:-}" ] &&
   download_release "$ACTION_REF"; then
  :
else
  build_from_source
fi

"$bin" version
echo "path=$bin" >> "$GITHUB_OUTPUT"

#!/usr/bin/env bash
# Fetch the geosite.dat / geoip.dat versions pinned in .github/ci/pins.env,
# verify their sha256, and install them where the geo tests read them.
#
# Usage: ci/fetch-geodata.sh [DEST_DIR]
#   DEST_DIR defaults to $DAE_LOCATION_ASSET, else the checkout root (which
#   `routing::tests::use_repo_geo_assets()` points DAE_LOCATION_ASSET at).
# Existing files whose checksum already matches are kept.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dest=${1:-${DAE_LOCATION_ASSET:-$root}}
# shellcheck source=/dev/null
source "$root/.github/ci/pins.env"
: "${GEOSITE_TAG:?}" "${GEOSITE_SHA256:?}" "${GEOIP_TAG:?}" "${GEOIP_SHA256:?}"

mkdir -p "$dest"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() {
  local url=$1 sha256=$2 name=$3
  if [[ -f "$dest/$name" ]] && printf '%s  %s\n' "$sha256" "$dest/$name" | sha256sum -c --status -; then
    echo "$name: up to date"
    return
  fi
  echo "$name: downloading $url"
  curl -fsSL --retry 3 --retry-all-errors -o "$tmp/$name" "$url"
  printf '%s  %s\n' "$sha256" "$tmp/$name" | sha256sum -c --quiet - \
    || { echo "$name: sha256 mismatch" >&2; exit 1; }
  mv "$tmp/$name" "$dest/$name"
  echo "$name: installed to $dest/$name"
}

fetch "https://github.com/v2fly/domain-list-community/releases/download/$GEOSITE_TAG/dlc.dat" "$GEOSITE_SHA256" geosite.dat
fetch "https://github.com/v2fly/geoip/releases/download/$GEOIP_TAG/geoip.dat" "$GEOIP_SHA256" geoip.dat

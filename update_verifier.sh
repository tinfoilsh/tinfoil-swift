#!/bin/bash
# Pins Package.swift to a tinfoil-go release of Tinfoil.xcframework and
# commits the change.
#
# Usage: ./update_verifier.sh [tag]
#   tag  the release to pin, such as v0.17.0; defaults to the newest release
set -euo pipefail
cd "$(dirname "$0")"

repo=tinfoilsh/tinfoil-go
tag="${1:-$(curl -fsSL "https://api.github.com/repos/$repo/releases" |
    jq -r '[.[] | select(.tag_name | test("^v[0-9]"))][0].tag_name')}"
if [[ -z "$tag" || "$tag" == null ]]; then
    echo "no tinfoil-go release found" >&2
    exit 1
fi
url="https://github.com/$repo/releases/download/$tag/Tinfoil.xcframework.zip"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/framework.zip" "$url"
curl -fsSL -o "$work/framework.zip.sha256" "$url.sha256"
checksum="$(shasum -a 256 "$work/framework.zip" | cut -d ' ' -f 1)"
published="$(cut -d ' ' -f 1 "$work/framework.zip.sha256")"
if [[ "$checksum" != "$published" ]]; then
    echo "downloaded checksum $checksum does not match the published $published" >&2
    exit 1
fi

# Replace the Tinfoil binary target's release tag and checksum together, so
# the pin cannot end up naming one release with another's checksum.
TAG="$tag" CHECKSUM="$checksum" perl -0pi -e '
    s{(\Qgithub.com/tinfoilsh/tinfoil-go/releases/download/\E)[^/"]+(/Tinfoil\.xcframework\.zip",\s*checksum:\s*")[0-9a-f]{64}"}{$1$ENV{TAG}$2$ENV{CHECKSUM}"}
' Package.swift
if ! grep -qF "releases/download/$tag/Tinfoil.xcframework.zip" Package.swift ||
    ! grep -qF "checksum: \"$checksum\"" Package.swift; then
    echo "could not update the Tinfoil binary target in Package.swift" >&2
    exit 1
fi

if git diff --quiet -- Package.swift; then
    echo "Package.swift already pins tinfoil-go $tag"
    exit 0
fi
git commit -q -m "chore: pin tinfoil-go $tag" -- Package.swift
echo "Pinned tinfoil-go $tag ($checksum) and committed Package.swift; push when ready."

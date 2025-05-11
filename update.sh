#!/bin/bash
set -e

LATEST_TAG=$(curl -sL https://api.github.com/repos/tinfoilsh/verifier/releases/latest | jq -r ".tag_name")

ZIP_FILE="verifier-$LATEST_TAG.zip"
if [ ! -f "$ZIP_FILE" ]; then
    wget -O "$ZIP_FILE" "https://github.com/tinfoilsh/verifier/releases/download/$LATEST_TAG/TinfoilVerifier.xcframework.zip"
fi

CHECKSUM=$(sha256sum "$ZIP_FILE" | cut -d ' ' -f 1)

echo "Verifier framework $LATEST_TAG checksum: $CHECKSUM"

sed -i '.bak' -E "s|(url: \"https://github.com/tinfoilsh/verifier/releases/download/)v[0-9]+\.[0-9]+\.[0-9]+(/TinfoilVerifier.xcframework.zip\")|\1$LATEST_TAG\2|" Package.swift
sed -i '.bak' -E "s/(checksum: \")[a-f0-9]+(\")/\1$CHECKSUM\2/" Package.swift
sed -i '.bak' -E "s|\.package\(url: \"https://github\.com/tinfoilsh/verifier-swift\", exact: \"[0-9]+\.[0-9]+\.[0-9]+\"|\.package\(url: \"https://github\.com/tinfoilsh/verifier-swift\", exact: \"${LATEST_TAG#v}\"|" README.md

git add .
git commit -m "chore: bump verifier "
echo "Update completed and commit created. Push to remote."
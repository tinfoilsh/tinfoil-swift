#!/bin/bash
set -e

LATEST_TAG=$(curl -sL https://api.github.com/repos/tinfoilsh/tinfoil-go/releases | jq -r '[.[] | select(.tag_name | test("^v[0-9]"))][0].tag_name')

ZIP_FILE="tinfoil-${LATEST_TAG}.zip"
if [ ! -f "$ZIP_FILE" ]; then
    wget -O "$ZIP_FILE" "https://github.com/tinfoilsh/tinfoil-go/releases/download/$LATEST_TAG/Tinfoil.xcframework.zip"
fi

CHECKSUM=$(sha256sum "$ZIP_FILE" | cut -d ' ' -f 1)

echo "Tinfoil framework $LATEST_TAG checksum: $CHECKSUM"

sed -i '.bak' -E "s|(url: \"https://github.com/tinfoilsh/tinfoil-go/releases/download/)v[0-9]+\.[0-9]+\.[0-9]+(/Tinfoil.xcframework.zip\")|\1$LATEST_TAG\2|" Package.swift
sed -i '.bak' -E "s/(checksum: \")[a-f0-9]+(\")/\1$CHECKSUM\2/" Package.swift

git add .
git commit -m "chore: bump verifier "
echo "Update completed and commit created. Push to remote."

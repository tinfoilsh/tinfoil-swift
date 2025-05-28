#!/bin/bash
set -e

# Function to update verifier dependency
update_verifier() {
    echo "Updating verifier dependency..."
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
    git commit -m "chore: bump verifier to $LATEST_TAG"
}

# Function to update TinfoilKit version
update_version() {
    if [ -z "$1" ]; then
        echo "Error: Please provide a version number (e.g., 0.0.6)"
        echo "Usage: $0 version <version_number>"
        exit 1
    fi
    
    NEW_VERSION="$1"
    echo "Updating TinfoilKit version to $NEW_VERSION..."
    
    # Update podspec version
    sed -i '.bak' -E "s/(s\.version[[:space:]]*=[[:space:]]*')[^']+(')/\1$NEW_VERSION\2/" TinfoilKit.podspec
    
    # Create git tag
    git add TinfoilKit.podspec
    git commit -m "chore: bump version to $NEW_VERSION"
    git tag "v$NEW_VERSION"
    
    echo "Version updated to $NEW_VERSION and tagged as v$NEW_VERSION"
}

# Main script logic
case "$1" in
    "verifier")
        update_verifier
        ;;
    "version")
        update_version "$2"
        ;;
    *)
        echo "Usage: $0 {verifier|version <version_number>}"
        echo "  verifier          - Update verifier dependency to latest release"
        echo "  version <number>  - Update TinfoilKit version (e.g., $0 version 0.0.6)"
        exit 1
        ;;
esac

echo "Update completed and commit created. Push to remote when ready."
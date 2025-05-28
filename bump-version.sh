#!/bin/bash
set -e

# Function to get the latest version from git tags
get_latest_version() {
    git tag --sort=-version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 | sed 's/^v//'
}

# Function to increment version
increment_version() {
    local version=$1
    local type=$2
    
    IFS='.' read -ra VERSION_PARTS <<< "$version"
    major=${VERSION_PARTS[0]}
    minor=${VERSION_PARTS[1]}
    patch=${VERSION_PARTS[2]}
    
    case $type in
        "major")
            ((major++))
            minor=0
            patch=0
            ;;
        "minor")
            ((minor++))
            patch=0
            ;;
        "patch"|*)
            ((patch++))
            ;;
    esac
    
    echo "$major.$minor.$patch"
}

# Main script
case "$1" in
    "major"|"minor"|"patch")
        CURRENT_VERSION=$(get_latest_version)
        if [ -z "$CURRENT_VERSION" ]; then
            echo "No existing version tags found. Starting with 0.0.1"
            NEW_VERSION="0.0.1"
        else
            echo "Current version: $CURRENT_VERSION"
            NEW_VERSION=$(increment_version "$CURRENT_VERSION" "$1")
        fi
        
        echo "Bumping version to: $NEW_VERSION"
        ./update.sh version "$NEW_VERSION"
        ;;
    *)
        echo "Usage: $0 {major|minor|patch}"
        echo "  major - Increment major version (1.0.0 -> 2.0.0)"
        echo "  minor - Increment minor version (1.0.0 -> 1.1.0)"
        echo "  patch - Increment patch version (1.0.0 -> 1.0.1)"
        echo ""
        echo "Current version: $(get_latest_version || echo 'No version tags found')"
        exit 1
        ;;
esac 
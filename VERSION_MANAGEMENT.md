# Version Management for TinfoilKit

This document describes how to automatically update version numbers for the TinfoilKit package.

## Scripts

### 1. `update.sh` - Manual Version Updates

This script allows you to manually update versions or dependencies.

**Usage:**
```bash
# Update verifier dependency to latest release
./update.sh verifier

# Update TinfoilKit version manually
./update.sh version 0.0.6
```

### 2. `bump-version.sh` - Automatic Version Bumping

This script automatically determines the next version number based on semantic versioning.

**Usage:**
```bash
# Increment patch version (0.0.4 -> 0.0.5)
./bump-version.sh patch

# Increment minor version (0.0.4 -> 0.1.0)
./bump-version.sh minor

# Increment major version (0.0.4 -> 1.0.0)
./bump-version.sh major
```

## What Gets Updated

When you update the version, the following files are automatically updated:

1. **`TinfoilKit.podspec`** - The version field gets updated
2. **Git tags** - A new version tag is created (e.g., `v0.0.5`)
3. **Git commits** - Changes are committed automatically

## Workflow

### For Regular Updates (Recommended)
```bash
# For bug fixes
./bump-version.sh patch

# For new features
./bump-version.sh minor

# For breaking changes
./bump-version.sh major
```

### For Manual Control
```bash
./update.sh version 1.2.3
```

### For Verifier Dependency Updates
```bash
./update.sh verifier
```

## Publishing to CocoaPods

After updating the version:

1. **Push to Git:**
   ```bash
   git push origin main
   git push origin --tags
   ```

2. **Publish to CocoaPods:**
   ```bash
   pod spec lint TinfoilKit.podspec
   pod trunk push TinfoilKit.podspec
   ```

## Current Setup

- **Current Version:** Based on latest git tag
- **Platform:** iOS 17.0+
- **Swift Version:** 5.9
- **Dependencies:** OpenAIKit, TinfoilVerifier (binary framework)

The podspec is configured to automatically use the version number for git tags, ensuring consistency between your package version and git releases. 
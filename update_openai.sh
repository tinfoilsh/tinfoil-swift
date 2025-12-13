#!/bin/bash
set -e

LATEST_TAG=$(curl -sL https://api.github.com/repos/MacPaw/OpenAI/releases/latest | jq -r ".tag_name")

echo "OpenAI package latest version: $LATEST_TAG"

sed -i '.bak' -E "s|(url: \"https://github.com/MacPaw/OpenAI.git\", exact: \")[0-9]+\.[0-9]+\.[0-9]+(\")|\1$LATEST_TAG\2|" Package.swift

git add .
git commit -m "chore: bump openai"
echo "Update completed and commit created. Push to remote."

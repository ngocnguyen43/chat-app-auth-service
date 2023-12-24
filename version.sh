#!/bin/bash

current_version=$1
IFS='.' read -ra version_parts <<< "$current_version"
major="${version_parts[0]}"
minor="${version_parts[1]}"
patch="${version_parts[2]}"

# Increment patch version
patch=$((patch + 1))

echo "$major.$minor.$patch"

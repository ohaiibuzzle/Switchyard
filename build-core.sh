#!/bin/sh
# Rebuilds app/libs/core.aar from core/ (needs gomobile: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init)
set -e
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | tail -1)}"
export PATH="$PATH:$(go env GOPATH)/bin"
cd "$(dirname "$0")/core"
gomobile bind -target=android/arm64,android/amd64 -androidapi 29 -ldflags="-s -w" -javapkg=snf -o ../app/libs/core.aar .

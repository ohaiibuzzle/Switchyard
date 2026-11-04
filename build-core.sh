#!/bin/sh
# Rebuilds app/libs/core.aar from core/ (needs gomobile: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init)
set -e
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | tail -1)}"
export PATH="$PATH:$(go env GOPATH)/bin"
cd "$(dirname "$0")/core"
# gomobile builds leave out VCS info, so Tailscale's version reads "x.y.z-ERR-BuildInfo" unless stamped
tsv=$(go list -m -f '{{.Version}}' tailscale.com); tsv=${tsv#v}
mkdir -p ../app/libs # git-ignored, so missing on a fresh checkout; gomobile won't create it
gomobile bind -target=android/arm64,android/amd64 -androidapi 29 -ldflags="-s -w -X tailscale.com/version.shortStamp=$tsv -X tailscale.com/version.longStamp=$tsv-g$(git rev-parse --short=9 HEAD)" -javapkg=snf -o ../app/libs/core.aar .

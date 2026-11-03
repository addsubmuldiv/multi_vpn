#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-0.1.0}"
ARCH="$(uname -m)"
case "$ARCH" in arm64|x86_64) ;; *) exit 1 ;; esac
python scripts/build_app.py --version "$VERSION"
dist/MultiVPN.app/Contents/MacOS/MultiVPN --self-test
lipo dist/MultiVPN.app/Contents/MacOS/MultiVPN -verify_arch "$ARCH"
codesign --verify --deep --strict dist/MultiVPN.app
mkdir -p dist/installers build/pkg-root/Applications
ditto dist/MultiVPN.app build/pkg-root/Applications/MultiVPN.app
pkgbuild --root build/pkg-root --identifier io.github.addsubmuldiv.multivpn \
  --version "$VERSION" --install-location / --ownership recommended \
  "dist/installers/MultiVPN-${VERSION}-macos-${ARCH}.pkg"
mkdir -p build/dmg
ditto dist/MultiVPN.app build/dmg/MultiVPN.app
ln -s /Applications build/dmg/Applications
hdiutil create -volname 'Multi VPN' -srcfolder build/dmg -ov -format UDZO \
  "dist/installers/MultiVPN-${VERSION}-macos-${ARCH}.dmg"

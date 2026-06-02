#!/bin/bash
# Run this ON LINUX after building the Go binary
# Usage: bash build-deb.sh
set -e

BINARY="../agent/linux-agent"
PKG_DIR="pkg-build"
VERSION="1.0.0"

if [[ ! -f "$BINARY" ]]; then
  echo "Binary not found. Build first: cd ../agent && GOOS=linux GOARCH=amd64 go build -o linux-agent ."
  exit 1
fi

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/local/bin"
mkdir -p "$PKG_DIR/etc/linux-agent"
mkdir -p "$PKG_DIR/etc/systemd/system"

cp DEBIAN/control  "$PKG_DIR/DEBIAN/"
cp DEBIAN/postinst "$PKG_DIR/DEBIAN/"
chmod 755 "$PKG_DIR/DEBIAN/postinst"

cp "$BINARY" "$PKG_DIR/usr/local/bin/linux-agent"
chmod 755 "$PKG_DIR/usr/local/bin/linux-agent"

cp ../deploy/linux-agent.service "$PKG_DIR/etc/systemd/system/"
cp ../deploy/linux-agent.timer   "$PKG_DIR/etc/systemd/system/"

# Default config file
echo "# Set your API Gateway endpoint below" > "$PKG_DIR/etc/linux-agent/config"
echo "AGENT_API_ENDPOINT=" >> "$PKG_DIR/etc/linux-agent/config"
chmod 640 "$PKG_DIR/etc/linux-agent/config"

dpkg-deb --build "$PKG_DIR" "linux-security-agent_${VERSION}_amd64.deb"
echo "Package built: linux-security-agent_${VERSION}_amd64.deb"
echo "Install with: sudo dpkg -i linux-security-agent_${VERSION}_amd64.deb"

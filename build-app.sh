#!/bin/sh
# Builds the menu bar app (ResProxy.app) next to resproxy.py.
set -e
cd "$(dirname "$0")"
mkdir -p ResProxy.app/Contents/MacOS
cat > ResProxy.app/Contents/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ResProxy</string>
<key>CFBundleIdentifier</key><string>local.resproxy</string>
<key>CFBundleName</key><string>ResProxy</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
swiftc -O MenuBar.swift -o ResProxy.app/Contents/MacOS/ResProxy
codesign -s - --force ResProxy.app
echo "Built ResProxy.app. Open it to get the menu bar switch."

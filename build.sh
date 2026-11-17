#!/usr/bin/env bash
# Сборка VPN Auto: Windows (программа + установщик), macOS (универсальный .app),
# архив для раздачи и SHA256SUMS.txt для автообновления.
# Нужно: Go 1.24+, python3, zip, curl. Работает на Linux/macOS/WSL.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(sed -n 's/.*appVersion = "\([^"]*\)".*/\1/p' app/main.go)
SETUPVER=$(sed -n 's/^const version = "\([^"]*\)".*/\1/p' setup/main.go)
[ "$VERSION" = "$SETUPVER" ] || { echo "версии не совпадают: app $VERSION, setup $SETUPVER"; exit 1; }
echo "== VPN Auto $VERSION"

export CGO_ENABLED=0
rm -rf dist build/mac build/bundle
mkdir -p dist build/mac build/bundle/Windows build/bundle/macOS

# значки в ресурсах exe
python3 assets/mksyso.py app/rsrc_windows_amd64.syso assets/icon.ico assets/icon_off.ico >/dev/null
python3 assets/mksyso.py setup/rsrc_windows_amd64.syso assets/icon.ico >/dev/null
cp assets/icon.ico setup/icon.ico

# сторонние компоненты, вшиваемые в установщик (в репозиторий не кладём)
if [ ! -s setup/zapret.zip ]; then
  tag=$(curl -fsSL https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  echo "-- запрет $tag"
  curl -fL -o setup/zapret.zip "https://github.com/Flowseal/zapret-discord-youtube/releases/download/$tag/zapret-discord-youtube-$tag.zip"
fi
if [ ! -s setup/TgWsProxy.exe ]; then
  url=$(curl -fsSL https://api.github.com/repos/Flowseal/tg-ws-proxy/releases/latest | grep -o '"browser_download_url": *"[^"]*\.exe"' | head -1 | sed 's/.*"\(http[^"]*\)"/\1/')
  echo "-- TG WS Proxy: $url"
  curl -fL -o setup/TgWsProxy.exe "$url"
fi

go test ./app

# Windows
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" -o setup/VPNAuto.exe ./app
(cd setup && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" -o ../dist/VPN-Auto-Setup.exe .)
rm -f setup/VPNAuto.exe

# macOS (Intel + Apple Silicon в одном файле)
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o build/vpnauto-amd64 ./app
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o build/vpnauto-arm64 ./app
APP="build/mac/VPN Auto.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
python3 tools/fatmacho.py "$APP/Contents/MacOS/VPNAuto" build/vpnauto-amd64 build/vpnauto-arm64
chmod +x "$APP/Contents/MacOS/VPNAuto"
sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
cp packaging/macos/PkgInfo "$APP/Contents/PkgInfo"
cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
(cd build/mac && zip -qry -X ../../dist/VPN-Auto-macOS.zip "VPN Auto.app")

# архив для раздачи: Windows + macOS + инструкция
cp dist/VPN-Auto-Setup.exe build/bundle/Windows/
cp -a "$APP" build/bundle/macOS/
cp "packaging/Как установить.txt" build/bundle/
(cd build/bundle && zip -qry -X "../../dist/VPN-Auto-$VERSION.zip" Windows macOS "Как установить.txt")

# контрольные суммы для автообновления
(cd dist && sha256sum VPN-Auto-Setup.exe VPN-Auto-macOS.zip "VPN-Auto-$VERSION.zip" > SHA256SUMS.txt)
echo "== готово: dist/"
ls -la dist

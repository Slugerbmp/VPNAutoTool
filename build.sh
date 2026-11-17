#!/usr/bin/env bash
# Сборка NETtool: Windows (программа + установщик), macOS (универсальный .app),
# архив для раздачи и SHA256SUMS.txt для автообновления.
# Нужно: Go 1.24+, python3, zip. Работает на Linux/macOS/WSL.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(sed -n 's/.*appVersion = "\([^"]*\)".*/\1/p' app/main.go)
SETUPVER=$(sed -n 's/^const version = "\([^"]*\)".*/\1/p' setup/main.go)
[ "$VERSION" = "$SETUPVER" ] || { echo "версии не совпадают: app $VERSION, setup $SETUPVER"; exit 1; }
echo "== NETtool $VERSION"

export CGO_ENABLED=0
rm -rf dist build/mac build/bundle
mkdir -p dist build/mac build/bundle/Windows build/bundle/macOS

# значки в ресурсах exe
# значки + сведения о файле (версия, автор undr) + манифест — меньше ложных срабатываний антивирусов
python3 assets/mksyso.py app/rsrc_windows_amd64.syso assets/icon.ico assets/icon_off.ico \
  --ver "$VERSION" --file VPNAuto.exe --desc "NETtool — автовыбор VPN-сервера, запрет и WARP" >/dev/null
python3 assets/mksyso.py setup/rsrc_windows_amd64.syso assets/icon.ico \
  --ver "$VERSION" --file NETtool-Setup.exe --desc "Установщик NETtool" >/dev/null
cp assets/icon.ico setup/icon.ico

# запрет и TG WS Proxy в установщик не вшиваются: программа скачивает их с GitHub авторов
# (вшитые WinDivert и PyInstaller-сборка давали ложные срабатывания антивирусов)

go test ./app

# Windows
# без -s -w: неурезанные exe реже получают «эвристические» ложные срабатывания антивирусов
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui" -o setup/VPNAuto.exe ./app
(cd setup && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui" -o ../dist/NETtool-Setup.exe .)
rm -f setup/VPNAuto.exe

# macOS (Intel + Apple Silicon в одном файле)
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o build/vpnauto-amd64 ./app
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o build/vpnauto-arm64 ./app
APP="build/mac/NETtool.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
python3 tools/fatmacho.py "$APP/Contents/MacOS/VPNAuto" build/vpnauto-amd64 build/vpnauto-arm64
chmod +x "$APP/Contents/MacOS/VPNAuto"
sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
cp packaging/macos/PkgInfo "$APP/Contents/PkgInfo"
cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
(cd build/mac && zip -qry -X ../../dist/NETtool-macOS.zip "NETtool.app")

# архив для раздачи: Windows + macOS + инструкция
cp dist/NETtool-Setup.exe build/bundle/Windows/
cp -a "$APP" build/bundle/macOS/
cp "packaging/Как установить.txt" build/bundle/
(cd build/bundle && zip -qry -X "../../dist/NETtool-$VERSION.zip" Windows macOS "Как установить.txt")

# контрольные суммы для автообновления
# копии под прежними именами — чтобы обновились программы версий 1.10–1.11 (они ищут эти файлы)
cp dist/NETtool-Setup.exe dist/VPN-Auto-Setup.exe
cp dist/NETtool-macOS.zip dist/VPN-Auto-macOS.zip
(cd dist && sha256sum NETtool-Setup.exe NETtool-macOS.zip "NETtool-$VERSION.zip" VPN-Auto-Setup.exe VPN-Auto-macOS.zip > SHA256SUMS.txt)
echo "== готово: dist/"
ls -la dist

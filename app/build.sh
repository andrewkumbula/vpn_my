#!/usr/bin/env bash
# Собирает vpnctl.app — настоящее macOS-приложение вокруг морды.
# Только системные средства: swiftc из Xcode CLT, sips/iconutil для иконки,
# codesign (ad-hoc) — без него на Apple Silicon приложение просто не запустится.
#
# Пересобирать после правок app/main.swift. Саму морду (ui_page.html,
# ui_server.py) пересобирать не нужно — приложение читает их из репозитория.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${REPO_DIR}/app/vpnctl.app"
CONTENTS="${APP_DIR}/Contents"

echo "Собираю ${APP_DIR}"
rm -rf "$APP_DIR"
mkdir -p "${CONTENTS}/MacOS" "${CONTENTS}/Resources"

# --- бинарь ------------------------------------------------------------------
swiftc -O "${REPO_DIR}/app/main.swift" -o "${CONTENTS}/MacOS/vpnctl"

# --- Info.plist --------------------------------------------------------------
# VPNCTLRepoDir — чтобы .app знал, где лежит ui_server.py, куда бы его ни
# перенесли (в /Applications, например).
cat > "${CONTENTS}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>vpnctl</string>
  <key>CFBundleDisplayName</key><string>vpnctl</string>
  <key>CFBundleIdentifier</key><string>local.vpnctl.app</string>
  <key>CFBundleExecutable</key><string>vpnctl</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleIconFile</key><string>vpnctl</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>VPNCTLRepoDir</key><string>${REPO_DIR}</string>
</dict>
</plist>
PLIST

# --- иконка ------------------------------------------------------------------
# Рисуем простой значок системными средствами, чтобы не тащить в репозиторий
# бинарный .icns и не зависеть от внешних картинок.
ICONSET="$(mktemp -d)/vpnctl.iconset"
mkdir -p "$ICONSET"
PNG_BASE="$(mktemp -d)/base.png"
/usr/bin/python3 - "$PNG_BASE" <<'PYICON'
import struct, sys, zlib

РАЗМЕР = 1024
ФОН = (16, 18, 22)
ЗЕЛЁНЫЙ = (87, 199, 133)

пиксели = bytearray()
центр = РАЗМЕР / 2
внешний, внутренний = РАЗМЕР * 0.40, РАЗМЕР * 0.22
for y in range(РАЗМЕР):
    пиксели.append(0)  # фильтр строки PNG
    for x in range(РАЗМЕР):
        dx, dy = x - центр, y - центр
        r = (dx * dx + dy * dy) ** 0.5
        # кольцо + вертикальная «щель» сверху — узнаваемый значок питания
        в_кольце = внутренний <= r <= внешний
        в_щели = abs(dx) < РАЗМЕР * 0.045 and dy < 0
        линия = abs(dx) < РАЗМЕР * 0.045 and -внешний * 1.05 < dy < -внутренний * 0.2
        цвет = ЗЕЛЁНЫЙ if ((в_кольце and not в_щели) or линия) else ФОН
        пиксели.extend(цвет)

def кусок(тип, данные):
    сырое = тип + данные
    return struct.pack(">I", len(данные)) + сырое + struct.pack(">I", zlib.crc32(сырое))

png = (b"\x89PNG\r\n\x1a\n"
       + кусок(b"IHDR", struct.pack(">IIBBBBB", РАЗМЕР, РАЗМЕР, 8, 2, 0, 0, 0))
       + кусок(b"IDAT", zlib.compress(bytes(пиксели), 9))
       + кусок(b"IEND", b""))
open(sys.argv[1], "wb").write(png)
PYICON

for SIZE in 16 32 64 128 256 512; do
  sips -z $SIZE $SIZE "$PNG_BASE" --out "${ICONSET}/icon_${SIZE}x${SIZE}.png" >/dev/null 2>&1
  DOUBLE=$((SIZE * 2))
  sips -z $DOUBLE $DOUBLE "$PNG_BASE" --out "${ICONSET}/icon_${SIZE}x${SIZE}@2x.png" >/dev/null 2>&1
done
iconutil -c icns "$ICONSET" -o "${CONTENTS}/Resources/vpnctl.icns"

# --- подпись -----------------------------------------------------------------
# Ad-hoc: на Apple Silicon неподписанный бинарь ядро не запустит вообще.
codesign --force --deep --sign - "$APP_DIR"
codesign --verify --strict "$APP_DIR"

echo "Готово: ${APP_DIR}"
echo "Открыть:      open '${APP_DIR}'"
echo "Положить в Dock: перетащи из Finder, или скопируй в /Applications"

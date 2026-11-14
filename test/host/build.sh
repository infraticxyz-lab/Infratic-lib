#!/usr/bin/env bash
# Builds Infratic-lib on the host (no ESP32 needed) against Arduino stubs,
# real ArduinoJson 6, mbedtls 2.28 and rweather/Crypto, then runs the tests.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$(cd "$HERE/../.." && pwd)"
DEPS="${DEPS:-$HERE/.deps}"
OUT="$HERE/.build"
mkdir -p "$DEPS" "$OUT"

fetch() { [ -d "$DEPS/$1" ] || git clone -q --depth 1 ${3:+-b "$3"} "$2" "$DEPS/$1"; }
fetch ArduinoJson https://github.com/bblanchon/ArduinoJson.git v6.21.5
fetch mbedtls https://github.com/Mbed-TLS/mbedtls.git v2.28.8
fetch arduinolibs https://github.com/rweather/arduinolibs.git

CRYPTO="$DEPS/arduinolibs/libraries/Crypto"
MBED="$DEPS/mbedtls"
CXXFLAGS="-std=${CXXSTD:-gnu++17} -O1 -g -Wall -Wno-unused-function -Wno-sign-compare -Wno-format -ffunction-sections -fdata-sections \
  -DARDUINO=10819 -DARDUINOJSON_ENABLE_ARDUINO_STREAM=0 -DARDUINOJSON_ENABLE_ARDUINO_PRINT=0 \
  -DARDUINOJSON_ENABLE_PROGMEM=0 -DARDUINOJSON_ENABLE_ARDUINO_STRING=1 -DARDUINOJSON_ENABLE_STD_STRING=1 \
  -I$HERE/stubs -I$LIB/src -I$DEPS/ArduinoJson/src -I$MBED/include -I$CRYPTO"

objs=()
cc_c() { local o="$OUT/$(basename "$1").o"; [ "$o" -nt "$1" ] || gcc -O1 -ffunction-sections -fdata-sections -I$MBED/include -c "$1" -o "$o"; objs+=("$o"); }
cc_x() { local o="$OUT/$(basename "$1").o"; g++ $CXXFLAGS ${2:-} -c "$1" -o "$o"; objs+=("$o"); }

for f in sha256 sha512 base64 platform_util constant_time; do cc_c "$MBED/library/$f.c"; done
for f in Ed25519 SHA512 Hash BigNumberUtil Curve25519 Crypto; do cc_x "$CRYPTO/$f.cpp" "-w"; done
cc_x "$HERE/stubs/runtime.cpp"
cc_x "$LIB/src/base58.cpp"
cc_x "$LIB/src/Infratic-lib.cpp" "-Werror=return-type"
cc_x "$HERE/test_main.cpp"
g++ -o "$OUT/infratic_tests" "${objs[@]}" -Wl,--gc-sections
echo "build ok"
"$OUT/infratic_tests" "$HERE/vectors.json"

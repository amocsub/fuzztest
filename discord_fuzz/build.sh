#!/usr/bin/env bash
# Build the Discord Social SDK AFL++ fuzzer
# Usage: ./build.sh [debug|release]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$SCRIPT_DIR/sdk"
BUILD_DIR="$SCRIPT_DIR/build"

MODE="${1:-release}"
echo "[*] Building Discord fuzz harness (mode=$MODE) ..."

mkdir -p "$BUILD_DIR"

# Choose SDK lib variant
if [ "$MODE" = "debug" ]; then
    LIB="$SDK_DIR/lib/debug/libdiscord_partner_sdk.so"
else
    LIB="$SDK_DIR/lib/release/libdiscord_partner_sdk.so"
fi

if [ ! -f "$LIB" ]; then
    echo "[-] Library not found: $LIB"
    exit 1
fi

# Copy the .so next to the binary so LD_LIBRARY_PATH works easily
cp "$LIB" "$BUILD_DIR/libdiscord_partner_sdk.so"

afl-clang-fast++ \
    -std=c++17 \
    -g -O1 \
    -fsanitize=address,undefined \
    -fno-omit-frame-pointer \
    -I"$SDK_DIR/include" \
    "$SCRIPT_DIR/fuzz_discord_activity.cc" \
    /usr/lib/afl/libAFLDriver.a \
    -L"$BUILD_DIR" \
    -ldiscord_partner_sdk \
    -Wl,-rpath,'$ORIGIN' \
    -o "$BUILD_DIR/fuzz_discord_activity"

echo "[+] Built: $BUILD_DIR/fuzz_discord_activity"
echo ""
echo "Run fuzzer with:"
echo "  export LD_LIBRARY_PATH=$BUILD_DIR"
echo "  afl-fuzz -i $SCRIPT_DIR/corpus -o $BUILD_DIR/findings -- $BUILD_DIR/fuzz_discord_activity @@"
echo ""
echo "Or using stdin mode (no @@ — reads from stdin via persistent loop):"
echo "  afl-fuzz -i $SCRIPT_DIR/corpus -o $BUILD_DIR/findings -- $BUILD_DIR/fuzz_discord_activity"

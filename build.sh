#!/bin/bash
set -e

echo "[+] Checking for Qt5 development packages..."
if ! dpkg -s qtbase5-dev &>/dev/null; then
    echo "[+] Installing Qt5 development packages..."
    sudo apt-get update
    sudo apt-get install -y qtbase5-dev qtbase5-dev-tools pkg-config build-essential
fi

if command -v g++-13 &>/dev/null; then
    CXX=g++-13
    echo "[+] Using g++-13"
elif command -v g++ &>/dev/null; then
    CXX=g++
    GCC_VER=$(g++ -dumpversion)
    echo "[+] Detected GCC version: $GCC_VER"
    GCC_MAJOR=$(echo $GCC_VER | cut -d. -f1)
    if [ $GCC_MAJOR -lt 13 ]; then
        echo "[!] ERROR: GCC < 13 does not support <format>. Installing g++-13..."
        sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
        sudo apt update
        sudo apt install -y g++-13
        CXX=g++-13
    fi
else
    echo "[!] Error: No g++ compiler found"
    exit 1
fi

PCAPPP_DIR="/home/jon/Documents/Projects/Jennet"

if [ ! -f "$PCAPPP_DIR/lib/libPcap++.a" ]; then
    echo "[!] Error: PcapPlusPlus libraries not found at $PCAPPP_DIR/lib/"
    echo "[!] Please install PcapPlusPlus or update PCAPPP_DIR variable"
    exit 1
fi

echo "[+] Collecting source files..."
SRC_FILES=$(find . -name '*.cpp')
echo "$SRC_FILES"

echo "[+] Getting Qt5 compile and link flags..."
QT_CFLAGS=$(pkg-config --cflags Qt5Widgets)
QT_LIBS=$(pkg-config --libs Qt5Widgets)

if [ -z "$QT_CFLAGS" ] || [ -z "$QT_LIBS" ]; then
    echo "[!] Error: pkg-config did not return Qt5Widgets flags. Check Qt5 installation."
    exit 1
fi

echo "[+] Qt5 compile flags: $QT_CFLAGS"
echo "[+] Qt5 link flags: $QT_LIBS"

echo "[+] Compiling Jennet with $CXX..."
$CXX -std=c++20 -O2 -fPIC -Wall -Wextra \
    -o jnet $SRC_FILES \
    -I . \
    -I "$PCAPPP_DIR/include/pcapplusplus" \
    -I "./JNET" \
    $QT_CFLAGS \
    "$PCAPPP_DIR/lib/libPcap++.a" \
    "$PCAPPP_DIR/lib/libPacket++.a" \
    "$PCAPPP_DIR/lib/libCommon++.a" \
    -lpcap \
    -lcjson \
    $QT_LIBS \
    -static-libstdc++ -static-libgcc

echo "[+] Compilation successful."
echo "[+] Running Jennet..."
sudo ./jnet
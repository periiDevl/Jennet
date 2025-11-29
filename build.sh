set -e

if command -v g++-13 &>/dev/null; then
    CXX=g++-13
    echo "Using g++-13"
elif command -v g++ &>/dev/null; then
    CXX=g++
    GCC_VER=$($CXX -dumpversion)
    GCC_MAJOR=$(echo $GCC_VER | cut -d. -f1)
    if [ $GCC_MAJOR -lt 13 ]; then
        echo "ERROR: GCC < 13 does not support <format>. Install g++-13!"
        exit 1
    fi
else
    echo "Error: No g++ compiler found"
    exit 1
fi

PCAPPP_DIR="/home/jon/Documents/Projects/Jennet"
if [ ! -f "$PCAPPP_DIR/lib/libPcap++.a" ]; then
    echo "Error: PcapPlusPlus libraries not found at $PCAPPP_DIR/lib/"
    exit 1
fi

SRC_FILES=$(find . -name '*.cpp')

QT_CFLAGS=$(pkg-config --cflags Qt5Widgets)
QT_LIBS=$(pkg-config --libs Qt5Widgets)

$CXX -std=c++20 -O2 -fPIC -Wall -Wextra \
    -o jnet $SRC_FILES \
    -I. \
    -I"$PCAPPP_DIR/include/pcapplusplus" \
    -I"./JNET" \
    $QT_CFLAGS \
    "$PCAPPP_DIR/lib/libPcap++.a" \
    "$PCAPPP_DIR/lib/libPacket++.a" \
    "$PCAPPP_DIR/lib/libCommon++.a" \
    -lpcap -lcjson $QT_LIBS \
    -static-libstdc++ -static-libgcc

echo "Compilation successful."
sudo ./jnet

#!/bin/bash

echo "Compiling Jennet with Qt5 support..."

PCAPPP_DIR=~/Documents/Projects/Jennet

# Collect all .cpp files recursively (including subdirs)
SRC_FILES=$(find . -name '*.cpp')

echo "Source files found:"
echo "$SRC_FILES"

# Get Qt5 compile and link flags
QT_CFLAGS=$(pkg-config --cflags Qt5Widgets)
QT_LIBS=$(pkg-config --libs Qt5Widgets)

g++ -fPIC -o jnet $SRC_FILES \
  -I "$PCAPPP_DIR/include/pcapplusplus" \
  -I "./JNET" \
  $QT_CFLAGS \
  "$PCAPPP_DIR/lib/libPcap++.a" \
  "$PCAPPP_DIR/lib/libPacket++.a" \
  "$PCAPPP_DIR/lib/libCommon++.a" \
  -lpcap \
  $QT_LIBS

if [ $? -eq 0 ]; then
    echo "Compilation successful. Running Jennet..."
    sudo ./jnet
else
    echo "Compilation failed. Please check for errors."
fi

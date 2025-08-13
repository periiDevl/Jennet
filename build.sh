#!/bin/bash

echo "Checking for Qt5 development packages..."

if ! dpkg -s qtbase5-dev &> /dev/null; then
  echo "Qt5 development packages not found. Installing now..."
  sudo apt-get update
  sudo apt-get install -y qtbase5-dev qtbase5-dev-tools
fi

PCAPPP_DIR=~/Documents/Projects/Jennet

echo "Collecting source files..."
SRC_FILES=$(find . -name '*.cpp')

echo "Source files found:"
echo "$SRC_FILES"

echo "Getting Qt5 compile and link flags..."
QT_CFLAGS=$(pkg-config --cflags Qt5Widgets)
QT_LIBS=$(pkg-config --libs Qt5Widgets)

if [ -z "$QT_CFLAGS" ] || [ -z "$QT_LIBS" ]; then
  echo "Error: pkg-config did not return Qt5Widgets flags. Check your Qt5 installation."
  exit 1
fi

echo "Qt5 compile flags: $QT_CFLAGS"
echo "Qt5 link flags: $QT_LIBS"

echo "Compiling Jennet..."

g++ -fPIC -o jnet $SRC_FILES \
  -I "$PCAPPP_DIR/include/pcapplusplus" \
  -I "./JNET" \
  $QT_CFLAGS \
  "$PCAPPP_DIR/lib/libPcap++.a" \
  "$PCAPPP_DIR/lib/libPacket++.a" \
  "$PCAPPP_DIR/lib/libCommon++.a" \
  -lpcap \
  -lcjson \
  $QT_LIBS

if [ $? -eq 0 ]; then
  echo "Compilation successful. Running Jennet..."
  sudo ./jnet
else
  echo "Compilation failed. Please check for errors."
fi

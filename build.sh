#!/bin/bash

echo "Compiling Jennet..."

PCAPPP_DIR=~/Documents/Projects/Jennet

# Collect all .cpp files recursively (including subdirs)
SRC_FILES=$(find . -name '*.cpp')

g++ -o jnet $SRC_FILES \
  -I "$PCAPPP_DIR/include/pcapplusplus" \
  -I "./JNET" \
  "$PCAPPP_DIR/lib/libPcap++.a" \
  "$PCAPPP_DIR/lib/libPacket++.a" \
  "$PCAPPP_DIR/lib/libCommon++.a" \
  -lpcap

if [ $? -eq 0 ]; then
    echo "Compilation successful. Running Jennet..."
    sudo ./jnet
else
    echo "Compilation failed. Please check for errors."
fi

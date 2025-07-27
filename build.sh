#!/bin/bash

echo "Compiling Jennet..."

PCAPPP_DIR=~/Documents/Projects/Jennet

g++ -o jnet *.cpp \
  -I "$PCAPPP_DIR/include/pcapplusplus" \
  -I "./Global" \
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

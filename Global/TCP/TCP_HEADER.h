#pragma once
#include"Defng.h"
#pragma pack(push, 1)

struct TCP_HEADER {
    bytes_2 srcPort;
    bytes_2 destPort;
    bytes_4 seqNum;
    bytes_4 ackNum;
    byte dataOffReservedAndNS;
    byte flag;
    bytes_2 windowSize;
    bytes_2 checksum;
    bytes_2 urgPointer; 
};
struct TCP_PSEUDO_HEADER {
    bytes_4 srcAddr;
    bytes_4 destAddr;
    byte     zero;
    byte     protocol;
    bytes_2  tcpLength;
};
#pragma pack(pop)

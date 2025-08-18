#pragma once
#include"Defng.h"
#pragma pack(push,1)

struct UDP_HEADER
{
   bytes_2 srcPort;
   bytes_2 dstPort;
   bytes_2 len;
   bytes_2 checksum;
};
struct UDP_PSEUDO_HEADER
{
   bytes_4 srcAdrr;
   bytes_4 dstAdrr;
   byte zero;
   byte protocol;
   bytes_2 udpLen;
};

#pragma pack(pop)
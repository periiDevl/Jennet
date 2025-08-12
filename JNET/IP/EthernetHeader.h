#pragma once
#include<iostream>
#include <cstdint>
#include"Defng.h"
#pragma pack(push, 1)
//this will be 14 bytes
struct ETHERNET_HEADER
{
    byte dstMac[6];
    byte srcMac[6];
    bytes_2 ethernetType;
};
#pragma pack(pop)
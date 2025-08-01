#pragma once
#include<iostream>
#include <cstdint>
#include"Defng.h"
#pragma pack(push, 1)
struct ICMP_HEADER
{
    byte type;
    byte code;
    bytes_2 checksum;
    bytes_4 extendedHeader;
};
#pragma pack(pop)
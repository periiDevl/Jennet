#pragma once
#include<iostream>
#include <cstdint>
#include"Defng.h"
#pragma pack(push, 1)
struct IPV4_HEADER
{
    byte version_IHL; //VERSION is 4 bits, IHL is 4 bits. combine to from half ver half IHL
    byte TOS; //TOS
    bytes_2 totalLen; //the total length of the packet, can pair TCP or ICMP smt with this
    bytes_2 id; // used to reassemble fragments
    bytes_2 flags_fragmentOffset; //Flags and fragment offset
    byte TTL;//Time to live
    byte protocol;//My protocol
    bytes_2 Hchecksum;//checksum
    bytes_4 sendersIP;
    bytes_4 reciveIP;
};
#pragma pack(pop)


#pragma once
#include<iostream>
#include <cstdint>
#include"Defng.h"
#pragma pack(push, 1)
struct ARP_HEADER
{
    bytes_2 hardwareType;
    bytes_2 protocolType;
    byte hardwareAdrssLen;
    byte protocolAdressLen;
    bytes_2 operation; // 1 for request, 2 for reply
    byte sendAdrr[6]; // Sender's hardware address (MAC)
    byte sendProtolAdrr[4]; // Sender's protocol address (IPv4)
    byte reciveAdrr[6]; // Target's hardware address (MAC)
    byte reciveProtolAdrr[4]; // Target's protocol address (IPv4
};
#pragma pack(pop)
#pragma once
#include "iostream"
#include "Defng.h"
#include <cstring>
#include <pcap.h>
#include"Handler.h"
class Packet
{
private:
    size_t currectReservedSize = 0;
public:
    void reserve(size_t size){currectReservedSize += size;}
    size_t getReserve(){return currectReservedSize;}
    byte* packet;
    size_t pktSize;
    int send(Handler hnd);
    Packet(size_t packetSize);
    ~Packet();
};


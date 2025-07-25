#pragma once
#include "iostream"
#include "Defng.h"
#include <cstring>

class Packet
{
private:
    void allocatePacketBuffer(size_t pkSize);
public:
    byte* packet;
    size_t pktSize;
    //virtual void deliver();
    Packet(size_t packetSize);
    ~Packet();
};

Packet::Packet(size_t packetSize)
{
    pktSize = packetSize;
    packet = new byte[packetSize];
    memset(packet, 0, packetSize);
}

Packet::~Packet()
{
    delete[] packet;
}
#include"Packet.h"
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
int Packet::send(pcap_t* handle){
    return pcap_sendpacket(handle, packet, pktSize);
}
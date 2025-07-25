#include <pcap.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include"Packet.h"
#include "EthernetHeader.h"
#include "IPV4_HEADER.h"
#include "ICMP_HEADER.h"
#include "Protocol.h"
#include"IPV4.h"
bytes_2 calculateChecksum(bytes_2* data, size_t length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(byte*)data;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

int main() {
    std::cout << "Jennet says HELLO" << std::endl;
    
    const char* device = "enp11s0";
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Failed to open device: " << errbuf << "\n";
        return 1;
    }
    /*
    const size_t packetSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER);
    byte packet[packetSize];
    memset(packet, 0, packetSize);
    */
    Packet pkt(sizeof(ETHERNET_HEADER)+sizeof(IPV4_HEADER)+sizeof(ICMP_HEADER));
    
    ETHERNET_HEADER* eth = (ETHERNET_HEADER*)pkt.packet;
    byte dstMac[6] = {0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc};
    byte srcMac[6] = {0x08, 0x00, 0x27, 0xdd, 0xee, 0xff};
    
    memcpy(eth->dstMac, dstMac, 6);
    memcpy(eth->srcMac, srcMac, 6);
    eth->ethernetType = htons(0x0800);
    
    pkt.reserve(sizeof(ETHERNET_HEADER));
    IPV4 ivp4;
    ivp4.include(pkt);
    ivp4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ivp4.header->TOS = 0;
    ivp4.header->totalLen = htons(sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER));
    ivp4.header->id = htons(0x1234);
    ivp4.header->flags_fragmentOffset = htons(0);
    ivp4.header->TTL = 64;
    ivp4.header->protocol = 1;
    ivp4.header->sendersIP = inet_addr("10.0.0.103");
    ivp4.header->reciveIP = inet_addr("10.0.0.51");
    ivp4.applyChecksum();
    /*
    ivp4->Hchecksum = 0;
    ivp4->Hchecksum = calculateChecksum((bytes_2*)ip, sizeof(IPV4_HEADER));
    */
    ICMP_HEADER* icmp = (ICMP_HEADER*)(pkt.packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER));
    icmp->type = 8;  // Echo Request
    icmp->code = 0;
    icmp->extendedHeader = 0x12340001; 
    icmp->checksum = 0;
    icmp->checksum = calculateChecksum((bytes_2*)icmp, sizeof(ICMP_HEADER));

    
    if (pkt.send(handle) != 0) {
        std::cerr << "Failed to send packet: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    std::cout << "Ethernet + IPv4 + ICMP Echo Request sent!!\n";
    pcap_close(handle);
    return 0;
}

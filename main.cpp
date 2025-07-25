#include <pcap.h>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <cstdint>

#include "EthernetHeader.h"
#include "IPV4_HEADER.h"
#include "ICMP_HEADER.h"

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
    ETHERNET_HEADER ethernetHeader{};
    IPV4_HEADER ipv4Header{};
    ICMP_HEADER icmpHeader{};

    std::cout << "Jennet says Blud" << std::endl;

    const char* device = "enp11s0";
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Failed to open device: " << errbuf << "\n";
        return 1;
    }

    const size_t packetSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER);
    byte packet[packetSize];
    memset(packet, 0, packetSize);


    ETHERNET_HEADER* eth = (ETHERNET_HEADER*)packet;
    byte dstMac[6] = {0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc};
    byte srcMac[6] = {0x08, 0x00, 0x27, 0xdd, 0xee, 0xff};

    memcpy(eth->dstMac, dstMac, 6);
    memcpy(eth->srcMac, srcMac, 6);
    eth->ethernetType = htons(0x0800);


    IPV4_HEADER* ip = (IPV4_HEADER*)(packet + sizeof(ETHERNET_HEADER));
    ip->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ip->TOS = 0;
    ip->totalLen = htons(sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER));
    ip->id = htons(0x1234);
    ip->flags_fragmentOffset = htons(0);
    ip->TTL = 64;
    ip->protocol = 1;
    ip->sendersIP = inet_addr("127.0.0.1");
    ip->reciveIP = inet_addr("10.0.0.1 ");
    ip->Hchecksum = 0;
    ip->Hchecksum = calculateChecksum((bytes_2*)ip, sizeof(IPV4_HEADER));


    ICMP_HEADER* icmp = (ICMP_HEADER*)(packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER));
    icmp->type = 8;  // Echo Request
    icmp->code = 0;
    icmp->extendedHeader = 0x12340001; 
    icmp->checksum = 0;
    icmp->checksum = calculateChecksum((bytes_2*)icmp, sizeof(ICMP_HEADER));

    
    if (pcap_sendpacket(handle, packet, packetSize) != 0) {
        std::cerr << "Failed to send packet: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    std::cout << "Ethernet + IPv4 + ICMP Echo Request sent!!\n";
    pcap_close(handle);
    return 0;
}

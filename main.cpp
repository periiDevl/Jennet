#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include"Packet.h"
#include "EthernetHeader.h"
#include"IP/IPV4.h"
#include"ICMP/ICMP.h"
#include"Protocol.h"
#include"TerminalInterface/ASCIIART.h"
#include"InternetUtils.h"
#include "TCP/TCP.h"
#include"TCP/TCP_FLAGS.h"
int main() {
    if (isMachineBigEndian() == 1){
        std::cout << "Yes";
    } else {
        std::cout << "No";
    }
    std::cout << "Jennet says HELLO" << std::endl;
    printAscii();
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
    Packet pkt(sizeof(ETHERNET_HEADER)+sizeof(IPV4_HEADER)+sizeof(TCP_HEADER));
    
    ETHERNET_HEADER* eth = (ETHERNET_HEADER*)pkt.packet;
    byte dstMac[6] = {0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc};
    byte srcMac[6] = {0x08, 0x00, 0x27, 0xdd, 0xee, 0xff};
    
    memcpy(eth->dstMac, dstMac, 6);
    memcpy(eth->srcMac, srcMac, 6);
    eth->ethernetType = convertToBigEndian(0x0800);
    
    pkt.reserve(sizeof(ETHERNET_HEADER));
    IPV4 ivp4;
    ivp4.include(pkt);
    ivp4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ivp4.header->TOS = 0;
    ivp4.header->totalLen = convertToBigEndian(sizeof(IPV4_HEADER) + sizeof(TCP_HEADER));
    ivp4.header->id = convertToBigEndian(0x1234);
    ivp4.header->flags_fragmentOffset = convertToBigEndian(0);
    ivp4.header->TTL = 64;
    ivp4.header->protocol = 6;
    ivp4.header->sendersIP = v4addr("10.0.0.103");
    ivp4.header->reciveIP = v4addr("10.0.0.2");
    ivp4.applyChecksum();

    pkt.reserve(sizeof(IPV4_HEADER));
    TCP tcp;
    tcp.include(pkt);
    tcp.header->srcPort = convertToBigEndian(5656);
    tcp.header->destPort = convertToBigEndian(5656);
    tcp.header->seqNum = convertToBigEndian(0x1);
    tcp.header->ackNum = 0;
    tcp.header->dataOffReservedAndNS = (sizeof(TCP_HEADER) / 4) << 4;
    tcp.header->flag = SYN(); // Just SYN flag
    tcp.header->windowSize = convertToBigEndian(65535);
    tcp.header->checksum = 0;
    tcp.header->urgPointer = 0;
    tcp.configurePseudoHeader(*ivp4.header);
    tcp.applyChecksum();


    
    if (pkt.send(handle) != 0) {
        std::cerr << "Failed to send packet: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    std::cout << "Ethernet + IPv4 + ICMP Echo Request sent!!\n";
    pcap_close(handle);
    return 0;
}

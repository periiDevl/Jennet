/*
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <vector>
#include "Packet.h"
#include "IP/EthernetHeader.h"
#include "IP/IPV4.h"
#include "TCP/TCP.h"
#include "TCP/TCP_FLAGS.h"
#include "Testing.h"
#include "InternetUtils.h"
#include"ARP/ARP.h"
#include"Handler.h"

int main() {
    Handler handler("enp11s0");

    MacGetter mg(handler.getInterface());

    byte srcMac[6]{};
    if (!mg.getInterfaceMac(srcMac)) {
        std::cerr << "Failed to get interface MAC\n";
        handler.close();
        return 1;
    }

    std::string gwIP = mg.getDefaultGatewayIP();
    if (gwIP.empty()) {
        std::cerr << "Failed to get default gateway IP\n";
        handler.close();
        return 1;
    }

    std::cout << "Gateway IP: " << gwIP << "\n";
    Packet pkt(sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER));

    ETHERNET_HEADER* eth = (ETHERNET_HEADER*)(pkt.packet);
    memset(eth->dstMac, 0xFF, 6);//Broadcast MAC for ARP request
    memcpy(eth->srcMac, srcMac, 6);
    eth->ethernetType = convertToBigEndian16(0x0806);//Ethertype =ARP
    pkt.reserve(sizeof(ETHERNET_HEADER));

    ARP arp;
    arp.include(pkt);
    arp.header->hardwareType = convertToBigEndian16(1);//Ethernet
    arp.header->protocolType = convertToBigEndian16(0x0800);//IPv4
    arp.header->hardwareAdrssLen = 6;//MAC LEN
    arp.header->protocolAdressLen = 4;//IPV4
    arp.header->operation = convertToBigEndian16(1);//Request
    memcpy(arp.header->sendAdrr, srcMac, 6);
    const char* senderIP = "10.0.0.103";
    bytes_4 sendersIPbytes = convertToBigEndian32(v4addr(senderIP));
    memcpy(arp.header->sendProtolAdrr, &sendersIPbytes, 4);
    memset(arp.header->reciveAdrr, 0, 6);//zero unkown adress mac

    uint32_t gwIpBytes = inet_addr(gwIP.c_str());
    memcpy(arp.header->reciveProtolAdrr, &gwIpBytes, 4);

    pkt.send(handler);


    std::cout << "SENT " << gwIP << "\n";

    handler.close();
    return 0;
}
*/







/*
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
    simpleIPV4(ipv4);

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
*/
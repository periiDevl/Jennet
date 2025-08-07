#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <vector>
#include "Packet.h"
#include "EthernetHeader.h"
#include "IP/IPV4.h"
#include "TCP/TCP.h"
#include "TCP/TCP_FLAGS.h"
#include "Testing.h"
#include "InternetUtils.h"
#include"ARP/ARP.h"
#include"Handler.h"

int main() {
    Handler handler("wlo1");

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
    const char* senderIP = "10.50.70.64";
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

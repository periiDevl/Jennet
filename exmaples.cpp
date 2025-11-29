

#include "Packet.h"
#include "IP/EthernetHeader.h"
#include "IP/IPV4.h"
#include "TCP/TCP.h"
#include "ICMP/ICMP.h"
#include "ARP/ARP.h"
#include "UDP/UDP.h"
#include "Handler.h"
#include <cstring>
#include <iostream>
#include"Testing.h"
#include "TCP/TCP_FLAGS.h"

void sendTCPSyn(const char* interface, const std::string& srcMac, const std::string& dstMac,
                const char* srcIP, const char* dstIP, 
                uint16_t srcPort, uint16_t dstPort) {
    
    Handler handler(interface);
    MacGetter mg(interface);
    
    ETHERNET_HEADER eth{};
    auto srcMacBytes = MacGetter::stringToMac(srcMac);
    auto dstMacBytes = MacGetter::stringToMac(dstMac);
    memcpy(eth.srcMac, srcMacBytes.data(), 6);
    memcpy(eth.dstMac, dstMacBytes.data(), 6);
    eth.ethernetType = convertToBigEndian16(0x0800);
    
    IPV4 ipv4;
    ipv4.header = new IPV4_HEADER;
    ipv4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ipv4.header->TOS = 0;
    ipv4.header->id = convertToBigEndian16(rand() % 65535);
    ipv4.header->flags_fragmentOffset = convertToBigEndian16(0x4000);
    ipv4.header->TTL = 64;
    ipv4.header->protocol = 6; // TCP
    ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIP));
    ipv4.header->reciveIP = convertToBigEndian32(v4addr(dstIP));
    
    TCP tcp;
    tcp.header = new TCP_HEADER;
    tcp.construtPrmtv(2);
    tcp.header->srcPort = convertToBigEndian16(srcPort);
    tcp.header->destPort = convertToBigEndian16(dstPort);
    tcp.header->seqNum = convertToBigEndian32(rand());
    tcp.header->ackNum = 0;
    tcp.header->dataOffReservedAndNS = (5 << 4);
    tcp.header->flag = SYN();
    tcp.header->windowSize = convertToBigEndian16(65535);
    tcp.header->urgPointer = 0;
    
    ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + sizeof(TCP_HEADER));
    ipv4.header->Hchecksum = 0;
    ipv4.applyChecksum();
    
    tcp.configurePseudoHeader(*ipv4.header);
    tcp.applyChecksum();
    
    size_t totalSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER);
    Packet pkt(totalSize);
    pkt.copyAdv(&eth, sizeof(ETHERNET_HEADER));
    pkt.copyAdv(ipv4.header, sizeof(IPV4_HEADER));
    pkt.copyAdv(tcp.header, sizeof(TCP_HEADER));
    
    if (pkt.send(handler) == 0) {
        std::cout << "TCP SYN packet sent successfully!\n";
    } else {
        std::cerr << "Failed to send TCP SYN packet\n";
    }
    
    delete ipv4.header;
    delete tcp.header;
    handler.close();
}
void sendTCPWithPayload(const char* interface, const std::string& srcMac, const std::string& dstMac,
                        const char* srcIP, const char* dstIP,
                        uint16_t srcPort, uint16_t dstPort,
                        const std::string& payloadText, byte flags = ACK()) {

    Handler handler(interface);
    MacGetter mg(interface);

    ETHERNET_HEADER eth{};
    auto srcMacBytes = MacGetter::stringToMac(srcMac);
    auto dstMacBytes = MacGetter::stringToMac(dstMac);
    memcpy(eth.srcMac, srcMacBytes.data(), 6);
    memcpy(eth.dstMac, dstMacBytes.data(), 6);
    eth.ethernetType = convertToBigEndian16(0x0800);

    IPV4 ipv4;
    ipv4.header = new IPV4_HEADER;
    ipv4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ipv4.header->TOS = 0;
    ipv4.header->id = convertToBigEndian16(rand() % 65535);
    ipv4.header->flags_fragmentOffset = convertToBigEndian16(0x4000);
    ipv4.header->TTL = 64;
    ipv4.header->protocol = 6;
    ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIP));
    ipv4.header->reciveIP = convertToBigEndian32(v4addr(dstIP));

    TCP tcp;
    tcp.header = new TCP_HEADER;
    tcp.construtPrmtv(flags);
    tcp.header->srcPort = convertToBigEndian16(srcPort);
    tcp.header->destPort = convertToBigEndian16(dstPort);
    tcp.header->seqNum = convertToBigEndian32(rand());
    tcp.header->ackNum = 0;
    tcp.header->dataOffReservedAndNS = (5 << 4);
    tcp.addText(payloadText);
    ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + sizeof(TCP_HEADER) + tcp.payload.size());
    ipv4.header->Hchecksum = 0;
    ipv4.applyChecksum();

    tcp.configurePseudoHeader(*ipv4.header);
    tcp.applyChecksum();

    size_t totalSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER) + tcp.payload.size();
    Packet pkt(totalSize);
    pkt.copyAdv(&eth, sizeof(ETHERNET_HEADER));
    pkt.copyAdv(ipv4.header, sizeof(IPV4_HEADER));
    pkt.copyAdv(tcp.header, sizeof(TCP_HEADER));
    if (!tcp.payload.empty()) {
        pkt.copyAdv(tcp.payload.data(), tcp.payload.size());
    }

    if (pkt.send(handler) == 0) {
        std::cout << "TCP packet with payload sent successfully!\n";
    } else {
        std::cerr << "Failed to send TCP packet\n";
    }

    delete ipv4.header;
    delete tcp.header;
    handler.close();
}

void sendICMPPing(const char* interface, const std::string& srcMac, const std::string& dstMac,
                  const char* srcIP, const char* dstIP) {
    
    Handler handler(interface);
    MacGetter mg(interface);
    
    ETHERNET_HEADER eth{};
    auto srcMacBytes = MacGetter::stringToMac(srcMac);
    auto dstMacBytes = MacGetter::stringToMac(dstMac);
    memcpy(eth.srcMac, srcMacBytes.data(), 6);
    memcpy(eth.dstMac, dstMacBytes.data(), 6);
    eth.ethernetType = convertToBigEndian16(0x0800);
    
    IPV4 ipv4;
    ipv4.header = new IPV4_HEADER;
    ipv4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ipv4.header->TOS = 0;
    ipv4.header->id = convertToBigEndian16(rand() % 65535);
    ipv4.header->flags_fragmentOffset = convertToBigEndian16(0x4000);
    ipv4.header->TTL = 64;
    ipv4.header->protocol = 1;
    ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIP));
    ipv4.header->reciveIP = convertToBigEndian32(v4addr(dstIP));
    
    ICMP icmp;
    icmp.header = new ICMP_HEADER;
    icmp.header->type = 8;
    icmp.header->code = 0;
    bytes_2 id = 1234;
    bytes_2 seq = 1;
    icmp.header->extendedHeader = convertToBigEndian32(((bytes_4)id << 16) | seq);
    
    ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER));
    ipv4.header->Hchecksum = 0;
    ipv4.applyChecksum();
    icmp.applyChecksum();
    
    size_t totalSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER);
    Packet pkt(totalSize);
    pkt.copyAdv(&eth, sizeof(ETHERNET_HEADER));
    pkt.copyAdv(ipv4.header, sizeof(IPV4_HEADER));
    pkt.copyAdv(icmp.header, sizeof(ICMP_HEADER));
    
    if (pkt.send(handler) == 0) {
        std::cout << "ICMP Echo Request sent successfully!\n";
    } else {
        std::cerr << "Failed to send ICMP packet\n";
    }
    
    delete ipv4.header;
    delete icmp.header;
    handler.close();
}

void sendUDP(const char* interface, const std::string& srcMac, const std::string& dstMac,
             const char* srcIP, const char* dstIP,
             uint16_t srcPort, uint16_t dstPort, const char* payload) {
    
    Handler handler(interface);
    MacGetter mg(interface);
    
    ETHERNET_HEADER eth{};
    auto srcMacBytes = MacGetter::stringToMac(srcMac);
    auto dstMacBytes = MacGetter::stringToMac(dstMac);
    memcpy(eth.srcMac, srcMacBytes.data(), 6);
    memcpy(eth.dstMac, dstMacBytes.data(), 6);
    eth.ethernetType = convertToBigEndian16(0x0800);
    
    IPV4 ipv4;
    ipv4.header = new IPV4_HEADER;
    ipv4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ipv4.header->TOS = 0;
    ipv4.header->id = convertToBigEndian16(rand() % 65535);
    ipv4.header->flags_fragmentOffset = convertToBigEndian16(0x4000);
    ipv4.header->TTL = 64;
    ipv4.header->protocol = 17;
    ipv4.header->sendersIP = convertToBigEndian32(v4addr(srcIP));
    ipv4.header->reciveIP = convertToBigEndian32(v4addr(dstIP));
    
    UDP udp;
    udp.header = new UDP_HEADER;
    udp.header->srcPort = convertToBigEndian16(srcPort);
    udp.header->dstPort = convertToBigEndian16(dstPort);
    udp.addText(payload);
    
    ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + udp.payload.size());
    ipv4.header->Hchecksum = 0;
    ipv4.applyChecksum();
    
    udp.configurePseudoHeader(*ipv4.header);
    udp.applyChecksum();
    
    size_t totalSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + udp.payload.size();
    Packet pkt(totalSize);
    pkt.copyAdv(&eth, sizeof(ETHERNET_HEADER));
    pkt.copyAdv(ipv4.header, sizeof(IPV4_HEADER));
    pkt.copyAdv(udp.header, sizeof(UDP_HEADER));
    pkt.copyAdv(udp.payload.data(), udp.payload.size());
    
    if (pkt.send(handler) == 0) {
        std::cout << "UDP packet sent successfully!\n";
    } else {
        std::cerr << "Failed to send UDP packet\n";
    }
    
    delete ipv4.header;
    delete udp.header;
    handler.close();
}

void sendARPRequest(const char* interface, const std::string& srcMac, 
                    const char* srcIP, const char* dstIP) {
    
    Handler handler(interface);
    MacGetter mg(interface);
    
    ETHERNET_HEADER eth{};
    auto srcMacBytes = MacGetter::stringToMac(srcMac);
    memcpy(eth.srcMac, srcMacBytes.data(), 6);
    memset(eth.dstMac, 0xFF, 6);
    eth.ethernetType = convertToBigEndian16(0x0806);
    
    ARP arp;
    arp.header = new ARP_HEADER;
    arp.header->hardwareType = convertToBigEndian16(1);
    arp.header->protocolType = convertToBigEndian16(0x0800);
    arp.header->hardwareAdrssLen = 6;
    arp.header->protocolAdressLen = 4;
    arp.header->operation = convertToBigEndian16(1);
    
    memcpy(arp.header->sendAdrr, srcMacBytes.data(), 6);
    
    bytes_4 sendersIPbytes = convertToBigEndian32(v4addr(srcIP));
    memcpy(arp.header->sendProtolAdrr, &sendersIPbytes, 4);
    
    memset(arp.header->reciveAdrr, 0, 6);
    
    bytes_4 destIPbytes = convertToBigEndian32(v4addr(dstIP));
    memcpy(arp.header->reciveProtolAdrr, &destIPbytes, 4);
    
    size_t totalSize = sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER);
    Packet pkt(totalSize);
    pkt.copyAdv(&eth, sizeof(ETHERNET_HEADER));
    pkt.copyAdv(arp.header, sizeof(ARP_HEADER));
    
    if (pkt.send(handler) == 0) {
        std::cout << "ARP Request sent successfully!\n";
    } else {
        std::cerr << "Failed to send ARP packet\n";
    }
    
    delete arp.header;
    handler.close();
}

int main() {
    const char* interface = "";
    std::string srcMac = "";
    std::string dstMac = "";
    const char* srcIP = "";
    const char* dstIP = "1.1.1.1";
    
    sendTCPSyn(interface, srcMac, dstMac, srcIP, dstIP, 12345, 80);
    
    sendTCPWithPayload(interface, srcMac, dstMac, srcIP, dstIP, 12345, 80, "Hello TCP World!");

    sendICMPPing(interface, srcMac, dstMac, srcIP, dstIP);
    
    sendUDP(interface, srcMac, dstMac, srcIP, dstIP, 54321, 600, "Hello UDP!");
    
    sendARPRequest(interface, srcMac, srcIP, "192.168.1.50");
    
    return 0;
}


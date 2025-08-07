/*#include <pcap.h>
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

int main() {
    const char* device = "wlo1";
    char errbuf[PCAP_ERRBUF_SIZE]{};

    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Failed to open device: " << errbuf << "\n";
        return 1;
    }

    MacGetter mg(device);
    byte srcMac[6]{};
    byte dstMac[6]{};

    if (!mg.getInterfaceMac(srcMac)) {
        std::cerr << "Failed to get source MAC address\n";
        pcap_close(handle);
        return 1;
    }

    if (!mg.getGatewayMac(dstMac)) {
        std::cerr << "Failed to get gateway MAC address\n";
        pcap_close(handle);
        return 1;
    }

    // Build TCP options and calculate lengths
    TCP tcp;
    tcp.addSynOptions();
    const size_t tcpOptionsLen = tcp.payload.size();
    const size_t tcpHeaderLen = sizeof(TCP_HEADER) + tcpOptionsLen;

    // Calculate total packet size
    const size_t totalPacketSize = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + tcpHeaderLen;
    Packet pkt(totalPacketSize);

    // --- 1. Build Ethernet Header ---
    ETHERNET_HEADER* eth = reinterpret_cast<ETHERNET_HEADER*>(pkt.packet);
    memcpy(eth->srcMac, srcMac, 6);
    memcpy(eth->dstMac, dstMac, 6);
    eth->ethernetType = convertToBigEndian16(0x0800);  // IPv4 Ethertype
    pkt.reserve(sizeof(ETHERNET_HEADER)); // Move pointer forward

    // --- 2. Build IPv4 Header ---
    IPV4 ipv4;
    ipv4.include(pkt);
    ipv4.header->version_IHL = (4 << 4) | (sizeof(IPV4_HEADER) / 4);
    ipv4.header->TOS = 0;
    ipv4.header->totalLen = convertToBigEndian16(sizeof(IPV4_HEADER) + tcpHeaderLen);
    ipv4.header->id = convertToBigEndian16(0x1234);
    ipv4.header->flags_fragmentOffset = convertToBigEndian16(0x4000);
    ipv4.header->TTL = 64;
    ipv4.header->protocol = 6;  // TCP
    ipv4.header->sendersIP = convertToBigEndian32(v4addr("10.50.70.64"));
    ipv4.header->reciveIP = convertToBigEndian32(v4addr("1.1.1.1"));
    ipv4.applyChecksum();
    pkt.reserve(sizeof(IPV4_HEADER)); // Move pointer forward

    // --- 3. Build TCP Header ---
    tcp.include(pkt);
    pkt.reserve(tcpHeaderLen);

    tcp.construtPrmtv(SYN());

    tcp.header->srcPort = convertToBigEndian16(52848);
    tcp.header->destPort = convertToBigEndian16(80);
    tcp.header->seqNum = convertToBigEndian32(static_cast<bytes_4>(1798999813));
    tcp.header->windowSize = convertToBigEndian16(64240);

    tcp.header->dataOffReservedAndNS = ((sizeof(TCP_HEADER) + tcpOptionsLen) / 4) << 4;

    memcpy(reinterpret_cast<byte*>(tcp.header + 1), tcp.payload.data(), tcp.payload.size());

    tcp.configurePseudoHeader(*ipv4.header);
    tcp.applyChecksum();

    // Send the packet
    if (pkt.send(handle) != 0) {
        std::cerr << "Failed to send packet: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    std::cout << "SYN with correct TCP options sent to 1.1.1.1:80\n";

    pcap_close(handle);
    return 0;
}
*/
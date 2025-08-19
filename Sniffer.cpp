
// Implementation
#include "Sniffer.h"
#include <QString>
#include <iostream>
#include "IP/EthernetHeader.h"
#include"IP/IPV4_HEADER.h"
#include "ARP/ARP_HEADER.h"
#include "ICMP/ICMP_HEADER.h"
Sniffer::Sniffer(PacketInfo* pktInfoPtr) 
    : handle(nullptr), pktInfo(pktInfoPtr), running(false), shouldStop(false) {
}

Sniffer::~Sniffer() {
    stop();
}

bool Sniffer::openDefaultDevice() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = pcap_lookupdev(errbuf);
    if (!dev) {
        std::cerr << "Error finding device: " << errbuf << std::endl;
        return false;
    }
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return false;
    }
    return true;
}

void Sniffer::start(Handler* hndr) {
    if (!hndr->get() || running) return;
    handle = hndr->get();
    shouldStop = false;
    running = true;

    captureThread = std::thread(&Sniffer::captureLoop, this);
}

void Sniffer::stop() {
    if (running) {
        shouldStop = true;
        
        if (handle) {
            pcap_breakloop(handle);
        }
        
        if (captureThread.joinable()) {
            captureThread.join();
        }
        
        running = false;
    }
    
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

void Sniffer::captureLoop() {
    if (!handle) return;
    
  
    int result = pcap_loop(handle, -1, Sniffer::packetHandler, reinterpret_cast<u_char*>(this));
    
    if (result == -1) {
        std::cerr << "Error in pcap_loop: " << pcap_geterr(handle) << std::endl;
    }
    
    running = false;
}

void Sniffer::packetHandler(u_char* args, const pcap_pkthdr* header, const u_char* packet) {
    Sniffer* self = reinterpret_cast<Sniffer*>(args);

    if (self->shouldStop) {
        return;
    }
    
    if (header->len < sizeof(ETHERNET_HEADER)) return;
    
    const ETHERNET_HEADER* eth = (const ETHERNET_HEADER*)(packet);
    if (netToHost16(eth->ethernetType) == 0x0806) {
        const ARP_HEADER* arp = (const ARP_HEADER*)(packet + sizeof(ETHERNET_HEADER));
        std::string arpContent = std::string("IPV4:\n") +
                            "(IP WISE):\n" +
                            "From: " + bArrayToIPv4String(arp->sendProtolAdrr) + "\n" +
                            "To: " + bArrayToIPv4String(arp->reciveProtolAdrr) + "\n" +
                            "(MAC WISE):\n" +
                            "From: " + bArrayToMACString(arp->sendAdrr) + "\n" +
                            "To: " + bArrayToMACString(arp->reciveAdrr) + "\n" +
                            "Operator: " + std::to_string(netToHost16(arp->operation));

        self->pktInfo->add("ARP(Address Resolution Protocol) From " +bArrayToIPv4String(arp->sendProtolAdrr)+" To " +bArrayToIPv4String(arp->reciveProtolAdrr),arpContent.c_str()
            ,255, 218, 173);
    }
    else if (netToHost16(eth->ethernetType) == 0x0800) { //IPV4
        const IPV4_HEADER* ipv4 =  (const IPV4_HEADER*)(packet + sizeof(ETHERNET_HEADER));
        std::string ipv4Content = std::string("IPV4:\n") +
            "IHL: " + std::to_string(ipv4->version_IHL & 0x0F) + "\n" +
            "TOS: " + std::to_string(ipv4->TOS) + "\n" +
            "Total Len: " + std::to_string(netToHost16(ipv4->totalLen)) + "\n" +
            "ID: " + std::to_string(netToHost16(ipv4->id)) + "\n" +
            "TTL(Time To Live): " + std::to_string(ipv4->TTL) + "\n" +
            "Protocol: " + std::to_string(ipv4->protocol) + "\n" +
            "From: " +ipv4BytesToString(netToHost32(ipv4->sendersIP)) + "\n" +
            "To: " + ipv4BytesToString(netToHost32(ipv4->reciveIP)) + "\n";
        if (ipv4->protocol == 1){
            //ICMP
            const ICMP_HEADER* icmp =  (const ICMP_HEADER*)(packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER));
            bytes_2 seq = netToHost16(icmp->extendedHeader & 0xFFFF);
            bytes_2 id  = netToHost16((icmp->extendedHeader >> 16) & 0xFFFF);

            std::string icmpContent = std::string("ICMP(Internet Control Message Protocol):\n") +
                "Type: " + std::to_string(icmp->type) + "\n" +
                "Code: " + std::to_string(icmp->code) + "\n" +
                "Seq: " + std::to_string(seq) + "\n" +
                "ID: " + std::to_string(id) + "\n";
            self->pktInfo->add("ICMP(Internet Control Message Protocol)" + ipv4BytesToString(netToHost32(ipv4->sendersIP)) + " Sent to " + ipv4BytesToString(netToHost32(ipv4->reciveIP)), (ipv4Content + icmpContent).c_str(), 4, 181, 54);
        }
        
    }
    else{
        self->pktInfo->add("Unkown", "idk", 140, 140, 140);
    }
}
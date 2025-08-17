#pragma once
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include"Packet.h"
#include"IP/IPV4.h"
#include"TCP/TCP.h"
#include"IP/EthernetHeader.h"
#include"ICMP/ICMP.h"
class JSON_JENNET
{
private:
public:
    char* read_file(const char* filename);
    void loadFeatures(const char* filename);
    void consturct(Packet* pkt, ETHERNET_HEADER header){
    std::memcpy(pkt->packet, &header, sizeof(ETHERNET_HEADER));
    
        if (enableIPV4) {
            std::memcpy(pkt->packet + sizeof(ETHERNET_HEADER), ipv4.header, sizeof(IPV4_HEADER));
        }
        
        if (enableTCP) {
            std::memcpy(pkt->packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER), tcp.header, sizeof(TCP_HEADER));
            if (tcp.payload.size()) {
                std::memcpy(
                    pkt->packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER),
                    tcp.payload.data(),
                    tcp.payload.size()
                );
            }
        }
        
        if (enableICMP) {
            std::memcpy(pkt->packet + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER), icmp.header, sizeof(ICMP_HEADER));
        }
    }
    //ETH is prebuilt
    bool enableIPV4 = false;
    IPV4 ipv4;
    bool enableTCP = false;
    TCP tcp;
    bool enableICMP = false;
    ICMP icmp;
    bool enableARP = false;
    bytes_2 totalSize = 0;
    JSON_JENNET();
    ~JSON_JENNET();
};

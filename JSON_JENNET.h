#pragma once
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include"Packet.h"
#include"IP/IPV4.h"
#include"TCP/TCP.h"
#include"IP/EthernetHeader.h"
#include"ICMP/ICMP.h"
#include"ARP/ARP.h"
#include"UDP/UDP.h"
class JSON_JENNET
{
private:
public:
    char* read_file(const char* filename);
    void loadFeatures(const char* filename);
    void consturct(Packet* pkt, ETHERNET_HEADER header);
    //ETH is prebuilt
    bool enableIPV4 = false;
    IPV4 ipv4;
    bool enableTCP = false;
    TCP tcp;
    bool enableICMP = false;
    ICMP icmp;
    bool enableARP = false;
    ARP arp;
    bool enableUDP = false;
    UDP udp;
    bytes_2 totalSize = 0;
    JSON_JENNET();
    ~JSON_JENNET();
};


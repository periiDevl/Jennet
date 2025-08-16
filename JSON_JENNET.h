#pragma once
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include"Packet.h"
#include"IP/IPV4.h"
#include"TCP/TCP.h"
class JSON_JENNET
{
private:
public:
    char* read_file(const char* filename);
    void loadFeatures(const char* filename);
    //ETH is prebuilt
    bool enableIPV4 = false;
    IPV4 ipv4;
    bool enableTCP = false;
    TCP tcp;
    bool enableICMP = false;
    bool enableARP = false;
    bytes_2 totalSize = 0;
    JSON_JENNET();
    ~JSON_JENNET();
};

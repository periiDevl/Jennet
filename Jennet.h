#pragma once
#include"AdressesCLI.h"
#include"Testing.h"
#include"Defng.h"
#include"InternetUtils.h"
#include "IP/EthernetHeader.h"
#include"Packet.h"
#include"Handler.h"

// sudo ./jnet Who.json Packet.json
class Jennet
{
private:
    AdressesCLI adrCli;
    
public:
    Jennet(const char* file1, const char* file2);
    ~Jennet();
};


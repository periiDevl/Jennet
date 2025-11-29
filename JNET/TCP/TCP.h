#pragma once
#include"IP/IPV4.h"
#include"TCP_HEADER.h"
#include"Protocol.h"
#include"InternetUtils.h"
#include<vector>
class TCP : public Protocol<TCP_HEADER>
{
private:


public:
    
    TCP();
    ~TCP();
    void applyChecksum() override;
    void configurePseudoHeader(IPV4_HEADER& ipv4Header);
    void construtPrmtv(byte flag);
    void addSynOptions(
    bytes_2 mss = 1460, 
    byte windowScale = 0, 
    bytes_4 tsVal = 0, 
    bytes_4 tsEcho = 0,
    bool addSACK = true
    );
    void addText(const std::string& text);

    TCP_PSEUDO_HEADER psudoHeader;
    std::vector<byte> payload;
};

